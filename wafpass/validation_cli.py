"""CLI commands and helpers for WAF++ official validation.

This module is imported by wafpass.cli and provides:

  * `wafpass validate *` subcommands
  * `wafpass verify` top-level command
  * helpers used by `wafpass check --validate`
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from wafpass import ValidationEnvelopeSchema, WafpassResultSchema
from wafpass.attestation import (
    create_official_envelope,
    create_offline_envelope,
    generate_signing_key,
    sign_run,
    upgrade_offline_envelope,
    verify_envelope,
)


# ── Helpers shared with `wafpass check` ───────────────────────────────────────


DEFAULT_VALIDATION_KEY = Path.home() / ".wafpass" / "validation.key"


def _default_validation_output() -> Path:
    return Path.cwd()


def _resolve_validation_key(key_path: Path | None) -> Path:
    """Return the validation key path, generating one if it does not exist."""
    path = key_path or DEFAULT_VALIDATION_KEY
    if not path.exists():
        generate_signing_key(path)
    return path


def _write_validation_artifacts(
    envelope: ValidationEnvelopeSchema,
    output_dir: Path,
    rc: Console,
    state_dir: Path | None = None,
) -> dict[str, Path]:
    """Persist the envelope, badge JSON, badge SVG, and PDF certificate."""
    output_dir.mkdir(parents=True, exist_ok=True)
    short_hash = envelope.run_hash[:16]

    envelope_path = output_dir / f"wafpass-validation-{short_hash}.json"
    badge_json_path = output_dir / f"wafpass-badge-{short_hash}.json"
    badge_svg_path = output_dir / f"wafpass-badge-{short_hash}.svg"
    certificate_pdf_path = output_dir / f"wafpass-certificate-{short_hash}.pdf"

    envelope_path.write_text(
        envelope.model_dump_json(indent=2),
        encoding="utf-8",
    )

    badge = _build_badge_json(envelope)
    badge_json_path.write_text(
        json.dumps(badge, indent=2),
        encoding="utf-8",
    )

    try:
        from wafpass.badge import generate_badge_svg

        badge_svg_path.write_text(
            generate_badge_svg(envelope, badge),
            encoding="utf-8",
        )
    except Exception as exc:
        rc.print(f"[yellow]Badge SVG could not be generated: {exc}[/yellow]")
        badge_svg_path = None  # type: ignore[assignment]

    try:
        from wafpass.pdf_reporter import generate_validation_certificate

        generate_validation_certificate(envelope, certificate_pdf_path)
    except Exception as exc:
        rc.print(f"[yellow]Certificate PDF could not be generated: {exc}[/yellow]")
        certificate_pdf_path = None  # type: ignore[assignment]

    # Lock the local run snapshot for official validations.
    if envelope.status == "official" and state_dir is not None and envelope.result:
        run_id = envelope.result.get("run_id")
        sv = envelope.server_validation
        if run_id and sv:
            try:
                from wafpass.state import lock_run

                lock_run(run_id, state_dir, sv.validation_id, envelope_path)
                rc.print(f"[green]✓ Local run locked[/green]           run-{run_id}-validated.json")
            except Exception as exc:
                rc.print(f"[yellow]Could not lock local run snapshot: {exc}[/yellow]")

    rc.print(f"[green]✓ Validation envelope saved[/green]   {envelope_path}")
    rc.print(f"[green]✓ Badge JSON saved[/green]          {badge_json_path}")
    if badge_svg_path:
        rc.print(f"[green]✓ Badge SVG saved[/green]           {badge_svg_path}")
    if certificate_pdf_path:
        rc.print(f"[green]✓ Certificate PDF saved[/green]     {certificate_pdf_path}")

    return {
        "envelope": envelope_path,
        "badge_json": badge_json_path,
        "badge_svg": badge_svg_path,
        "certificate_pdf": certificate_pdf_path,
    }


def _build_badge_json(envelope: ValidationEnvelopeSchema) -> dict[str, Any]:
    """Build the portable badge JSON for a validation envelope."""
    sv = envelope.server_validation
    result_dict = envelope.result if isinstance(envelope.result, dict) else (
        envelope.result.model_dump() if envelope.result else None
    )
    return {
        "schema_version": "1.0",
        "kind": "wafpass-official-validation",
        "status": envelope.status,
        "run_hash": envelope.run_hash,
        "score": result_dict.get("score") if result_dict else None,
        "project": result_dict.get("project") if result_dict else None,
        "branch": result_dict.get("branch") if result_dict else None,
        "git_sha": result_dict.get("git_sha") if result_dict else None,
        "validation_id": sv.validation_id if sv else None,
        "validated_at": sv.validated_at if sv else None,
        "badge_url": sv.badge_url if sv else "",
        "verification_url": sv.verification_url if sv else "",
        "signer_public_key": envelope.local_attestation.public_key,
    }


def _load_result(path: Path) -> WafpassResultSchema:
    """Load a WafpassResultSchema from JSON."""
    if not path.exists():
        raise FileNotFoundError(f"Result file not found: {path}")
    return WafpassResultSchema.model_validate_json(path.read_text(encoding="utf-8"))


def _load_envelope(path: Path) -> ValidationEnvelopeSchema:
    """Load a ValidationEnvelopeSchema from JSON."""
    if not path.exists():
        raise FileNotFoundError(f"Envelope file not found: {path}")
    return ValidationEnvelopeSchema.model_validate_json(path.read_text(encoding="utf-8"))


def _server_validation_url() -> str | None:
    """Resolve the validation gateway URL from the WAFPASS_VALIDATION_URL env var."""
    return os.environ.get("WAFPASS_VALIDATION_URL")


def _normalize_validation_url(url: str) -> str:
    """Return the gateway validation endpoint URL."""
    url = url.rstrip("/")
    if url.endswith("/api/v1/validations"):
        return url
    return f"{url}/api/v1/validations"


def _resolve_server_certificate(path: Path | str | None) -> str:
    """Load the wafpass-server sub-CA certificate from disk."""
    if path is None:
        return ""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Server certificate not found: {p}")
    return p.read_text(encoding="utf-8").strip()


def _post_validation(
    result: WafpassResultSchema,
    attestation: Any,
    url: str,
    api_key: str | None = None,
    server_certificate: str | None = None,
) -> dict[str, Any]:
    """POST a run + attestation to the WAF++ validation gateway.

    The gateway requires:
      * a valid API key issued by the validation website (X-Api-Key)
      * the wafpass-server's sub-CA certificate issued by the gateway root CA
      * a local attestation over the canonical run hash
      * the run result itself

    Returns the gateway response dict on success. Raises httpx.HTTPStatusError
    or other exceptions on failure.
    """
    headers: dict[str, str] = {"Content-Type": "application/json"}
    effective_key = api_key or os.environ.get("WAFPASS_VALIDATION_API_KEY")
    if effective_key:
        headers["X-Api-Key"] = effective_key

    payload = {
        "server_certificate": server_certificate or "",
        "local_attestation": attestation.model_dump() if hasattr(attestation, "model_dump") else attestation,
        "run": result.model_dump(),
    }

    resp = httpx.post(url, json=payload, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


def _server_response_to_validation(server_response: dict[str, Any]) -> Any:
    """Convert the WAF++ validation gateway response into a ServerValidationSchema.

    The gateway returns a ValidationOut payload directly:
      {
        "validation_id": "...",
        "signed_at": "...",
        "certificate_chain": [...],
        "badge_url": "...",
        "verify_url": "...",
        "status": "valid",
        ...
      }

    This helper maps those fields into the legacy ServerValidationSchema so that
    envelope/badge/certificate generation keeps working.
    """
    from wafpass.schema import ServerValidationSchema

    payload = server_response.get("data", server_response)
    return ServerValidationSchema(
        validation_id=payload.get("validation_id", ""),
        validated_at=payload.get("signed_at", ""),
        server_public_key=payload.get("server_public_key", ""),
        server_signature=payload.get("server_signature", ""),
        certificate_chain=payload.get("certificate_chain", []),
        badge_url=payload.get("badge_url", payload.get("verify_url", "").replace("/verify", "/badge.svg")),
        verification_url=payload.get("verify_url", ""),
        expires_at=None,
    )


# ── Typer app for `wafpass validate` ──────────────────────────────────────────


validate_app = typer.Typer(
    name="validate",
    help="Request and manage WAF++ official validation certificates.",
    add_completion=False,
)


@validate_app.command("generate-key")
def validate_generate_key(
    key_path: Path = typer.Option(
        DEFAULT_VALIDATION_KEY,
        "--path",
        help="Path for the new Ed25519 signing key.",
    ),
) -> None:
    """Generate a new local Ed25519 signing key for validation."""
    rc = Console()
    if key_path.exists():
        rc.print(f"[yellow]Key already exists:[/yellow] {key_path}")
        raise typer.Exit(code=1)
    generate_signing_key(key_path)
    rc.print(f"[green]✓ Generated validation key[/green]  {key_path}")


def _request_official_validation(
    result: WafpassResultSchema,
    key_path: Path,
    output_dir: Path,
    api_key: str | None,
    server_url: str | None,
    server_certificate: str | None,
    rc: Console,
    fallback_on_offline: bool = False,
) -> ValidationEnvelopeSchema | None:
    """Shared implementation: request official validation for a result.

    If *fallback_on_offline* is True and the server cannot be reached, an
    offline envelope is created instead of raising an error.
    """
    key_path = _resolve_validation_key(key_path)
    attestation = sign_run(result, key_path)

    if server_url is not None:
        url = _normalize_validation_url(server_url)
    else:
        url = _server_validation_url()
    if url is None:
        rc.print(
            "[red]No validation gateway configured.[/red]\n"
            "Set WAFPASS_VALIDATION_URL or provide --validation-url."
        )
        raise typer.Exit(code=1)

    rc.print(f"  Requesting official validation via [cyan]{url}[/cyan]…")
    try:
        server_response = _post_validation(
            result, attestation, url, api_key=api_key, server_certificate=server_certificate
        )
        server_validation = _server_response_to_validation(server_response)
    except httpx.ConnectError as exc:
        if fallback_on_offline:
            rc.print(f"[yellow]Cannot reach validation server:[/yellow] {exc}")
            rc.print("  Falling back to offline self-signed validation.")
            return create_offline_envelope(result, key_path)
        rc.print(f"[red]Cannot reach validation server:[/red] {exc}")
        rc.print(
            "Use [bold]wafpass validate offline[/bold] to create an interim self-signed proof, "
            "then upgrade it later with [bold]wafpass validate upgrade[/bold]."
        )
        raise typer.Exit(code=1)
    except httpx.HTTPStatusError as exc:
        detail = ""
        try:
            detail = exc.response.json().get("detail", "")
        except Exception:
            pass
        rc.print(f"[red]Validation request failed:[/red] HTTP {exc.response.status_code} {detail}")
        raise typer.Exit(code=1)
    except Exception as exc:
        rc.print(f"[red]Validation request failed:[/red] {exc}")
        raise typer.Exit(code=1)

    return create_official_envelope(result, attestation, server_validation)


@validate_app.command("official")
def validate_official(
    result_file: Path = typer.Argument(
        Path("wafpass-result.json"),
        help="Path to the wafpass-result.json to validate.",
    ),
    key_path: Path = typer.Option(
        DEFAULT_VALIDATION_KEY,
        "--key",
        help="Path to the organization Ed25519 signing key.",
    ),
    output_dir: Path = typer.Option(
        _default_validation_output,
        "--output-dir",
        help="Directory for the validation envelope, badge, and certificate.",
    ),
    api_key: str | None = typer.Option(
        None,
        "--api-key",
        envvar="WAFPASS_VALIDATION_API_KEY",
        help="API key issued by the WAF++ validation gateway.",
    ),
    validation_url: str | None = typer.Option(
        None,
        "--validation-url",
        envvar="WAFPASS_VALIDATION_URL",
        help="Override the validation gateway URL.",
    ),
    server_certificate: Path | None = typer.Option(
        None,
        "--server-certificate",
        envvar="WAFPASS_SERVER_CERTIFICATE",
        help="Path to the wafpass-server sub-CA certificate issued by the validation gateway.",
    ),
) -> None:
    """Request official WAF++ validation for a run result.

    Requires a validation gateway API key and the wafpass-server sub-CA
    certificate. Obtain the API key from the validation dashboard and the
    certificate from your wafpass-server administrator.
    """
    rc = Console()

    if not result_file.exists():
        rc.print(f"[red]Result file not found:[/red] {result_file}")
        raise typer.Exit(code=2)

    cert_pem = _resolve_server_certificate(server_certificate)
    if not cert_pem:
        rc.print(
            "[red]No server certificate provided.[/red]\n"
            "Provide --server-certificate or set WAFPASS_SERVER_CERTIFICATE."
        )
        raise typer.Exit(code=1)

    result = _load_result(result_file)
    envelope = _request_official_validation(
        result, key_path, output_dir, api_key, validation_url, cert_pem, rc
    )
    _write_validation_artifacts(envelope, output_dir, rc)
    _print_validation_summary(envelope, rc)


@validate_app.command("offline")
def validate_offline(
    result_file: Path = typer.Argument(
        Path("wafpass-result.json"),
        help="Path to the wafpass-result.json to self-sign offline.",
    ),
    key_path: Path = typer.Option(
        DEFAULT_VALIDATION_KEY,
        "--key",
        help="Path to the organization Ed25519 signing key.",
    ),
    output_dir: Path = typer.Option(
        _default_validation_output,
        "--output-dir",
        help="Directory for the validation envelope, badge, and certificate.",
    ),
) -> None:
    """Create a self-signed offline validation when internet is unavailable.

    Offline validations are not official WAF++ certificates, but they are
    cryptographically signed by your organization and can be upgraded later.
    """
    rc = Console()

    if not result_file.exists():
        rc.print(f"[red]Result file not found:[/red] {result_file}")
        raise typer.Exit(code=2)

    key_path = _resolve_validation_key(key_path)
    result = _load_result(result_file)
    envelope = create_offline_envelope(result, key_path)

    _write_validation_artifacts(envelope, output_dir, rc)
    _print_validation_summary(envelope, rc)
    rc.print(
        "[yellow]  This is an offline, self-signed validation.[/yellow]\n"
        "  Run [bold]wafpass validate upgrade --envelope <file>[/bold] once online."
    )


@validate_app.command("upgrade")
def validate_upgrade(
    envelope_file: Path = typer.Argument(
        ...,
        help="Path to the offline validation envelope to upgrade.",
    ),
    output_dir: Path = typer.Option(
        _default_validation_output,
        "--output-dir",
        help="Directory for the upgraded validation artifacts.",
    ),
    api_key: str | None = typer.Option(
        None,
        "--api-key",
        envvar="WAFPASS_VALIDATION_API_KEY",
        help="API key issued by the WAF++ validation gateway.",
    ),
    validation_url: str | None = typer.Option(
        None,
        "--validation-url",
        envvar="WAFPASS_VALIDATION_URL",
        help="Override the validation gateway URL.",
    ),
    server_certificate: Path | None = typer.Option(
        None,
        "--server-certificate",
        envvar="WAFPASS_SERVER_CERTIFICATE",
        help="Path to the wafpass-server sub-CA certificate issued by the validation gateway.",
    ),
) -> None:
    """Upgrade an offline validation envelope to official."""
    rc = Console()

    if not envelope_file.exists():
        rc.print(f"[red]Envelope file not found:[/red] {envelope_file}")
        raise typer.Exit(code=2)

    envelope = _load_envelope(envelope_file)
    if envelope.status != "offline":
        rc.print(f"[red]Envelope status is '{envelope.status}', not 'offline'.[/red]")
        raise typer.Exit(code=1)
    if envelope.result is None:
        rc.print("[red]Envelope contains no result to upgrade.[/red]")
        raise typer.Exit(code=1)

    cert_pem = _resolve_server_certificate(server_certificate)
    if not cert_pem:
        rc.print(
            "[red]No server certificate provided.[/red]\n"
            "Provide --server-certificate or set WAFPASS_SERVER_CERTIFICATE."
        )
        raise typer.Exit(code=1)

    # The result in the envelope is already a dict; convert back to schema.
    result = WafpassResultSchema.model_validate(envelope.result)

    if validation_url is not None:
        url = _normalize_validation_url(validation_url)
    else:
        url = _server_validation_url()
    if url is None:
        rc.print(
            "[red]No validation gateway configured.[/red]\n"
            "Set WAFPASS_VALIDATION_URL or provide --validation-url."
        )
        raise typer.Exit(code=1)

    rc.print(f"  Upgrading offline validation via [cyan]{url}[/cyan]…")
    try:
        server_response = _post_validation(
            result, envelope.local_attestation, url, api_key=api_key, server_certificate=cert_pem
        )
        server_validation = _server_response_to_validation(server_response)
    except httpx.ConnectError as exc:
        rc.print(f"[red]Cannot reach validation server:[/red] {exc}")
        raise typer.Exit(code=1)
    except httpx.HTTPStatusError as exc:
        detail = ""
        try:
            detail = exc.response.json().get("detail", "")
        except Exception:
            pass
        rc.print(f"[red]Upgrade failed:[/red] HTTP {exc.response.status_code} {detail}")
        raise typer.Exit(code=1)
    except Exception as exc:
        rc.print(f"[red]Upgrade failed:[/red] {exc}")
        raise typer.Exit(code=1)

    official = upgrade_offline_envelope(envelope, server_validation)
    _write_validation_artifacts(official, output_dir, rc)
    _print_validation_summary(official, rc)


@validate_app.command("show")
def validate_show(
    envelope_file: Path = typer.Argument(
        ...,
        help="Path to the validation envelope to display.",
    ),
    format: str = typer.Option(
        "summary",
        "--format",
        help="Output format: summary, badge, chain.",
    ),
) -> None:
    """Display a validation envelope, badge, or certificate chain."""
    rc = Console()

    if not envelope_file.exists():
        rc.print(f"[red]Envelope file not found:[/red] {envelope_file}")
        raise typer.Exit(code=2)

    envelope = _load_envelope(envelope_file)

    if format == "badge":
        badge = _build_badge_json(envelope)
        rc.print_json(json.dumps(badge))
        return

    if format == "chain":
        _print_certificate_chain(envelope, rc)
        return

    _print_validation_summary(envelope, rc)


def _print_validation_summary(envelope: ValidationEnvelopeSchema, rc: Console) -> None:
    """Print a human-readable validation summary panel."""
    sv = envelope.server_validation
    table = Table.grid(padding=(0, 2))
    table.add_column(style="dim", justify="right")
    table.add_column()

    table.add_row("Status", f"[bold]{envelope.status.upper()}[/bold]")
    table.add_row("Run hash", f"[cyan]{envelope.run_hash}[/cyan]")
    table.add_row("Signed by", envelope.local_attestation.signer_kind)
    table.add_row("Signed at", envelope.local_attestation.signed_at)
    if sv:
        table.add_row("Validation ID", f"[bold]{sv.validation_id}[/bold]")
        table.add_row("Validated at", sv.validated_at)
        table.add_row("Badge URL", f"[cyan]{sv.badge_url}[/cyan]")
        table.add_row("Verification URL", f"[cyan]{sv.verification_url}[/cyan]")
        if sv.expires_at:
            table.add_row("Expires at", sv.expires_at)
    else:
        table.add_row("Validation ID", "[yellow]— (offline / not yet countersigned)[/yellow]")

    rc.print(Panel(
        table,
        title="[bold white]WAF++ Validation[/bold white]",
        border_style="green" if envelope.status == "official" else "yellow",
        padding=(1, 2),
    ))


def _print_certificate_chain(envelope: ValidationEnvelopeSchema, rc: Console) -> None:
    """Print the certificate chain fingerprints."""
    sv = envelope.server_validation
    if sv is None:
        rc.print("[yellow]No server validation — no certificate chain available.[/yellow]")
        return

    table = Table(title="WAF++ Validation Certificate Chain", show_lines=True)
    table.add_column("Position", style="bold")
    table.add_column("Subject", style="cyan")
    table.add_column("SHA-256 Fingerprint", style="dim")

    for idx, cert_pem in enumerate(sv.certificate_chain):
        try:
            from cryptography import x509

            cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
            fingerprint = cert.fingerprint(cert.signature_hash_algorithm).hex()
            subject = cert.subject.rfc4514_string()
        except Exception:
            subject = "(unknown)"
            fingerprint = "(could not parse)"
        position = "Server" if idx == 0 else "Root"
        table.add_row(position, subject, fingerprint)

    rc.print(table)


# ── Top-level `wafpass verify` command ──────────────────────────────────────────


def verify_command(
    envelope_file: Path = typer.Argument(
        ...,
        help="Path to the validation envelope to verify.",
    ),
    root_public_key: str | None = typer.Option(
        None,
        "--root-public-key",
        help="Path or raw PEM/base64 of the WAF++ root public key/certificate.",
    ),
    check_server: bool = typer.Option(
        False,
        "--check-server",
        help="Query the server verification URL to confirm the validation is still active.",
    ),
) -> None:
    """Locally verify a WAF++ validation envelope and its certificate chain."""
    rc = Console()

    if not envelope_file.exists():
        rc.print(f"[red]Envelope file not found:[/red] {envelope_file}")
        raise typer.Exit(code=2)

    envelope = _load_envelope(envelope_file)

    root_key: str | None = None
    if root_public_key:
        p = Path(root_public_key)
        root_key = p.read_text(encoding="utf-8") if p.exists() else root_public_key

    ok, reason = verify_envelope(envelope, root_public_key_or_cert=root_key)

    if not ok:
        rc.print(f"[red]✗ Verification failed:[/red] {reason}")
        raise typer.Exit(code=1)

    rc.print(f"[green]✓ Local verification passed[/green]  {reason}")

    if check_server and envelope.server_validation and envelope.server_validation.verification_url:
        rc.print("  Checking server-side validation status…")
        try:
            resp = httpx.get(envelope.server_validation.verification_url, timeout=15)
            resp.raise_for_status()
            server_status = resp.json().get("status", "unknown")
            if server_status in ("active", "official", "valid"):
                rc.print("[green]✓ Server validation active[/green]")
            elif server_status == "revoked":
                rc.print("[red]✗ Server validation has been revoked[/red]")
                raise typer.Exit(code=1)
            else:
                rc.print(f"[yellow]  Server status:[/yellow] {server_status}")
        except Exception as exc:
            rc.print(f"[yellow]  Could not check server status:[/yellow] {exc}")
