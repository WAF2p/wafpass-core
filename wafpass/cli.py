"""CLI entry point for WAF++ PASS."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import List

import typer

from wafpass import __name_full__, __version__, run_scan as _public_run_scan
from wafpass.engine import filter_by_severity, run_controls
from wafpass.iac import registry
from wafpass.iac.base import IaCState
from wafpass.loader import load_controls
from wafpass.models import Report
from wafpass.reporter import print_report, print_summary_only
from wafpass.waivers import DEFAULT_SKIP_FILE, apply_waivers, load_waivers

# Optional web dependencies for init --mode dashboard health checks
try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

_DEFAULT_STATE_DIR = Path(".wafpass-state")

# ── UI server helpers ──────────────────────────────────────────────────────────

_UI_PID_FILE = Path.home() / ".wafpass" / "ui.pid"
_UI_LOG_FILE = Path.home() / ".wafpass" / "ui.log"

# The serve package lives next to wafpass/ inside the same project root.
_SERVE_ROOT = Path(__file__).parent.parent  # …/pass/


def _pid_file_read() -> int | None:
    """Return the PID from the pid-file, or None if absent / stale."""
    if not _UI_PID_FILE.exists():
        return None
    try:
        pid = int(_UI_PID_FILE.read_text().strip())
    except (ValueError, OSError):
        return None
    # Verify the process still exists
    try:
        os.kill(pid, 0)
        return pid
    except (ProcessLookupError, PermissionError):
        return None


def _pid_file_write(pid: int) -> None:
    _UI_PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    _UI_PID_FILE.write_text(str(pid))


def _pid_file_remove() -> None:
    try:
        _UI_PID_FILE.unlink(missing_ok=True)
    except OSError:
        pass


# ── Demo IaC generator ─────────────────────────────────────────────────────────

_DEMO_MAIN_TF = '''\
# WAF++ PASS demo file — intentionally contains a public S3 bucket.
# This file is generated for local scanning only; do not deploy it to AWS.

resource "aws_s3_bucket" "example" {{
  bucket = "{bucket_name}"
}}

resource "aws_s3_bucket_public_access_block" "example" {{
  bucket = aws_s3_bucket.example.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}}
'''


def _generate_demo_bucket_name() -> str:
    """Return a unique, obviously-local S3 bucket name for demo scans."""
    import secrets
    suffix = secrets.token_hex(4)
    return f"wafpass-demo-{suffix}"


def _write_demo_main_tf(dest_dir: Path, bucket_name: str | None = None) -> Path:
    """Write a deliberately non-compliant demo main.tf into *dest_dir*.

    The generated bucket name is unique and clearly local-only, avoiding
    collisions with real AWS buckets while still producing a predictable
    FAIL on public-access controls.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    name = bucket_name or _generate_demo_bucket_name()
    main_tf = dest_dir / "main.tf"
    main_tf.write_text(_DEMO_MAIN_TF.format(bucket_name=name), encoding="utf-8")
    return main_tf


app = typer.Typer(
    name="wafpass",
    help="WAF++ PASS – IaC controls checker for the WAF++ framework.",
    add_completion=False,
)

ui_app = typer.Typer(
    name="ui",
    help="Manage the WAF++ PASS web UI server.",
    add_completion=False,
)
app.add_typer(ui_app, name="ui")

control_app = typer.Typer(
    name="control",
    help="Author, validate, and manage WAF++ PASS controls.",
    add_completion=False,
)
app.add_typer(control_app, name="control")

# ── wafpass validate / verify ─────────────────────────────────────────────────

from wafpass.validation_cli import (  # noqa: E402
    validate_app,
    verify_command,
)

# validate_app already registers generate-key / official / offline / upgrade / show
# inside wafpass.validation_cli, so we only need to mount it on the top-level CLI.
app.add_typer(validate_app, name="validate")
app.command("verify")(verify_command)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"{__name_full__} v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """WAF++ PASS – check IaC files against WAF++ controls."""


@app.command()
def check(
    paths: List[Path] = typer.Argument(
        ...,
        help=(
            "Path(s) to IaC files (directories or individual files). "
            "Pass multiple paths to merge results from different cloud folders, "
            "e.g. wafpass check ./aws ./azure ./gcp"
        ),
    ),
    iac: str = typer.Option(
        "terraform",
        "--iac",
        help=(
            "IaC framework plugin to use for parsing. "
            f"Available: terraform, bicep, cdk, pulumi. "
            "Default: terraform."
        ),
    ),
    controls_dir: Path = typer.Option(
        Path("controls"),
        "--controls-dir",
        help="Path to WAF++ YAML control files.",
    ),
    server_url: str = typer.Option(
        "",
        "--server-url",
        envvar="WAFPASS_SERVER_URL",
        help=(
            "wafpass-server URL to fetch controls from. "
            "Overrides --controls-dir. Requires --output json for --push integration."
        ),
    ),
    pillar: str | None = typer.Option(
        None,
        "--pillar",
        help="Filter by pillar name: cost, sovereign, security, reliability, operations, architecture, governance.",
    ),
    control_ids: str | None = typer.Option(
        None,
        "--controls",
        help="Comma-separated list of control IDs to run (e.g. WAF-COST-010,WAF-COST-020).",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        help="Minimum severity level to evaluate: low, medium, high, critical.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show all results including PASSes (default: only show FAILs and SKIPs).",
    ),
    fail_on: str = typer.Option(
        "fail",
        "--fail-on",
        help="Exit non-zero condition: 'fail' (default), 'skip', 'any'.",
    ),
    output: str = typer.Option(
        "console",
        "--output",
        help="Output format: console, pdf, json.",
    ),
    push: str | None = typer.Option(
        None,
        "--push",
        help=(
            "POST the result to this URL (e.g. http://localhost:8000/api/v1/runs). "
            "Pass [bold]@[/bold] to push to the server from 'wafpass login' using your stored token. "
            "Requires --output json."
        ),
    ),
    api_key: str | None = typer.Option(
        None,
        "--api-key",
        envvar="WAFPASS_API_KEY",
        help=(
            "API key sent as 'X-Api-Key' header when using --push. "
            "Not needed after 'wafpass login' — Bearer token is used automatically. "
            "Can also be set via the WAFPASS_API_KEY environment variable."
        ),
    ),
    validation_url: str | None = typer.Option(
        None,
        "--validation-url",
        envvar="WAFPASS_VALIDATION_URL",
        help="Validation gateway URL for --validate official (default: env WAFPASS_VALIDATION_URL).",
    ),
    validation_api_key: str | None = typer.Option(
        None,
        "--validation-api-key",
        envvar="WAFPASS_VALIDATION_API_KEY",
        help="API key for the validation gateway when using --validate official.",
    ),
    server_certificate: Path | None = typer.Option(
        None,
        "--server-certificate",
        envvar="WAFPASS_SERVER_CERTIFICATE",
        help="Path to the wafpass-server sub-CA certificate for --validate official.",
    ),
    project: str = typer.Option(
        "",
        "--project",
        help="Project / repo name to embed in the result (used by wafpass-server).",
    ),
    branch: str = typer.Option(
        "",
        "--branch",
        help="VCS branch name (auto-detected from git if not set).",
    ),
    git_sha: str = typer.Option(
        "",
        "--git-sha",
        help="Commit SHA (auto-detected from git if not set).",
    ),
    triggered_by: str = typer.Option(
        "",
        "--triggered-by",
        help="Trigger source: local, github-actions, gitlab-ci, … (auto-detected if not set).",
    ),
    is_cicd: bool = typer.Option(
        False,
        "--is-cicd",
        flag_value=True,
        help="Set to true if this run was triggered by a CI/CD pipeline.",
    ),
    stage: str = typer.Option(
        "",
        "--stage",
        help="Deployment stage this run targets, e.g. dev, staging, prod.",
    ),
    pdf_out: Path = typer.Option(
        None,
        "--pdf-out",
        help="Destination path for the PDF report (default: wafpass-report.pdf). Only used with --output pdf.",
    ),
    summary_only: bool = typer.Option(
        False,
        "--summary",
        help="Print only the summary table, not per-control details.",
    ),
    skip_file: Path = typer.Option(
        None,
        "--skip-file",
        help=(
            f"Path to a YAML waiver file listing controls to intentionally skip "
            f"(default: auto-discovered '{DEFAULT_SKIP_FILE}' in the current directory)."
        ),
    ),
    baseline_path: Path = typer.Option(
        None,
        "--baseline",
        help="Path to a JSON baseline from a previous run — enables trend/delta in the PDF report.",
    ),
    save_baseline_path: Path = typer.Option(
        None,
        "--save-baseline",
        help="Save the current run as a JSON baseline file for future trend comparison.",
    ),
    state_dir: Path = typer.Option(
        _DEFAULT_STATE_DIR,
        "--state-dir",
        help=(
            "Directory for versioned run state files "
            f"(default: {_DEFAULT_STATE_DIR}). Each run is saved as a JSON snapshot. "
            "Set to empty string to disable."
        ),
    ),
    no_state: bool = typer.Option(
        False,
        "--no-state",
        help="Disable automatic run state saving and change tracking.",
    ),
    export: str | None = typer.Option(
        None,
        "--export",
        help=(
            "Comma-separated list of export plugin names to push the run snapshot to "
            "(e.g. 'grafana', 'grafana,webhook', 'slack'). "
            "Available: grafana, prometheus, datadog, splunk, slack, webhook."
        ),
    ),
    export_config: Path = typer.Option(
        None,
        "--export-config",
        help=(
            "Path to a YAML export config file (default: auto-discovered "
            "'.wafpass-export.yml' in the current directory). "
            "See README for the expected format."
        ),
    ),
    blast_radius: bool = typer.Option(
        False,
        "--blast-radius",
        help=(
            "After the main report, analyse and visualise how failing resources "
            "affect downstream dependent resources (blast radius). "
            "Also writes a Mermaid diagram to blast_radius.md."
        ),
    ),
    blast_radius_out: Path = typer.Option(
        Path("blast_radius.md"),
        "--blast-radius-out",
        help="Destination for the Mermaid blast radius diagram (default: blast_radius.md).",
    ),
    no_secrets: bool = typer.Option(
        False,
        "--no-secrets",
        help="Disable the hardcoded-secret scanner (enabled by default).",
    ),
    plan_file: Path = typer.Option(
        None,
        "--plan-file",
        help=(
            "Path to a JSON file produced by 'terraform show -json <plan>' or "
            "'terraform plan -json'. When provided the parsed resource-change "
            "summary is embedded in the JSON output and pushed to the dashboard "
            "as 'plan_changes', enabling Change Overview analysis."
        ),
    ),
    upload_source: bool = typer.Option(
        False,
        "--upload-source",
        flag_value=True,
        help=(
            "When used with --push, also upload the contents of all source files "
            "for the selected IaC plugin so the dashboard can render Local preview diffs. "
            "Requires --output json and --push."
        ),
    ),
    validate: str | None = typer.Option(
        None,
        "--validate",
        help="Request validation: 'official' (server countersigned) or 'offline' (self-signed). Requires --output json.",
    ),
    validation_key: Path = typer.Option(
        Path.home() / ".wafpass" / "validation.key",
        "--validation-key",
        help="Path to the organization Ed25519 signing key (auto-generated if missing).",
    ),
    validation_output: Path = typer.Option(
        Path.cwd(),
        "--validation-output",
        help="Directory for validation envelope, badge, and certificate files.",
    ),
    skip_validation_on_offline: bool = typer.Option(
        False,
        "--skip-validation-on-offline",
        flag_value=True,
        help="If official validation fails because the server is unreachable, fall back to offline mode instead of erroring.",
    ),
) -> None:
    """Check IaC files against WAF++ YAML controls."""

    # ── Validate --upload-source prerequisites ────────────────────────────────
    if upload_source and (not push or output != "json"):
        typer.echo(
            "ERROR: --upload-source requires --output json and --push. "
            "Re-run with --output json --push <url|@> --upload-source.",
            err=True,
        )
        raise typer.Exit(code=2)

    # ── Validate --validate prerequisites ───────────────────────────────────────
    if validate and output != "json":
        typer.echo(
            "ERROR: --validate requires --output json so the run result can be signed.",
            err=True,
        )
        raise typer.Exit(code=2)
    if validate and validate not in ("official", "offline"):
        typer.echo(
            "ERROR: --validate must be 'official' or 'offline'.",
            err=True,
        )
        raise typer.Exit(code=2)

    # ── Validate --plan-file path ─────────────────────────────────────────────
    if plan_file and not plan_file.exists():
        typer.echo(f"ERROR: --plan-file path does not exist: {plan_file}", err=True)
        raise typer.Exit(code=2)

    # Parse control ID list
    ids: list[str] | None = None
    if control_ids:
        ids = [i.strip() for i in control_ids.split(",") if i.strip()]

    # ── Resolve waiver file ───────────────────────────────────────────────────
    def _find_skip_file() -> Path | None:
        # Discover both the canonical risk_acceptance.yml and legacy .wafpass-skip.yml
        _names = ["risk_acceptance.yml", DEFAULT_SKIP_FILE]
        candidates: list[Path] = []
        for name in _names:
            candidates.append(Path(name))
            for p in paths:
                d = p if p.is_dir() else p.parent
                candidate = d / name
                if candidate not in candidates:
                    candidates.append(candidate)
        for c in candidates:
            if c.exists():
                return c
        return None

    _active_waivers: list = []
    resolved_skip_file = skip_file or _find_skip_file()
    if resolved_skip_file:
        try:
            _active_waivers = load_waivers(resolved_skip_file)
        except ValueError as exc:
            typer.echo(f"ERROR in waiver file: {exc}", err=True)
            raise typer.Exit(code=2) from exc

    # ── Load controls (from filesystem or server) ──────────────────────────────
    effective_controls_dir = controls_dir
    if server_url:
        effective_controls_dir = Path(".wafpass-server-controls")
        typer.echo(f"Fetching controls from: {server_url}", err=True)

    # ── Run the core scan ──────────────────────────────────────────────────────
    from wafpass.runner import ScanConfig, run_scan

    try:
        report, schema = run_scan(ScanConfig(
            paths=list(paths),
            controls_dir=effective_controls_dir,
            iac=iac,
            project=project,
            branch=branch,
            git_sha=git_sha,
            triggered_by=triggered_by,
            is_cicd=is_cicd,
            stage=stage,
            control_ids=ids,
            severity=severity,
            pillar=pillar,
            waivers_file=resolved_skip_file,
            plan_file=plan_file,
            no_secrets=no_secrets,
            upload_source=upload_source,
            server_url=server_url,
        ))
    except FileNotFoundError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except ValueError as exc:
        msg = str(exc)
        if "No controls found" in msg:
            _hint = (f" (pillar={pillar})" if pillar else "") + (f" (ids={ids})" if ids else "")
            _src = f"from server {server_url!r}" if server_url else f"in '{controls_dir}'"
            typer.echo(f"No controls found {_src}{_hint}", err=True)
            typer.echo("", err=True)
            typer.echo("Controls are not bundled with WAF++ PASS — they must be obtained separately.", err=True)
            typer.echo("", err=True)
            typer.echo("Option A — Download from the WAF++ website:", err=True)
            typer.echo("  1. Visit https://waf2p.dev/wafpass/ and click \"Download Controls\"", err=True)
            typer.echo("  2. Unzip the archive and copy the *.yml files into your controls directory:", err=True)
            typer.echo(f"       cp /path/to/download/*.yml {controls_dir}/", err=True)
            typer.echo("", err=True)
            typer.echo("Option B — Clone the WAF++ framework repository:", err=True)
            typer.echo("  git clone https://github.com/WAF2p/framework.git", err=True)
            typer.echo(f"  cp framework/modules/controls/controls/*.yml {controls_dir}/", err=True)
            typer.echo("", err=True)
            typer.echo("Then re-run your wafpass command.", err=True)
            raise typer.Exit(code=2)
        typer.echo(f"ERROR: {msg}", err=True)
        raise typer.Exit(code=2) from exc
    except Exception as exc:
        typer.echo(f"ERROR running scan: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    _secret_findings = report.secret_findings

    # ── Secret scanner output (console/PDF path) ───────────────────────────────
    if not no_secrets and _secret_findings and output in ("console", "pdf"):
        from wafpass.secret_scanner import REMEDIATION_GUIDANCE
        from rich.console import Console as _RichConsole
        from rich.panel import Panel as _Panel
        from rich.table import Table as _Table
        from rich.text import Text as _Text

        _visible = [f for f in _secret_findings if not f.suppressed]
        _suppressed_count = sum(1 for f in _secret_findings if f.suppressed)

        if _visible:
            _rc = _RichConsole(stderr=True)
            _sev_style = {"critical": "bold red", "high": "red", "medium": "yellow"}

            _tbl = _Table(show_header=True, header_style="bold white on dark_red",
                          show_lines=True, expand=True)
            _tbl.add_column("Severity", style="bold", width=10)
            _tbl.add_column("File : Line", style="cyan", no_wrap=True)
            _tbl.add_column("Finding", style="white")
            _tbl.add_column("Attribute", style="dim")
            _tbl.add_column("Value (masked)", style="dim")

            for _f in _visible:
                _style = _sev_style.get(_f.severity, "white")
                _tbl.add_row(
                    _Text(_f.severity.upper(), style=_style),
                    f"{_f.file}:{_f.line_no}",
                    _f.pattern_name,
                    _f.matched_key or "—",
                    _f.masked_value,
                )

            _rc.print()
            _rc.print(_Panel(
                _tbl,
                title="[bold white on dark_red] ⚠  HARDCODED SECRETS DETECTED [/bold white on dark_red]",
                border_style="red",
                padding=(0, 1),
            ))
            _rc.print()
            _rc.print(f"[bold red]{len(_visible)} hardcoded secret(s) found.[/bold red] "
                      f"These must be remediated before deployment.")
            if _suppressed_count:
                _rc.print(f"[dim]{_suppressed_count} finding(s) suppressed via wafpass:ignore-secret.[/dim]")
            _rc.print()
            _rc.print("[bold]How to fix:[/bold]")
            for _line in REMEDIATION_GUIDANCE.splitlines():
                _rc.print(f"  [dim]{_line}[/dim]" if _line.startswith(" ") else f"  {_line}")
            _rc.print()

    # ── Run state: load previous, compute diff, save current ───────────────────
    run_diff: dict | None = None
    snapshot: dict | None = None
    _state_enabled = not no_state and state_dir and str(state_dir) not in ("", "none")

    if _state_enabled:
        from wafpass.state import (
            build_run_snapshot,
            compute_diff,
            generate_run_id,
            load_latest_run,
            save_run,
        )

        run_id = generate_run_id()
        snapshot = build_run_snapshot(report, run_id=run_id, iac_plugin=iac.lower(), stage=stage)

        previous_run = load_latest_run(state_dir)
        if previous_run is not None:
            run_diff = compute_diff(previous_run, snapshot)
            # Embed provenance of previous run into the snapshot for traceability
            snapshot["diff_from_previous"] = run_diff

        try:
            saved_to = save_run(snapshot, state_dir)
            typer.echo(f"Run state saved: {saved_to}  (run-id: {run_id})")
        except Exception as exc:
            typer.echo(f"WARNING: Could not save run state to '{state_dir}': {exc}", err=True)

    # ── Blast radius computation (needed by both console and PDF output) ────────
    _br_result = None
    if blast_radius:
        from wafpass.blast_radius import build_dependency_graph, compute_blast_radius
        graph = build_dependency_graph(report.state)
        _br_result = compute_blast_radius(report, report.state, graph)

    # ── Carbon footprint (always computed for PDF; skipped for console-only) ──
    _carbon_result = None
    if output == "pdf":
        try:
            from wafpass.carbon import compute_carbon
            _carbon_result = compute_carbon(report.state, report, report.detected_regions)
        except Exception as exc:
            typer.echo(f"WARNING: Could not compute carbon footprint: {exc}", err=True)

    # ── Output ─────────────────────────────────────────────────────────────────
    if output == "console":
        if summary_only:
            print_summary_only(report, schema.score)
        else:
            print_report(report, verbose=verbose, diff=run_diff, score=schema.score)
    elif output == "pdf":
        try:
            from wafpass.pdf_reporter import generate_pdf
        except ImportError:
            typer.echo(
                "ERROR: PDF output requires 'reportlab'. Install with: pip install reportlab",
                err=True,
            )
            raise typer.Exit(code=2)
        from wafpass.baseline import build_baseline, load_baseline, save_baseline as save_baseline_file

        dest = pdf_out or Path("wafpass-report.pdf")

        baseline_data: dict | None = None
        if baseline_path:
            try:
                baseline_data = load_baseline(baseline_path)
            except Exception as exc:
                typer.echo(f"WARNING: Could not load baseline '{baseline_path}': {exc}", err=True)

        generate_pdf(report, dest, baseline=baseline_data, diff=run_diff,
                     blast_radius_result=_br_result,
                     secret_findings=_secret_findings or None,
                     carbon_result=_carbon_result,
                     waivers=_active_waivers or None)
        typer.echo(f"PDF report written to: {dest}")

        if save_baseline_path:
            snap = build_baseline(report)
            save_baseline_file(snap, save_baseline_path)
            typer.echo(f"Baseline saved to: {save_baseline_path}")
        # Also print summary to console so CI pipelines see the result
        print_summary_only(report, schema.score)
    elif output == "json":
        _json_str = schema.model_dump_json(indent=2)
        typer.echo(_json_str)

        if schema.plan_changes:
            _total_changes = sum(
                v for k, v in schema.plan_changes.get("summary", {}).items() if k != "no_op"
            )
            typer.echo(
                f"Plan file parsed: {_total_changes} resource change(s) detected "
                f"({plan_file})",
                err=True,
            )

        if push:
            try:
                import httpx as _httpx
                from wafpass.auth import resolve_push_target, get_valid_credentials

                _push_url, _auto_headers = resolve_push_target(push)

                if push == "@" and _push_url is None:
                    typer.echo(
                        "ERROR: --push @ requires an active login session. "
                        "Run 'wafpass login <server-url>' first.",
                        err=True,
                    )
                    raise typer.Exit(code=1)

                _push_headers: dict[str, str] = {
                    "Content-Type": "application/json",
                    **_auto_headers,
                }
                # Explicit --api-key always wins over the stored Bearer token
                if api_key:
                    _push_headers.pop("Authorization", None)
                    _push_headers["X-Api-Key"] = api_key

                _resp = _httpx.post(
                    _push_url,
                    content=_json_str,
                    headers=_push_headers,
                    timeout=30,
                )
                if _resp.status_code == 401:
                    # Token may have just expired — try one refresh and retry
                    _creds = get_valid_credentials()
                    if _creds and not api_key:
                        _push_headers["Authorization"] = _creds.bearer()
                        _resp = _httpx.post(_push_url, content=_json_str, headers=_push_headers, timeout=30)
                _resp.raise_for_status()
                typer.echo(f"Pushed to {_push_url}  →  HTTP {_resp.status_code}", err=True)
            except SystemExit:
                raise
            except Exception as exc:
                typer.echo(f"ERROR: Push to '{push}' failed: {exc}", err=True)
                raise typer.Exit(code=2)

    else:
        typer.echo(f"Output format '{output}' is not yet supported.", err=True)
        raise typer.Exit(code=2)

    # ── Push for non-JSON output modes (--push without --output json) ──────────
    if push and output != "json":
        _push_hint = push if push != "@" else "@ (stored server)"
        typer.echo(
            f"NOTE: --push only works with --output json. "
            f"Re-run with --output json --push {_push_hint}.",
            err=True,
        )

    # ── Validation (official / offline) ────────────────────────────────────────
    if validate and output == "json":
        from wafpass.validation_cli import (
            _request_official_validation,
            _write_validation_artifacts,
            _print_validation_summary,
            create_offline_envelope,
            generate_signing_key,
        )
        from rich.console import Console as _RichConsole

        _rc = _RichConsole()

        if not validation_key.exists():
            generate_signing_key(validation_key)

        if validate == "offline":
            _envelope = create_offline_envelope(schema, validation_key)
        else:  # official
            cert_pem = ""
            if server_certificate:
                cert_pem = server_certificate.read_text(encoding="utf-8").strip()
            elif os.environ.get("WAFPASS_SERVER_CERTIFICATE"):
                cert_pem = Path(os.environ["WAFPASS_SERVER_CERTIFICATE"]).read_text(encoding="utf-8").strip()
            if not cert_pem:
                _rc.print(
                    "[red]--validate official requires a server certificate.[/red]\n"
                    "Provide --server-certificate or set WAFPASS_SERVER_CERTIFICATE."
                )
                raise typer.Exit(code=1)

            _envelope = _request_official_validation(
                result=schema,
                key_path=validation_key,
                output_dir=validation_output,
                api_key=validation_api_key,
                server_url=validation_url,
                server_certificate=cert_pem,
                rc=_rc,
                fallback_on_offline=skip_validation_on_offline,
            )
            if _envelope is None:
                raise typer.Exit(code=1)

        # Embed the attestation back into the JSON result that is printed.
        schema.attestation = _envelope.local_attestation

        # Make the run_id available inside the envelope result for local locking.
        if _state_enabled and snapshot is not None:
            _envelope.result["run_id"] = snapshot["run_id"]

        _write_validation_artifacts(
            _envelope, validation_output, _rc,
            state_dir=state_dir if _state_enabled else None,
        )
        _print_validation_summary(_envelope, _rc)

        if _envelope.status == "offline":
            _rc.print(
                "[yellow]  This is an offline, self-signed validation.[/yellow]\n"
                "  Run [bold]wafpass validate upgrade --envelope <file>[/bold] once online."
            )

    # ── Export to monitoring systems ───────────────────────────────────────────
    if export and _state_enabled and snapshot is not None:
        import wafpass.export.plugins  # noqa: F401 — triggers self-registration
        from wafpass.export.registry import registry as export_registry
        from wafpass.export.config import load_export_config, DEFAULT_EXPORT_CONFIG

        # Load export config file
        _export_cfg_path = export_config or DEFAULT_EXPORT_CONFIG
        _export_configs: dict[str, dict] = {}
        if _export_cfg_path.exists():
            try:
                _export_configs = load_export_config(_export_cfg_path)
            except Exception as exc:
                typer.echo(f"WARNING: Could not load export config '{_export_cfg_path}': {exc}", err=True)
        elif export_config is not None:
            typer.echo(f"ERROR: Export config file not found: {export_config}", err=True)
            raise typer.Exit(code=2)

        for plugin_name in [n.strip() for n in export.split(",") if n.strip()]:
            exp_plugin = export_registry.get(plugin_name)
            if exp_plugin is None:
                available_exp = ", ".join(export_registry.available) or "(none)"
                typer.echo(
                    f"WARNING: Unknown export plugin '{plugin_name}'. "
                    f"Available: {available_exp}",
                    err=True,
                )
                continue
            plugin_cfg = _export_configs.get(plugin_name, {})
            typer.echo(f"Exporting to [{plugin_name}]...")
            result = exp_plugin.export(snapshot, plugin_cfg)
            if result.success:
                typer.echo(f"  ✓ {plugin_name}: {result.message}")
            else:
                typer.echo(f"  ✗ {plugin_name}: {result.message}", err=True)
    elif export and not _state_enabled:
        typer.echo(
            "WARNING: --export requires run state tracking. "
            "Remove --no-state or set --state-dir to enable export.",
            err=True,
        )

    # ── Blast radius analysis — terminal + Mermaid output ─────────────────────
    if blast_radius and _br_result is not None:
        from wafpass.blast_renderer import print_blast_radius, write_mermaid
        from rich.console import Console

        print_blast_radius(_br_result, console=Console())
        try:
            write_mermaid(_br_result, blast_radius_out)
            typer.echo(f"Blast radius diagram written to: {blast_radius_out}")
        except Exception as exc:
            typer.echo(f"WARNING: Could not write blast radius diagram: {exc}", err=True)

    # ── Exit code ──────────────────────────────────────────────────────────────
    fail_on_lower = fail_on.lower()
    if fail_on_lower == "fail" and report.total_fail > 0:
        raise typer.Exit(code=1)
    elif fail_on_lower == "skip" and (report.total_fail > 0 or report.total_skip > 0):
        raise typer.Exit(code=1)
    elif fail_on_lower == "any" and (report.total_fail > 0 or report.total_skip > 0):
        raise typer.Exit(code=1)


# ── Demo command ─────────────────────────────────────────────────────────────────

_DEMO_PROJECT = "wafpass-demo"
_DEMO_DIR = Path.home() / ".wafpass" / "demo"
_DEMO_CONTROLS_DIR = Path.home() / ".wafpass" / "controls"


def _ensure_demo_controls(controls_dir: Path) -> Path:
    """Return a controls directory guaranteed to contain controls.

    If *controls_dir* exists and is non-empty, use it. Otherwise fall back to
    the bundled controls next to the CLI (development layout) or the user's
    shared cache directory. Raises typer.Exit if no controls can be found.
    """
    candidates = [
        controls_dir,
        _DEMO_CONTROLS_DIR,
        Path("controls"),
    ]
    for candidate in candidates:
        if candidate.exists() and any(candidate.glob("*.yml")):
            return candidate

    typer.echo(
        "ERROR: No WAF++ controls found. "
        "Run from a directory that contains a 'controls/' folder, "
        "or pass --controls-dir.",
        err=True,
    )
    raise typer.Exit(code=2)


@app.command()
def demo(
    controls_dir: Path = typer.Option(
        Path("controls"),
        "--controls-dir",
        help="Path to WAF++ YAML control files.",
    ),
    server_url: str = typer.Option(
        "",
        "--server-url",
        envvar="WAFPASS_SERVER_URL",
        help=(
            "wafpass-server URL to POST the demo result to. "
            "Equivalent to --push on 'wafpass check'."
        ),
    ),
    api_key: str | None = typer.Option(
        None,
        "--api-key",
        envvar="WAFPASS_API_KEY",
        help=(
            "API key sent as 'X-Api-Key' when posting to --server-url. "
            "Not needed after 'wafpass login'."
        ),
    ),
    no_push: bool = typer.Option(
        False,
        "--no-push",
        help="Run the demo locally without pushing to the server.",
    ),
    no_state: bool = typer.Option(
        False,
        "--no-state",
        help="Disable automatic run state saving for the demo scan.",
    ),
) -> None:
    """Run a sample scan and optionally seed the dashboard with the result."""
    from wafpass.state import generate_run_id

    # ── Prepare demo project ───────────────────────────────────────────────────
    _DEMO_DIR.mkdir(parents=True, exist_ok=True)
    _write_demo_main_tf(_DEMO_DIR)

    effective_controls_dir = _ensure_demo_controls(controls_dir)

    # ── Run scan ───────────────────────────────────────────────────────────────
    typer.echo("Running WAF++ PASS demo scan...", err=True)
    try:
        schema = _public_run_scan(
            paths=[str(_DEMO_DIR)],
            controls_dir=str(effective_controls_dir),
        )
    except Exception as exc:
        typer.echo(f"ERROR running demo scan: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    # Enrich metadata for the demo result
    schema.project = _DEMO_PROJECT
    schema.branch = "main"
    schema.stage = "demo"
    schema.triggered_by = "local"
    schema.iac_framework = "terraform"

    # ── Optional state snapshot ─────────────────────────────────────────────
    run_id = ""
    state_dir = _DEFAULT_STATE_DIR
    if not no_state:
        from wafpass.state import build_run_snapshot, save_run
        from wafpass.models import Report as ReportModel

        # Build a minimal Report for state saving from the schema's totals.
        report = ReportModel(
            path=str(_DEMO_DIR),
            controls_loaded=schema.controls_loaded,
            controls_run=schema.controls_run,
            results=[],
            source_paths=[str(_DEMO_DIR)],
        )
        snapshot = build_run_snapshot(
            report,
            run_id=generate_run_id(),
            iac_plugin="terraform",
            stage="demo",
        )
        snapshot["totals"] = {
            "controls_run": schema.controls_run,
            "pass": sum(1 for f in schema.findings if f.status == "PASS"),
            "fail": sum(1 for f in schema.findings if f.status == "FAIL"),
            "skip": sum(1 for f in schema.findings if f.status == "SKIP"),
            "waived": sum(1 for f in schema.findings if f.status == "WAIVED"),
        }
        save_run(snapshot, state_dir)
        run_id = snapshot["run_id"]

    # ── Print friendly summary ───────────────────────────────────────────────
    from wafpass.reporter import _compute_score

    score = schema.score
    pass_count = sum(1 for f in schema.findings if f.status == "PASS")
    fail_count = sum(1 for f in schema.findings if f.status == "FAIL")
    skip_count = sum(1 for f in schema.findings if f.status == "SKIP")

    from rich.console import Console as _RichConsole

    _rc = _RichConsole()
    _rc.print("")
    _rc.print(f"[bold cyan]WAF++ PASS demo[/bold cyan]  [dim]v{__version__}[/dim]")
    _rc.print(f"  Project: {_DEMO_PROJECT}")
    _rc.print(f"  Score:   {score}/100")
    _rc.print(
        f"  Findings: [green]✓ PASS {pass_count}[/green]  "
        f"[red]✗ FAIL {fail_count}[/red]  "
        f"[yellow]─ SKIP {skip_count}[/yellow]"
    )
    _rc.print("")

    # ── Push to server ────────────────────────────────────────────────────────
    dashboard_url = "http://localhost:3000"
    push_url: str | None = None
    if not no_push and server_url:
        try:
            import httpx as _httpx
            from wafpass.auth import resolve_push_target

            push_arg = server_url
            _resolved_url, _auto_headers = resolve_push_target(push_arg)
            if push_arg == "@" and _resolved_url is None:
                typer.echo(
                    "ERROR: --server-url @ requires an active login session. "
                    "Run 'wafpass login <server-url>' first.",
                    err=True,
                )
                raise typer.Exit(code=1)

            push_url = _resolved_url or push_arg
            _push_headers: dict[str, str] = {
                "Content-Type": "application/json",
                **_auto_headers,
            }
            if api_key:
                _push_headers.pop("Authorization", None)
                _push_headers["X-Api-Key"] = api_key

            json_payload = schema.model_dump_json(indent=2)
            _resp = _httpx.post(
                push_url,
                content=json_payload,
                headers=_push_headers,
                timeout=30,
            )
            _resp.raise_for_status()
            data = _resp.json()
            run_summary = data.get("data", {})
            server_run_id = run_summary.get("id", "")
            dashboard_url = f"http://localhost:3000/runs/{server_run_id}"
            typer.echo(f"Pushed to {push_url}  →  HTTP {_resp.status_code}", err=True)
        except SystemExit:
            raise
        except Exception as exc:
            typer.echo(f"WARNING: Could not push demo result to server: {exc}", err=True)
            dashboard_url = "http://localhost:3000"

    # ── Final CTA ──────────────────────────────────────────────────────────────
    _rc.print(f"Open the dashboard: {dashboard_url}")
    if not server_url:
        _rc.print("")
        _rc.print(
            "[dim]Re-run with --server-url http://localhost:8000/runs "
            "to seed the dashboard with this scan.[/dim]"
        )
    if run_id:
        _rc.print(f"[dim]Local run state saved: run-id {run_id}[/dim]")


# ── Init command ─────────────────────────────────────────────────────────────────

_INIT_STACK_DIR = Path.home() / ".wafpass" / "stack"
_INIT_DEMO_DIR = Path("wafpass-demo")
_INIT_CONTROLS_CACHE = Path.home() / ".wafpass" / "controls"


_INIT_REQUIRED_ENVS = [
    "POSTGRES_USER",
    "POSTGRES_PASSWORD",
    "POSTGRES_DB",
    "WAFPASS_ENV",
    "WAFPASS_JWT_SECRET",
    "WAFPASS_JWT_EXPIRE_MINUTES",
    "WAFPASS_JWT_REFRESH_DAYS",
    "WAFPASS_ADMIN_USERNAME",
    "WAFPASS_ADMIN_PASSWORD",
    "WAFPASS_API_KEY",
    "WAFPASS_INTERNAL_API_KEY",
    "WAFPASS_CONTROLS_DIR",
    "WAFPASS_BASE_PATH",
    "KEYCLOAK_DB",
    "KEYCLOAK_DB_USER",
    "KEYCLOAK_DB_PASSWORD",
    "KEYCLOAK_ADMIN_USER",
    "KEYCLOAK_ADMIN_PASSWORD",
]


def _random_secret(length: int = 32) -> str:
    """Return a URL-safe random secret string."""
    import secrets
    return secrets.token_urlsafe(length)


def _locate_compose_file() -> Path | None:
    """Find a usable docker-compose.yml in the current directory or monorepo root."""
    candidates = [
        Path("docker-compose.yml"),
        Path.cwd().parent / "docker-compose.yml",
    ]
    for candidate in candidates:
        if candidate.exists():
            # Sanity check: file should mention the wafpass-server service.
            text = candidate.read_text(encoding="utf-8")
            if "wafpass-server:" in text:
                return candidate
    return None


def _link_compose_file(stack_dir: Path, compose_file: Path) -> None:
    """Copy (or symlink) the compose file into the stack directory.

    A symlink is used when the source is writeable (development layout); a copy
    is used when the source is read-only or when symlinks are unsupported.
    """
    dest = stack_dir / "docker-compose.yml"
    try:
        dest.symlink_to(compose_file.resolve())
    except OSError:
        import shutil
        shutil.copy2(compose_file, dest)


def _generate_env_file(stack_dir: Path) -> dict[str, str]:
    """Create a complete .env file with random secrets for the Docker stack."""
    env: dict[str, str] = {
        # ── Database ──────────────────────────────────────────────────────────
        "POSTGRES_USER": "wafpass",
        "POSTGRES_PASSWORD": _random_secret(24),
        "POSTGRES_DB": "wafpass",
        "POSTGRES_PORT": "5432",

        # ── Server / runtime ─────────────────────────────────────────────────
        "WAFPASS_ENV": "local",
        "WAFPASS_JWT_SECRET": _random_secret(48),
        "WAFPASS_JWT_EXPIRE_MINUTES": "60",
        "WAFPASS_JWT_REFRESH_DAYS": "7",
        "WAFPASS_ADMIN_USERNAME": "admin",
        "WAFPASS_ADMIN_PASSWORD": _random_secret(16),
        "WAFPASS_API_KEY": _random_secret(32),
        "WAFPASS_INTERNAL_API_KEY": _random_secret(32),
        "WAFPASS_CONTROLS_DIR": "/app/controls",
        "WAFPASS_BASE_PATH": "/app",

        # ── Keycloak dev defaults ──────────────────────────────────────────────
        "KEYCLOAK_DB": "keycloak",
        "KEYCLOAK_DB_USER": "keycloak",
        "KEYCLOAK_DB_PASSWORD": _random_secret(24),
        "KEYCLOAK_ADMIN_USER": "admin",
        "KEYCLOAK_ADMIN_PASSWORD": _random_secret(16),
        "KEYCLOAK_PORT": "8080",
    }
    return env


def _write_env_file(stack_dir: Path, env: dict[str, str]) -> Path:
    """Write an .env file to *stack_dir*. Existing files are preserved unless
    *stack_dir* is empty or the user explicitly requested overwrite."""
    stack_dir.mkdir(parents=True, exist_ok=True)
    env_path = stack_dir / ".env"

    lines = [
        "# WAF++ PASS local stack — generated by wafpass init",
        "# https://waf2p.dev/wafpass-install/",
        "",
    ]
    for key, value in env.items():
        lines.append(f"{key}={value}")
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return env_path


def _check_docker_available() -> None:
    """Ensure docker and docker compose are available."""
    for cmd in ["docker", "docker compose"]:
        try:
            subprocess.run(cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        except Exception as exc:
            typer.echo(f"ERROR: '{cmd}' is required for dashboard mode but is not available.", err=True)
            raise typer.Exit(code=2) from exc


def _wait_for_server(base_url: str, timeout: int = 120) -> bool:
    """Poll the server /health endpoint until it responds or timeout."""
    if not _HTTPX_AVAILABLE:
        return False

    import httpx
    deadline = time.time() + timeout
    url = f"{base_url.rstrip('/')}/health"
    while time.time() < deadline:
        try:
            resp = httpx.get(url, timeout=5)
            if resp.status_code < 500:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def _open_browser(url: str) -> None:
    """Best-effort attempt to open a URL in the default browser."""
    try:
        if sys.platform == "darwin":
            subprocess.run(["open", url], check=False)
        elif sys.platform == "win32":
            subprocess.run(["start", url], shell=True, check=False)
        else:
            subprocess.run(["xdg-open", url], check=False)
    except Exception:
        pass


@app.command()
def init(
    mode: str | None = typer.Option(
        None,
        "--mode",
        help="Setup mode: cli, dashboard, or ask (interactive).",
    ),
    controls_dir: Path = typer.Option(
        Path("controls"),
        "--controls-dir",
        help="Path to WAF++ YAML control files (used by --mode cli).",
    ),
    stack_dir: Path = typer.Option(
        _INIT_STACK_DIR,
        "--stack-dir",
        help="Directory where the Docker stack and .env will live.",
    ),
    demo_dir: Path = typer.Option(
        _INIT_DEMO_DIR,
        "--demo-dir",
        help="Directory for the CLI demo project (used by --mode cli).",
    ),
    server_url: str = typer.Option(
        "http://localhost:8000/runs",
        "--server-url",
        help="wafpass-server URL to push the demo result to.",
    ),
    api_key: str | None = typer.Option(
        None,
        "--api-key",
        envvar="WAFPASS_API_KEY",
        help="API key used when pushing the demo result to the server.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Accept defaults and do not prompt for input.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show the plan without changing anything.",
    ),
) -> None:
    """Guided first-time setup for WAF++ PASS.

    Defaults to an interactive prompt that asks whether to set up the CLI-only
    quickstart or the full local dashboard. Use --mode to skip the prompt.
    """
    from rich.console import Console as _RichConsole

    rc = _RichConsole()

    # ── Choose mode ───────────────────────────────────────────────────────────
    resolved_mode = mode
    if not resolved_mode:
        if yes:
            resolved_mode = "cli"
        else:
            rc.print("Welcome to WAF++ PASS. Choose your first setup:")
            rc.print("  [1] CLI-only scan (recommended, ~30 seconds)")
            rc.print("  [2] Full local dashboard (Docker required)")
            choice = input("Choice [1]: ").strip() or "1"
            resolved_mode = "dashboard" if choice == "2" else "cli"

    if resolved_mode not in ("cli", "dashboard"):
        typer.echo(f"ERROR: --mode must be 'cli' or 'dashboard', got '{resolved_mode}'", err=True)
        raise typer.Exit(code=2)

    rc.print(f"[bold cyan]wafpass init --mode {resolved_mode}[/bold cyan]")

    # ── Shared prep ───────────────────────────────────────────────────────────
    if dry_run:
        rc.print("[yellow]DRY-RUN:[/yellow] showing plan; no changes will be made.")

    if resolved_mode == "cli":
        # ── CLI-only setup ────────────────────────────────────────────────────
        effective_controls = _ensure_demo_controls(controls_dir)
        if not dry_run:
            demo_dir.mkdir(parents=True, exist_ok=True)
            _write_demo_main_tf(demo_dir)
            rc.print(f"Demo project created: {demo_dir.resolve()}")
            rc.print(f"Controls loaded from: {effective_controls.resolve()}")
            rc.print("")
            rc.print("Run your first scan with:")
            rc.print(f"  [bold]wafpass check {demo_dir} --controls-dir {effective_controls}[/bold]")
        else:
            rc.print(f"Would create demo project in {demo_dir.resolve()}")
            rc.print(f"Would use controls from {effective_controls.resolve()}")

    elif resolved_mode == "dashboard":
        # ── Dashboard setup ─────────────────────────────────────────────────
        _check_docker_available()

        compose_file = _locate_compose_file()

        if not dry_run:
            stack_dir.mkdir(parents=True, exist_ok=True)
            env = _generate_env_file(stack_dir)
            env_path = _write_env_file(stack_dir, env)

            if compose_file:
                _link_compose_file(stack_dir, compose_file)

            rc.print(f"Stack directory: {stack_dir.resolve()}")
            rc.print(f"Environment file: {env_path}")
            if compose_file:
                rc.print(f"Compose file: {stack_dir / 'docker-compose.yml'}")
            rc.print("")
            rc.print(
                "[yellow]Admin password generated — save it now:[/yellow] "
                f"[bold]{env['WAFPASS_ADMIN_PASSWORD']}[/bold]"
            )
            rc.print("")
            if compose_file:
                rc.print("Start the stack with:")
                rc.print(f"  [bold]cd {stack_dir} && docker compose up -d[/bold]")
                rc.print("")
                rc.print("Then seed the dashboard with:")
                rc.print(f"  [bold]wafpass demo --server-url {server_url} --api-key {env['WAFPASS_API_KEY']}[/bold]")
            else:
                rc.print(
                    "[yellow]No docker-compose.yml found in the current directory.[/yellow] "
                    "Download the WAF++ stack from https://github.com/WAF2p/pass, place it here, "
                    "then run:"
                )
                rc.print(f"  [bold]cd <stack-dir> && docker compose --env-file {env_path} up -d[/bold]")
        else:
            rc.print(f"Would create stack directory {stack_dir.resolve()}")
            rc.print("Would generate .env with random secrets")
            if compose_file:
                rc.print(f"Would link compose file {compose_file} into the stack directory")

    rc.print("")
    rc.print("[green]Setup complete.[/green]")


# ── Shared pipeline helper ──────────────────────────────────────────────────────

def _run_check_pipeline(
    paths: list[Path],
    plugin,
    controls,
    iac: str,
    severity: str | None,
    skip_file: Path | None,
) -> tuple[list, "IaCState", list]:
    """Run parse → controls → filter → waivers. Returns (results, merged_state, waivers)."""
    merged_state = IaCState()
    all_regions: list[tuple[str, str]] = []

    for p in paths:
        try:
            state = plugin.parse(p)
        except Exception as exc:
            typer.echo(f"ERROR parsing IaC files in {p}: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        merged_state.resources.extend(state.resources)
        merged_state.providers.extend(state.providers)
        merged_state.variables.extend(state.variables)
        merged_state.modules.extend(state.modules)
        merged_state.config_blocks.extend(state.config_blocks)
        all_regions.extend(plugin.extract_regions(state))

    try:
        results = run_controls(controls, merged_state, engine_name=iac.lower())
    except Exception as exc:
        typer.echo(f"ERROR running controls: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if severity:
        results = filter_by_severity(results, severity)

    active_waivers: list = []
    if skip_file and skip_file.exists():
        try:
            active_waivers = load_waivers(skip_file)
        except ValueError as exc:
            typer.echo(f"ERROR in waiver file: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        if active_waivers:
            apply_waivers(results, active_waivers)

    return results, merged_state, active_waivers


@app.command()
def fix(
    paths: List[Path] = typer.Argument(
        ...,
        help=(
            "Path(s) to IaC files or directories to scan and fix. "
            "The same paths are passed to both the check and the patch step."
        ),
    ),
    iac: str = typer.Option(
        "terraform",
        "--iac",
        help="IaC framework plugin (terraform, bicep, cdk, pulumi). Default: terraform.",
    ),
    controls_dir: Path = typer.Option(
        Path("controls"),
        "--controls-dir",
        help="Path to WAF++ YAML control files.",
    ),
    server_url: str = typer.Option(
        "",
        "--server-url",
        envvar="WAFPASS_SERVER_URL",
        help=(
            "wafpass-server URL to fetch controls from. "
            "Overrides --controls-dir."
        ),
    ),
    pillar: str | None = typer.Option(
        None,
        "--pillar",
        help="Limit fixes to a single pillar (cost, security, reliability, …).",
    ),
    control_ids: str | None = typer.Option(
        None,
        "--controls",
        help="Comma-separated control IDs to fix (e.g. WAF-SEC-010,WAF-COST-020).",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        help="Minimum severity level to fix: low, medium, high, critical.",
    ),
    skip_file: Path | None = typer.Option(
        None,
        "--skip-file",
        help="Path to waiver/skip YAML — waived controls are never auto-fixed.",
    ),
    apply: bool = typer.Option(
        False,
        "--apply",
        is_flag=True,
        help="Write the patches to disk.  Without this flag the command is a dry-run.",
    ),
    backup: bool = typer.Option(
        True,
        "--backup/--no-backup",
        help="Create <file>.bak before modifying (default: true, only with --apply).",
    ),
) -> None:
    """Auto-fix failing WAF++ checks by patching IaC source files.

    By default this command runs in **dry-run / preview mode** and only prints
    a coloured diff of what would change.  Pass ``--apply`` to actually write
    the patches to disk.

    Only assertions whose desired value can be derived unambiguously from the
    control definition are patched:

    \b
      is_true / is_false → attribute = true / false
      equals             → attribute = <expected>
      ≥ / ≤ numeric      → attribute = <threshold>
      in                 → attribute = <first allowed value>
      key_exists (tags)  → inserts "key" = "TODO-fill-in" into tags block
      attribute_exists   → inserts a known-safe default block when available

    Assertions using dynamic expressions (var., local., ${…}) are left
    untouched.  Runtime and negation operators are reported as manual-fix items.

    Writes are atomic: a temp file is created, a framework-specific formatter is
    run when available, and the original file is kept as ``<file>.bak``.  Use
    ``wafpass fix-rollback`` to restore backups.

    After ``--apply`` the checks are re-run and an improvement delta is printed.
    """
    from rich.console import Console
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text

    rc = Console()

    # ── Resolve plugin ────────────────────────────────────────────────────────
    plugin = registry.get(iac.lower())
    if plugin is None:
        typer.echo(f"ERROR: Unknown IaC plugin '{iac}'.", err=True)
        raise typer.Exit(code=2)

    for p in paths:
        if not p.exists():
            typer.echo(f"ERROR: Path does not exist: {p}", err=True)
            raise typer.Exit(code=2)

    # ── Parse control IDs filter ──────────────────────────────────────────────
    ids: list[str] | None = None
    if control_ids:
        ids = [i.strip() for i in control_ids.split(",") if i.strip()]

    # ── Load controls (from filesystem or server) ─────────────────────────────
    effective_controls_dir = controls_dir
    if server_url:
        effective_controls_dir = Path(".wafpass-server-controls")
        typer.echo(f"Fetching controls from: {server_url}", err=True)

    try:
        controls = load_controls(effective_controls_dir, pillar=pillar, ids=ids, server_url=server_url)
    except Exception as exc:
        typer.echo(f"ERROR loading controls: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if not controls:
        _src = f"from server {server_url!r}" if server_url else f"in '{controls_dir}'"
        typer.echo(f"No controls found {_src}.", err=True)
        raise typer.Exit(code=2)

    # ── Resolve waiver file ───────────────────────────────────────────────────
    resolved_skip_file: Path | None = skip_file
    if resolved_skip_file is None:
        for name in ["risk_acceptance.yml", DEFAULT_SKIP_FILE]:
            for p in [Path(name)] + [p / name for p in paths if p.is_dir()]:
                if p.exists():
                    resolved_skip_file = p
                    break
            if resolved_skip_file:
                break

    # ── Run initial check pipeline ────────────────────────────────────────────
    rc.print()
    rc.print(Rule("[bold cyan]WAF++ PASS — Auto-Fix[/bold cyan]", style="cyan"))
    rc.print()

    results, merged_state, _ = _run_check_pipeline(
        paths=paths,
        plugin=plugin,
        controls=controls,
        iac=iac,
        severity=severity,
        skip_file=resolved_skip_file,
    )

    total_fail = sum(1 for cr in results for r in cr.results if r.status == "FAIL")
    if total_fail == 0:
        rc.print("[bold green]✓  Nothing to fix — all checks pass.[/bold green]")
        raise typer.Exit(code=0)

    rc.print(f"[bold]{total_fail}[/bold] failing check(s) found. Deriving patches…")
    rc.print()

    # ── Build locator and fix plan ────────────────────────────────────────────
    from wafpass.fixer import (
        FixPlan,
        PatchKind,
        make_locator,
        apply_fix_plan,
        build_fix_plan,
        compute_fix_delta,
        render_diff,
    )

    locator = make_locator(iac.lower(), list(paths)).build()
    plan = build_fix_plan(
        control_results=results,
        merged_state=merged_state,
        controls=controls,
        locator=locator,
        framework=iac.lower(),
    )

    # ── Compute diffs (always, for preview) ───────────────────────────────────
    dry_run_result = apply_fix_plan(plan, locator, dry_run=True, backup=False)
    diff_map = dry_run_result.diffs

    def _print_warnings(warnings: list[str]) -> None:
        if not warnings:
            return
        rc.print(Rule("[bold yellow]Warnings[/bold yellow]", style="yellow"))
        for w in warnings:
            rc.print(f"[yellow]⚠  {w}[/yellow]")
        rc.print()

    _print_warnings(dry_run_result.warnings)

    # ── Print per-file diff panels ────────────────────────────────────────────
    if diff_map:
        for file_path, (original, patched) in sorted(diff_map.items()):
            file_patches = [p for p in plan.active_patches if p.file_path == file_path]
            diff_lines = render_diff(original, patched, file_path)

            diff_text = Text()
            for dl in diff_lines:
                line = dl.rstrip("\n")
                if line.startswith("+++") or line.startswith("---"):
                    diff_text.append(line + "\n", style="dim")
                elif line.startswith("+"):
                    diff_text.append(line + "\n", style="bold green")
                elif line.startswith("-"):
                    diff_text.append(line + "\n", style="bold red")
                elif line.startswith("@@"):
                    diff_text.append(line + "\n", style="cyan")
                else:
                    diff_text.append(line + "\n", style="dim white")

            patch_label = f"{len(file_patches)} fix(es)"
            rc.print(Panel(
                diff_text,
                title=f"[bold cyan]{file_path}[/bold cyan]  [dim]{patch_label}[/dim]",
                border_style="cyan",
                padding=(0, 1),
            ))
    else:
        rc.print("[dim]No file changes could be derived from the failing checks.[/dim]")

    # ── Patch summary ─────────────────────────────────────────────────────────
    rc.print(Rule("[bold]Fix Plan Summary[/bold]", style="dim"))
    rc.print()

    active_count = len(plan.active_patches)
    dedup_count  = len([p for p in plan.patches if p.already_applied])
    skipped_count = len(plan.skipped)
    files_count  = len(plan.files_affected)

    summary_tbl = Table(show_header=False, box=None, padding=(0, 2))
    summary_tbl.add_column("key",   style="dim",       no_wrap=True)
    summary_tbl.add_column("value", style="bold white", no_wrap=True)
    summary_tbl.add_column("note",  style="dim",       no_wrap=True)

    summary_tbl.add_row(
        "Patches to apply:",
        str(active_count),
        f"across {files_count} file(s)"  if files_count else "no files affected",
    )
    summary_tbl.add_row(
        "Deduplicated:",
        str(dedup_count),
        "same attribute targeted by multiple controls",
    )
    summary_tbl.add_row(
        "Manual remediation:",
        str(skipped_count),
        "see table below",
    )
    rc.print(summary_tbl)
    rc.print()

    if plan.patches:
        # Detail table of what will be patched
        detail_tbl = Table(
            show_header=True,
            header_style="bold white on dark_blue",
            show_lines=True,
            expand=True,
        )
        detail_tbl.add_column("Resource",  style="cyan",  no_wrap=True)
        detail_tbl.add_column("Attribute", style="white", no_wrap=True)
        detail_tbl.add_column("New value", style="green", no_wrap=True)
        detail_tbl.add_column("Control",   style="dim",   no_wrap=True)
        detail_tbl.add_column("File",      style="dim",   no_wrap=True)

        for p in plan.active_patches:
            if p.patch_kind == PatchKind.ADD_TAG_KEY:
                label = p.tag_key
                val   = f'tag "{p.tag_key}" = "TODO-fill-in"'
            elif p.patch_kind == PatchKind.ADD_BLOCK:
                label = p.attribute_path
                val   = "(block from default template)"
            else:
                label = p.attribute_path
                val   = p.hcl_value
            detail_tbl.add_row(
                p.address,
                label,
                val,
                p.control_id,
                p.file_path.name,
            )

        rc.print(detail_tbl)
        rc.print()

    # ── Manual-fix items ──────────────────────────────────────────────────────
    if plan.skipped:
        skip_tbl = Table(
            show_header=True,
            header_style="bold white on dark_orange3",
            show_lines=True,
            expand=True,
            title="[bold yellow]Manual Remediation Required[/bold yellow]",
        )
        skip_tbl.add_column("Check",     style="dim",    no_wrap=True)
        skip_tbl.add_column("Resource",  style="yellow", no_wrap=True)
        skip_tbl.add_column("Attribute", style="white",  no_wrap=True)
        skip_tbl.add_column("Operator",  style="dim",    no_wrap=True)
        skip_tbl.add_column("Reason",    style="dim")

        for s in plan.skipped:
            skip_tbl.add_row(s.check_id, s.address, s.attribute, s.op, s.reason)

        rc.print(skip_tbl)
        rc.print()

    if plan.patches and any(p.patch_kind == PatchKind.ADD_TAG_KEY for p in plan.active_patches):
        rc.print(
            "[bold yellow]⚠  Tag patches use TODO-fill-in as placeholder.[/bold yellow]"
            "  Replace with real values before deploying."
        )
        rc.print()

    # ── Apply ─────────────────────────────────────────────────────────────────
    if not apply:
        rc.print(
            "[dim]Dry-run complete. Pass [bold]--apply[/bold] to write the patches to disk.[/dim]"
        )
        raise typer.Exit(code=0)

    if not diff_map:
        rc.print("[dim]Nothing to write.[/dim]")
        raise typer.Exit(code=0)

    apply_result = apply_fix_plan(plan, locator, dry_run=False, backup=backup)
    _print_warnings(apply_result.warnings)

    files_written = list(diff_map.keys())
    rc.print(Rule("[bold green]Patches Applied[/bold green]", style="green"))
    rc.print()
    for f in sorted(files_written):
        bak_note = f"  [dim](backup: {f.name}.bak)[/dim]" if backup else ""
        rc.print(f"  [green]✓[/green]  {f}{bak_note}")
    rc.print()
    rc.print(
        f"[bold green]Applied {active_count} patch(es) to {len(files_written)} file(s).[/bold green]"
    )
    rc.print()

    # ── Re-run and show improvement delta ────────────────────────────────────
    rc.print(Rule("[bold cyan]Re-checking after fix…[/bold cyan]", style="cyan"))
    rc.print()

    new_results, _, _ = _run_check_pipeline(
        paths=paths,
        plugin=plugin,
        controls=controls,
        iac=iac,
        severity=severity,
        skip_file=resolved_skip_file,
    )

    delta = compute_fix_delta(results, new_results)

    if delta.resolved:
        rc.print(f"[bold green]Resolved ({len(delta.resolved)}):[/bold green]")
        for check_id, addr in delta.resolved:
            rc.print(f"  [green]✓[/green]  {check_id}  [dim]{addr}[/dim]  [dim]FAIL → PASS[/dim]")
        rc.print()

    if delta.still_failing:
        rc.print(f"[bold yellow]Still failing ({len(delta.still_failing)}) — manual remediation required:[/bold yellow]")
        for check_id, addr in delta.still_failing:
            rc.print(f"  [yellow]─[/yellow]  {check_id}  [dim]{addr}[/dim]")
        rc.print()

    if delta.regressions:
        rc.print(f"[bold red]⚠  Regressions introduced ({len(delta.regressions)}) — please review:[/bold red]")
        for check_id, addr in delta.regressions:
            rc.print(f"  [red]✗[/red]  {check_id}  [dim]{addr}[/dim]  [dim]PASS → FAIL[/dim]")
        rc.print()

    total_orig = len(delta.resolved) + len(delta.still_failing)
    rc.print(
        f"[bold]Fixed {len(delta.resolved)}/{total_orig} failing check(s).[/bold]"
    )

    exit_code = 1 if delta.still_failing or delta.regressions else 0
    raise typer.Exit(code=exit_code)


@app.command(name="fix-rollback")
def fix_rollback(
    paths: List[Path] = typer.Argument(
        ...,
        help="Path(s) to IaC files or directories to restore from .bak backups.",
    ),
    iac: str = typer.Option(
        "terraform",
        "--iac",
        help="IaC framework plugin (terraform, bicep, cdk, pulumi). Default: terraform.",
    ),
) -> None:
    """Restore IaC source files from their .bak backups created by `wafpass fix --apply`."""
    from wafpass.fixer import restore_backup

    plugin = registry.get(iac.lower())
    if plugin is None:
        typer.echo(f"ERROR: Unknown IaC plugin '{iac}'.", err=True)
        raise typer.Exit(code=2)

    extensions = set(plugin.file_extensions)

    restored = 0
    missing = 0
    for p in paths:
        if not p.exists():
            typer.echo(f"ERROR: Path not found: {p}", err=True)
            raise typer.Exit(code=2)

        if p.is_file():
            files = [p]
        else:
            files = sorted({
                f
                for ext in extensions
                for f in p.rglob(f"*{ext}")
            })

        for source_file in files:
            if source_file.suffix not in extensions:
                continue
            if restore_backup(source_file):
                restored += 1
                typer.echo(f"Restored {source_file} from backup")
            else:
                missing += 1

    if restored == 0:
        typer.echo("No backups were restored.", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Restored {restored} file(s).")


# ── wafpass ui ─────────────────────────────────────────────────────────────────


@ui_app.command("start")
def ui_start(
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Host address to bind the server to.",
    ),
    port: int = typer.Option(
        8080,
        "--port",
        "-p",
        help="TCP port to listen on (default: 8080).",
    ),
    no_browser: bool = typer.Option(
        False,
        "--no-browser",
        is_flag=True,
        help="Do not open the browser automatically after starting.",
    ),
    reload: bool = typer.Option(
        False,
        "--reload",
        is_flag=True,
        help="Enable uvicorn auto-reload (for development).",
    ),
) -> None:
    """Start the WAF++ PASS web UI server in the background."""
    from rich.console import Console

    rc = Console()

    existing_pid = _pid_file_read()
    if existing_pid is not None:
        rc.print(
            f"[yellow]Server is already running[/yellow] (PID {existing_pid})  "
            f"[dim]http://{host}:{port}[/dim]"
        )
        rc.print("Run [bold]wafpass ui stop[/bold] first to restart.")
        raise typer.Exit(code=1)

    cmd = [
        sys.executable, "-m", "uvicorn",
        "serve.app:app",
        "--host", host,
        "--port", str(port),
    ]
    if reload:
        cmd.append("--reload")

    _UI_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    log_fh = _UI_LOG_FILE.open("w")

    proc = subprocess.Popen(
        cmd,
        cwd=str(_SERVE_ROOT),
        stdout=log_fh,
        stderr=log_fh,
        start_new_session=True,   # detach from the terminal's process group
    )

    _pid_file_write(proc.pid)

    # Brief pause so uvicorn can fail fast on port-in-use errors
    time.sleep(1.2)

    if _pid_file_read() is None:
        rc.print("[red]✗  Server failed to start.[/red]")
        rc.print(f"[dim]Check the log: {_UI_LOG_FILE}[/dim]")
        raise typer.Exit(code=1)

    url = f"http://{host}:{port}"
    rc.print(f"[green]✓  WAF++ PASS UI started[/green]  PID [bold]{proc.pid}[/bold]")
    rc.print(f"   [bold cyan]{url}[/bold cyan]")
    rc.print(f"   [dim]Log: {_UI_LOG_FILE}[/dim]")
    rc.print("   Run [bold]wafpass ui stop[/bold] to shut it down.")

    if not no_browser:
        import webbrowser
        time.sleep(0.5)
        webbrowser.open(url)


@ui_app.command("status")
def ui_status(
    host: str = typer.Option("127.0.0.1", "--host", help="Host the server was bound to."),
    port: int = typer.Option(8080, "--port", "-p", help="Port the server is listening on."),
) -> None:
    """Show whether the WAF++ PASS web UI server is running."""
    from rich.console import Console

    rc = Console()
    pid = _pid_file_read()

    if pid is None:
        rc.print("[red]●[/red]  Server is [bold]not running[/bold].")
        if _UI_PID_FILE.exists():
            rc.print(f"[dim]Stale PID file removed: {_UI_PID_FILE}[/dim]")
            _pid_file_remove()
        raise typer.Exit(code=1)

    url = f"http://{host}:{port}"
    rc.print(f"[green]●[/green]  Server is [bold green]running[/bold green]  PID [bold]{pid}[/bold]")
    rc.print(f"   [bold cyan]{url}[/bold cyan]")
    rc.print(f"   [dim]Log: {_UI_LOG_FILE}[/dim]")


@ui_app.command("stop")
def ui_stop() -> None:
    """Stop the WAF++ PASS web UI server."""
    from rich.console import Console

    rc = Console()
    pid = _pid_file_read()

    if pid is None:
        rc.print("[yellow]Server is not running.[/yellow]")
        _pid_file_remove()
        raise typer.Exit(code=0)

    try:
        if sys.platform == "win32":
            os.kill(pid, signal.SIGTERM)
        else:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass

    # Wait up to 5 seconds for graceful shutdown
    for _ in range(50):
        time.sleep(0.1)
        if _pid_file_read() is None:
            break
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break

    _pid_file_remove()
    rc.print(f"[green]✓  Server stopped[/green]  (was PID {pid})")


# ── wafpass control * ──────────────────────────────────────────────────────────


@control_app.command("generate")
def control_generate(
    non_interactive: Path = typer.Option(
        None,
        "--non-interactive",
        "-n",
        help=(
            "Path to a JSON or YAML spec file.  Skips the interactive wizard — "
            "validates the spec, exports files, and optionally pushes to the server."
        ),
        metavar="SPEC_FILE",
    ),
    controls_dir: Path = typer.Option(
        Path("controls"),
        "--controls-dir",
        help="Root controls directory.  Wizard output goes to <controls-dir>/<pillar>/<id>.yml.",
    ),
    checkov_dir: Path = typer.Option(
        Path("checkov_checks"),
        "--checkov-dir",
        help="Directory for Checkov Python stubs.  Default: ./checkov_checks/",
    ),
    server_url: str = typer.Option(
        "",
        "--server-url",
        help=(
            "wafpass-server base URL for step 7 push "
            "(overrides WAFPASS_SERVER_URL env var)."
        ),
    ),
) -> None:
    """Interactive wizard to author a new WAF++ control (7 steps)."""
    from wafpass.wizard import run_wizard, run_wizard_non_interactive

    effective_url: str | None = server_url or os.environ.get("WAFPASS_SERVER_URL") or None

    if non_interactive:
        result = run_wizard_non_interactive(
            non_interactive,
            controls_dir=controls_dir,
            checkov_dir=checkov_dir,
            server_url=effective_url,
        )
    else:
        result = run_wizard(
            controls_dir=controls_dir,
            checkov_dir=checkov_dir,
            server_url=effective_url,
        )

    if result is None:
        raise typer.Exit(code=1)


@control_app.command("validate")
def control_validate(
    file: Path = typer.Argument(..., help="Path to the YAML control file to validate."),
) -> None:
    """Validate a YAML control file against the WizardControl Pydantic schema."""
    import yaml
    from pydantic import ValidationError
    from rich.console import Console
    from wafpass.control_schema import WizardControl

    rc = Console()

    if not file.exists():
        rc.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(code=2)

    try:
        raw = yaml.safe_load(file.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        rc.print(f"[red]YAML parse error: {exc}[/red]")
        raise typer.Exit(code=1)

    if not isinstance(raw, dict):
        rc.print("[red]File does not contain a YAML mapping.[/red]")
        raise typer.Exit(code=1)

    # Strip header comment keys that might appear if file was hand-edited
    try:
        control = WizardControl.model_validate(raw)
    except ValidationError as exc:
        rc.print(f"[red]Validation failed:[/red] {file}")
        for e in exc.errors():
            loc = " → ".join(str(x) for x in e["loc"])
            rc.print(f"  • [bold]{loc}[/bold]: {e['msg']}")
        raise typer.Exit(code=1)

    rc.print(f"[green]✓ Valid[/green]  {control.id}  ({control.pillar} / {control.severity})")


@control_app.command("list")
def control_list(
    controls_dir: Path = typer.Option(
        Path("controls"),
        "--controls-dir",
        help="Root controls directory to scan.",
    ),
    pillar: str = typer.Option(
        "",
        "--pillar",
        help="Filter by pillar name.",
    ),
) -> None:
    """List all controls found under the controls directory."""
    import yaml
    from rich.console import Console
    from rich.table import Table

    rc = Console()

    if not controls_dir.exists():
        rc.print(f"[red]Controls directory not found: {controls_dir}[/red]")
        raise typer.Exit(code=2)

    yml_files = sorted(controls_dir.rglob("*.yml")) + sorted(controls_dir.rglob("*.yaml"))
    if not yml_files:
        rc.print(f"[yellow]No YAML files found in {controls_dir}[/yellow]")
        return

    table = Table(title=f"WAF++ Controls — {controls_dir}", show_lines=False)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Pillar", style="magenta")
    table.add_column("Severity", style="bold")
    table.add_column("Description")

    count = 0
    for yml_path in yml_files:
        try:
            raw = yaml.safe_load(yml_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(raw, dict):
            continue

        ctrl_id = str(raw.get("id", yml_path.stem))
        ctrl_pillar = str(raw.get("pillar", ""))
        ctrl_severity = str(raw.get("severity", ""))
        ctrl_desc = str(raw.get("description", "")).strip().split("\n")[0][:80]

        if pillar and ctrl_pillar.lower() != pillar.lower():
            continue

        sev_color = {
            "critical": "red",
            "high": "orange3",
            "medium": "yellow",
            "low": "green",
        }.get(ctrl_severity.lower(), "white")
        table.add_row(
            ctrl_id,
            ctrl_pillar,
            f"[{sev_color}]{ctrl_severity}[/{sev_color}]",
            ctrl_desc,
        )
        count += 1

    rc.print(table)
    rc.print(f"[dim]{count} control(s) found[/dim]")


@control_app.command("show")
def control_show(
    control_id: str = typer.Argument(..., help="Control ID to display (e.g. SOV-011)."),
    controls_dir: Path = typer.Option(
        Path("controls"),
        "--controls-dir",
        help="Root controls directory to search.",
    ),
) -> None:
    """Print a control by ID."""
    import yaml
    from rich.console import Console
    from rich.syntax import Syntax

    rc = Console()

    if not controls_dir.exists():
        rc.print(f"[red]Controls directory not found: {controls_dir}[/red]")
        raise typer.Exit(code=2)

    target_id = control_id.strip().upper()
    for yml_path in sorted(controls_dir.rglob("*.yml")) + sorted(controls_dir.rglob("*.yaml")):
        # Fast check on filename stem before loading
        if yml_path.stem.upper() == target_id:
            rc.print(Syntax(yml_path.read_text(encoding="utf-8"), "yaml", theme="monokai"))
            return
        # Slower: check id field inside file
        try:
            raw = yaml.safe_load(yml_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if isinstance(raw, dict) and str(raw.get("id", "")).upper() == target_id:
            rc.print(Syntax(yml_path.read_text(encoding="utf-8"), "yaml", theme="monokai"))
            return

    rc.print(f"[red]Control not found:[/red] {control_id}")
    raise typer.Exit(code=1)


# ── wafpass login / logout / whoami ───────────────────────────────────────────


@app.command("login")
def cmd_login(
    server_url: str = typer.Argument(
        ...,
        help="Base URL of the wafpass-server, e.g. https://wafpass.example.com or http://localhost:8000.",
    ),
    username: str = typer.Option(
        None,
        "--username",
        "-u",
        help="Username (prompted if not given).",
    ),
    no_verify: bool = typer.Option(
        False,
        "--no-verify",
        help="Disable TLS certificate verification (insecure — development only).",
    ),
) -> None:
    """Authenticate with a wafpass-server and store a session token.

    Your password is never written to disk — only the issued JWT token is saved
    to ~/.wafpass/credentials.json (chmod 600).

    After login you can push scan results without --api-key:

    \b
        wafpass check ./infra --output json --push @
        wafpass check ./infra --output json --push http://my-server:8000/api/v1/runs
    """
    from rich.console import Console
    from rich.prompt import Prompt
    import httpx as _httpx
    from wafpass.auth import do_login, _CREDS_FILE

    rc = Console()

    # Normalise URL — strip trailing slash, add scheme if bare hostname given
    _url = server_url.rstrip("/")
    if not _url.startswith(("http://", "https://")):
        _url = f"https://{_url}"

    # Quick reachability check
    try:
        _health_resp = _httpx.get(
            f"{_url}/health",
            timeout=8,
            verify=not no_verify,
            follow_redirects=True,
        )
        if _health_resp.status_code not in (200, 404):
            rc.print(f"[yellow]Warning: /health returned HTTP {_health_resp.status_code} — check URL.[/yellow]")
    except _httpx.ConnectError:
        rc.print(f"[red]Cannot reach {_url} — check the URL and network connectivity.[/red]")
        raise typer.Exit(code=1)
    except Exception:
        pass  # Non-fatal — proceed to login

    if not username:
        username = Prompt.ask("[bold]Username[/bold]")
    password = Prompt.ask("[bold]Password[/bold]", password=True)

    rc.print(f"  Authenticating with [cyan]{_url}[/cyan]…")

    try:
        from wafpass.auth import do_login as _do_login
        creds = _do_login(_url, username, password)
    except _httpx.HTTPStatusError as exc:
        if exc.response.status_code == 401:
            rc.print("[red]Login failed: invalid username or password.[/red]")
        elif exc.response.status_code == 403:
            rc.print("[red]Login failed: account is disabled.[/red]")
        else:
            rc.print(f"[red]Login failed: HTTP {exc.response.status_code}[/red]")
        raise typer.Exit(code=1)
    except Exception as exc:
        rc.print(f"[red]Login failed: {exc}[/red]")
        raise typer.Exit(code=1)

    # Friendly expiry display
    from datetime import datetime, timezone
    try:
        exp = datetime.fromisoformat(creds.expires_at)
        _exp_str = exp.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        _exp_str = creds.expires_at

    rc.print(f"[green]✓  Logged in[/green] as [bold]{creds.username}[/bold] ([cyan]{creds.role}[/cyan])")
    rc.print(f"   Server   : {creds.server_url}")
    rc.print(f"   Token    : valid until {_exp_str}  [dim](auto-refreshed via refresh token)[/dim]")
    rc.print(f"   Stored   : {_CREDS_FILE}")
    rc.print()
    rc.print("  Push scan results using [bold]--push @[/bold] to use this server automatically:")
    rc.print(f"  [dim]wafpass check ./infra --output json --push @[/dim]")


@app.command("logout")
def cmd_logout() -> None:
    """Revoke the stored session and remove local credentials.

    The refresh token is invalidated on the server so the session cannot be
    silently extended after logout.
    """
    from rich.console import Console
    from wafpass.auth import load, do_logout, clear

    rc = Console()
    creds = load()
    if creds is None:
        rc.print("[yellow]Not logged in — nothing to do.[/yellow]")
        return

    rc.print(f"  Revoking session for [bold]{creds.username}[/bold] on {creds.server_url}…")
    do_logout(creds)
    clear()
    rc.print("[green]✓  Logged out[/green] — local credentials removed.")


@app.command("whoami")
def cmd_whoami() -> None:
    """Show the currently stored login session."""
    from rich.console import Console
    from rich.table import Table
    from datetime import datetime, timezone
    from wafpass.auth import get_valid_credentials, load

    rc = Console()
    raw = load()
    if raw is None:
        rc.print("[yellow]Not logged in.[/yellow]  Run [bold]wafpass login <server-url>[/bold] first.")
        raise typer.Exit(code=1)

    creds = get_valid_credentials()

    table = Table.grid(padding=(0, 2))
    table.add_column(style="dim", justify="right")
    table.add_column()

    table.add_row("Server",   raw.server_url)
    table.add_row("Username", f"[bold]{raw.username}[/bold]")
    table.add_row("Role",     f"[cyan]{raw.role}[/cyan]")

    try:
        exp = datetime.fromisoformat(raw.expires_at)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        delta = exp - now
        if delta.total_seconds() < 0:
            _exp_label = f"[red]expired {abs(int(delta.total_seconds() // 60))} min ago[/red]"
        elif delta.total_seconds() < 300:
            _exp_label = f"[yellow]expires in {int(delta.total_seconds())}s (refreshing…)[/yellow]"
        else:
            _exp_label = f"[green]valid for {int(delta.total_seconds() // 60)} min[/green]  ({exp.strftime('%Y-%m-%d %H:%M UTC')})"
    except Exception:
        _exp_label = raw.expires_at

    table.add_row("Token",    _exp_label)

    if creds is None:
        table.add_row("Session", "[red]Refresh failed — run 'wafpass login' again.[/red]")
    elif creds.access_token != raw.access_token:
        table.add_row("Session", "[green]Auto-refreshed ✓[/green]")

    rc.print(table)
    rc.print()
    rc.print("  Use [bold]--push @[/bold] to push scan results to this server.")


# ── wafpass evidence ───────────────────────────────────────────────────────────

evidence_app = typer.Typer(
    name="evidence",
    help="Manage locked, immutable evidence packages on a wafpass-server.",
    add_completion=False,
)
app.add_typer(evidence_app, name="evidence")


def _require_creds():
    """Return valid credentials or exit with a helpful message."""
    from wafpass.auth import get_valid_credentials
    from rich.console import Console
    creds = get_valid_credentials()
    if creds is None:
        Console().print(
            "[red]Not logged in.[/red]  Run [bold]wafpass login <server-url>[/bold] first."
        )
        raise typer.Exit(code=1)
    return creds


@evidence_app.command("lock")
def evidence_lock(
    run_id: str = typer.Option(
        None,
        "--run-id",
        help="UUID of the run to lock as evidence (required).",
    ),
    title: str = typer.Option(
        "",
        "--title",
        help="Evidence package title (auto-generated from run if omitted).",
    ),
    note: str = typer.Option(
        "",
        "--note",
        help="Auditor-facing note to embed in the evidence package.",
    ),
    project: str = typer.Option(
        "",
        "--project",
        help="Project name tag.",
    ),
    prepared_by: str = typer.Option(
        "",
        "--prepared-by",
        help="Name of the person preparing this evidence package.",
    ),
    organization: str = typer.Option(
        "",
        "--organization",
        help="Organization name for the evidence package.",
    ),
    audit_period: str = typer.Option(
        "",
        "--audit-period",
        help="Audit period description, e.g. 'Q1 2026'.",
    ),
    frameworks: str = typer.Option(
        "",
        "--frameworks",
        help="Comma-separated compliance frameworks, e.g. 'ISO 27001,SOC 2'.",
    ),
) -> None:
    """Lock a server-side run as an immutable evidence package.

    Requires an active login session (run 'wafpass login <url>' first).

    \b
    Example:
        wafpass evidence lock --run-id <uuid> --title "Q1 2026 Audit"
    """
    import httpx as _httpx
    from rich.console import Console

    rc = Console()

    if not run_id:
        rc.print("[red]--run-id is required.[/red]")
        raise typer.Exit(code=2)

    creds = _require_creds()

    _frameworks = [f.strip() for f in frameworks.split(",") if f.strip()] if frameworks else []

    payload: dict = {
        "run_id": run_id,
        "snapshot": {},  # server will load the run's stored data
    }
    if title:
        payload["title"] = title
    if note:
        payload["note"] = note
    if project:
        payload["project"] = project
    if prepared_by:
        payload["prepared_by"] = prepared_by
    if organization:
        payload["organization"] = organization
    if audit_period:
        payload["audit_period"] = audit_period
    if _frameworks:
        payload["frameworks"] = _frameworks

    url = f"{creds.server_url}/api/v1/evidence"
    headers = {"Content-Type": "application/json", "Authorization": creds.bearer()}

    rc.print(f"  Locking run [cyan]{run_id}[/cyan] as evidence…")

    try:
        resp = _httpx.post(url, json=payload, headers=headers, timeout=30)
        if resp.status_code == 401:
            creds = _require_creds()
            headers["Authorization"] = creds.bearer()
            resp = _httpx.post(url, json=payload, headers=headers, timeout=30)
        resp.raise_for_status()
    except _httpx.HTTPStatusError as exc:
        _body = ""
        try:
            _body = exc.response.json().get("detail", "")
        except Exception:
            pass
        rc.print(f"[red]Lock failed: HTTP {exc.response.status_code}[/red]  {_body}")
        raise typer.Exit(code=1)
    except Exception as exc:
        rc.print(f"[red]Lock failed: {exc}[/red]")
        raise typer.Exit(code=1)

    ev = resp.json()
    public_url = f"{creds.server_url}/api/v1/evidence/p/{ev['public_token']}"

    rc.print(f"[green]✓  Evidence locked[/green]")
    rc.print(f"   ID           : [bold]{ev['id']}[/bold]")
    rc.print(f"   Title        : {ev.get('title', '—')}")
    rc.print(f"   SHA-256      : [dim]{ev.get('hash_digest', '—')}[/dim]")
    rc.print(f"   Public URL   : [cyan]{public_url}[/cyan]")
    rc.print(f"   Created      : {ev.get('created_at', '—')}")
    rc.print()
    rc.print("  Share the public URL with auditors — no login required.")
    rc.print(f"  [dim]wafpass evidence show {ev['id']}[/dim]  for full details.")


@evidence_app.command("list")
def evidence_list(
    project: str = typer.Option(
        "",
        "--project",
        help="Filter by project name.",
    ),
    limit: int = typer.Option(
        20,
        "--limit",
        "-n",
        help="Maximum number of packages to show (default: 20).",
    ),
) -> None:
    """List locked evidence packages on the connected server."""
    import httpx as _httpx
    from rich.console import Console
    from rich.table import Table

    rc = Console()
    creds = _require_creds()

    params: dict = {}
    if project:
        params["project"] = project

    url = f"{creds.server_url}/api/v1/evidence"
    headers = {"Authorization": creds.bearer()}

    try:
        resp = _httpx.get(url, params=params, headers=headers, timeout=15)
        if resp.status_code == 401:
            creds = _require_creds()
            headers["Authorization"] = creds.bearer()
            resp = _httpx.get(url, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
    except _httpx.HTTPStatusError as exc:
        rc.print(f"[red]Request failed: HTTP {exc.response.status_code}[/red]")
        raise typer.Exit(code=1)
    except Exception as exc:
        rc.print(f"[red]Request failed: {exc}[/red]")
        raise typer.Exit(code=1)

    packages = resp.json()
    if not packages:
        rc.print("[yellow]No evidence packages found.[/yellow]")
        return

    packages = packages[:limit]

    tbl = Table(
        title=f"Evidence Packages — {creds.server_url}",
        show_lines=False,
        header_style="bold white on dark_blue",
    )
    tbl.add_column("ID", style="dim", no_wrap=True, max_width=12)
    tbl.add_column("Title", style="bold white")
    tbl.add_column("Project", style="cyan")
    tbl.add_column("Run ID", style="dim", max_width=12)
    tbl.add_column("Created", style="dim", no_wrap=True)
    tbl.add_column("SHA-256", style="dim", max_width=16)

    for ev in packages:
        _id = str(ev.get("id", ""))[:8] + "…"
        _run = str(ev.get("run_id", ""))[:8] + "…"
        _hash = str(ev.get("hash_digest", ""))[:14] + "…"
        _created = str(ev.get("created_at", ""))[:16]
        tbl.add_row(
            _id,
            ev.get("title") or "—",
            ev.get("project") or "—",
            _run,
            _created,
            _hash,
        )

    rc.print(tbl)
    rc.print(f"[dim]{len(packages)} package(s) shown[/dim]")


@evidence_app.command("show")
def evidence_show(
    evidence_id: str = typer.Argument(
        ...,
        help="Evidence package UUID to display.",
    ),
    show_hash: bool = typer.Option(
        False,
        "--hash",
        is_flag=True,
        help="Print only the SHA-256 hash digest (useful for scripting / verification).",
    ),
) -> None:
    """Show details of a locked evidence package."""
    import httpx as _httpx
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    rc = Console()
    creds = _require_creds()

    url = f"{creds.server_url}/api/v1/evidence/{evidence_id}"
    headers = {"Authorization": creds.bearer()}

    try:
        resp = _httpx.get(url, headers=headers, timeout=15)
        if resp.status_code == 401:
            creds = _require_creds()
            headers["Authorization"] = creds.bearer()
            resp = _httpx.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
    except _httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            rc.print(f"[red]Evidence package not found:[/red] {evidence_id}")
        else:
            rc.print(f"[red]Request failed: HTTP {exc.response.status_code}[/red]")
        raise typer.Exit(code=1)
    except Exception as exc:
        rc.print(f"[red]Request failed: {exc}[/red]")
        raise typer.Exit(code=1)

    ev = resp.json()

    if show_hash:
        rc.print(ev.get("hash_digest", ""))
        return

    public_url = f"{creds.server_url}/api/v1/evidence/p/{ev['public_token']}"

    tbl = Table.grid(padding=(0, 2))
    tbl.add_column(style="dim", justify="right")
    tbl.add_column()

    tbl.add_row("Evidence ID",  f"[bold]{ev.get('id', '—')}[/bold]")
    tbl.add_row("Title",        ev.get("title") or "—")
    tbl.add_row("Note",         ev.get("note") or "—")
    tbl.add_row("Project",      ev.get("project") or "—")
    tbl.add_row("Prepared by",  ev.get("prepared_by") or "—")
    tbl.add_row("Organization", ev.get("organization") or "—")
    tbl.add_row("Audit period", ev.get("audit_period") or "—")
    _fw = ", ".join(ev.get("frameworks") or []) or "—"
    tbl.add_row("Frameworks",   _fw)
    tbl.add_row("Run ID",       ev.get("run_id") or "—")
    tbl.add_row("Locked by",    str(ev.get("locked_by") or "—"))
    tbl.add_row("Created",      str(ev.get("created_at") or "—"))
    tbl.add_row("SHA-256",      f"[dim]{ev.get('hash_digest', '—')}[/dim]")
    tbl.add_row("Public URL",   f"[cyan]{public_url}[/cyan]")

    rc.print(Panel(
        tbl,
        title=f"[bold white]Evidence Package[/bold white]  [dim]{str(ev.get('id', ''))[:8]}…[/dim]",
        border_style="cyan",
        padding=(1, 2),
    ))
    rc.print()
    rc.print("  [dim]Download report:[/dim]  "
             f"[dim]{creds.server_url}/api/v1/evidence/{evidence_id}/report.html[/dim]")
    rc.print("  [dim]Share with auditor:[/dim]  "
             f"[cyan]{public_url}[/cyan]")
