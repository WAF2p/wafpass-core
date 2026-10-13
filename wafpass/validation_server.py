"""Server-side validation service for WAF++ PASS.

This module implements a minimal, in-memory validation authority that can be
mounted into the local `serve` FastAPI app (or into the real `wafpass-server`
later). It provides the `/api/v1/validations` contract the CLI expects.

It is intentionally self-contained and uses an in-memory store so it can be
used for local end-to-end testing without a database.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from wafpass.attestation import (
    compute_run_hash,
    verify_local_attestation,
)
from wafpass.schema import (
    LocalAttestationSchema,
    ServerValidationSchema,
    ValidationEnvelopeSchema,
    WafpassResultSchema,
)


# ── In-memory store ──────────────────────────────────────────────────────────

_validations: dict[str, dict[str, Any]] = {}
_revocations: set[str] = set()


# ── Certificate / key material ─────────────────────────────────────────────────

_root_key: Ed25519PrivateKey | None = None
_root_cert_pem: str | None = None
_server_key: Ed25519PrivateKey | None = None
_server_cert_pem: str | None = None


def _init_keys() -> None:
    """Generate or load the root and server signing keys on first use.

    In production this must be replaced with KMS-backed keys.
    """
    global _root_key, _root_cert_pem, _server_key, _server_cert_pem
    if _root_key is not None:
        return

    key_dir = Path(
        os.environ.get("WAFPASS_SERVER_KEYS_DIR", str(Path.home() / ".wafpass" / "server-keys"))
    )
    key_dir.mkdir(parents=True, exist_ok=True)
    root_key_path = key_dir / "root.key"
    root_cert_path = key_dir / "root.crt"
    server_key_path = key_dir / "server.key"
    server_cert_path = key_dir / "server.crt"

    if root_key_path.exists() and server_key_path.exists():
        _root_key = _load_private_key(root_key_path)
        _root_cert_pem = root_cert_path.read_text(encoding="ascii")
        _server_key = _load_private_key(server_key_path)
        _server_cert_pem = server_cert_path.read_text(encoding="ascii")
        return

    # Generate a fresh root/server key pair.
    _root_key = Ed25519PrivateKey.generate()
    _server_key = Ed25519PrivateKey.generate()

    root_subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "WAF++ Root CA")])
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_subject)
        .public_key(_root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(_root_key, None)
    )
    _root_cert_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

    server_subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "WAF++ Validation Server")])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(root_cert.subject)
        .public_key(_server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(_root_key, None)
    )
    _server_cert_pem = server_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

    _persist_private_key(_root_key, root_key_path)
    _persist_private_key(_server_key, server_key_path)
    root_cert_path.write_text(_root_cert_pem, encoding="ascii")
    server_cert_path.write_text(_server_cert_pem, encoding="ascii")


def _persist_private_key(key: Ed25519PrivateKey, path: Path) -> None:
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    try:
        os.chmod(path, 0o600)
    except (OSError, NotImplementedError):
        pass


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    data = path.read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("server keys must be Ed25519 private keys")
    return key


# ── Pydantic request/response models ───────────────────────────────────────────


class ValidationSubmitRequest(BaseModel):
    result: dict[str, Any] = Field(description="The WafpassResultSchema JSON object.")
    attestation: dict[str, Any] = Field(description="The LocalAttestationSchema JSON object.")


class ValidationRecordResponse(BaseModel):
    validation_id: str
    canonical_hash: str
    project: str
    branch: str
    git_sha: str
    validated_at: str
    server_public_key: str
    server_signature: str
    certificate_chain: list[str]
    badge_url: str
    verification_url: str
    status: str


class VerificationResponse(BaseModel):
    validation_id: str
    canonical_hash: str
    validated_at: str
    server_public_key: str
    server_signature: str
    certificate_chain: list[str]
    status: str


# ── Router ─────────────────────────────────────────────────────────────────────

router = APIRouter(prefix="/api/v1/validations", tags=["validations"])


def _server_signature_message(canonical_hash: str, validation_id: str, validated_at: str) -> bytes:
    message = f"wafpass-server-validation-v1|{canonical_hash}|{validation_id}|{validated_at}"
    return message.encode("utf-8")


def _countersign(canonical_hash: str, validation_id: str, validated_at: str) -> bytes:
    _init_keys()
    assert _server_key is not None
    message = _server_signature_message(canonical_hash, validation_id, validated_at)
    return _server_key.sign(message)


def _server_public_key_pem() -> str:
    _init_keys()
    assert _server_key is not None
    return _server_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _certificate_chain() -> list[str]:
    _init_keys()
    assert _server_cert_pem is not None and _root_cert_pem is not None
    return [_server_cert_pem, _root_cert_pem]


def _build_server_validation(
    canonical_hash: str,
    validation_id: str,
    base_url: str,
) -> ServerValidationSchema:
    validated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    signature = _countersign(canonical_hash, validation_id, validated_at)
    return ServerValidationSchema(
        validation_id=validation_id,
        validated_at=validated_at,
        server_public_key=_server_public_key_pem(),
        server_signature=base64.b64encode(signature).decode("ascii"),
        certificate_chain=_certificate_chain(),
        badge_url=f"{base_url}/api/v1/validations/{validation_id}/badge.svg",
        verification_url=f"{base_url}/api/v1/validations/{validation_id}/verify",
    )


class _EnvelopeResponse(BaseModel):
    data: ServerValidationSchema
    meta: dict[str, Any] = Field(default_factory=dict)


@router.post("", response_model=_EnvelopeResponse, status_code=201)
async def submit_validation(
    req: ValidationSubmitRequest,
    request: Request,
) -> _EnvelopeResponse:
    """Submit a WAF++ run for official server countersignature.

    The server recomputes the canonical hash, verifies the local attestation,
    and returns a signed ServerValidationSchema wrapped in the standard
    WAF++ API envelope.
    """
    try:
        result = WafpassResultSchema.model_validate(req.result)
        attestation = LocalAttestationSchema.model_validate(req.attestation)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid request payload: {exc}") from exc

    # Recompute canonical hash and verify local signature.
    canonical_hash = compute_run_hash(result)
    if canonical_hash != attestation.canonical_hash:
        raise HTTPException(
            status_code=400,
            detail="Canonical hash mismatch: the submitted result was modified or incorrectly serialized.",
        )

    ok, reason = verify_local_attestation(result, attestation)
    if not ok:
        raise HTTPException(status_code=400, detail=f"Local attestation verification failed: {reason}")

    validation_id = str(uuid.uuid4())
    base_url = str(request.base_url).rstrip("/")
    server_validation = _build_server_validation(canonical_hash, validation_id, base_url)

    # Persist the immutable validation record.
    _validations[validation_id] = {
        "validation_id": validation_id,
        "canonical_hash": canonical_hash,
        "project": result.project,
        "branch": result.branch,
        "git_sha": result.git_sha,
        "validated_at": server_validation.validated_at,
        "server_public_key": server_validation.server_public_key,
        "server_signature": server_validation.server_signature,
        "certificate_chain": server_validation.certificate_chain,
        "badge_url": server_validation.badge_url,
        "verification_url": server_validation.verification_url,
        "status": "official",
        "result_json": result.model_dump_json(),
    }

    return _EnvelopeResponse(data=server_validation)


@router.get("/{validation_id}/verify", response_model=VerificationResponse)
async def verify_validation(validation_id: str) -> VerificationResponse:
    """Public endpoint to retrieve the signed validation record."""
    record = _validations.get(validation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    if validation_id in _revocations:
        record = dict(record)
        record["status"] = "revoked"
    return VerificationResponse(**{k: record[k] for k in VerificationResponse.model_fields.keys()})


@router.get("/{validation_id}", response_model=ValidationRecordResponse)
async def get_validation(validation_id: str) -> ValidationRecordResponse:
    """Return the full validation record (requires auth in production)."""
    record = _validations.get(validation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    if validation_id in _revocations:
        record = dict(record)
        record["status"] = "revoked"
    return ValidationRecordResponse(**{k: record[k] for k in ValidationRecordResponse.model_fields.keys()})


def _validation_envelope_from_record(record: dict[str, Any]) -> ValidationEnvelopeSchema:
    """Reconstruct a ValidationEnvelopeSchema from an in-memory record."""
    status = "revoked" if record["validation_id"] in _revocations else record.get("status", "official")
    return ValidationEnvelopeSchema(
        schema_version="1.0",
        run_hash=record["canonical_hash"],
        status=status,
        result=json.loads(record["result_json"]),
        local_attestation=LocalAttestationSchema(
            public_key="",
            signature="",
            canonical_hash=record["canonical_hash"],
            signed_at="",
        ),
        server_validation=ServerValidationSchema(
            **{k: record.get(k) for k in ServerValidationSchema.model_fields.keys()}
        ),
    )


@router.get("/{validation_id}/badge.svg")
async def get_badge_svg(validation_id: str) -> Response:
    """Return an embeddable SVG badge for the validation."""
    record = _validations.get(validation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    from wafpass.badge import generate_badge_svg

    envelope = _validation_envelope_from_record(record)
    svg = generate_badge_svg(envelope)
    return Response(content=svg.encode("utf-8"), media_type="image/svg+xml")


@router.get("/{validation_id}/badge.json")
async def get_badge_json(validation_id: str) -> dict[str, Any]:
    """Return the portable badge JSON for the validation."""
    record = _validations.get(validation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    from wafpass.validation_cli import _build_badge_json

    envelope = _validation_envelope_from_record(record)
    return _build_badge_json(envelope)


@router.post("/{validation_id}/revoke")
async def revoke_validation(validation_id: str) -> dict[str, str]:
    """Revoke a validation (admin-only in production)."""
    if validation_id not in _validations:
        raise HTTPException(status_code=404, detail="Validation not found")
    _revocations.add(validation_id)
    return {"status": "revoked", "validation_id": validation_id}


@router.get("/revocations")
async def list_revocations() -> dict[str, list[str]]:
    """Return the list of revoked validation IDs."""
    return {"revoked_ids": sorted(_revocations)}

