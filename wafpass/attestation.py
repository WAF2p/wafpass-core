"""Cryptographic attestation and validation for WAF++ PASS runs.

This module provides the primitives needed to prove that a specific WAF++ run
was produced and/or validated by a known entity:

  * Ed25519 key generation and loading
  * Deterministic canonical serialization of a run result
  * SHA-256 run hash
  * Local (organization) signature over the run hash
  * Server countersignature forming a certificate chain
  * Offline fallback envelope generation and later upgrade
  * Local verification of signatures and certificate chains

All serialization is deterministic so that the CLI, the central server, and any
third-party verifier can recompute the exact same run hash from the same result.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

if TYPE_CHECKING:
    from wafpass.schema import (
        LocalAttestationSchema,
        ServerValidationSchema,
        ValidationEnvelopeSchema,
        WafpassResultSchema,
    )


# ── Key management ────────────────────────────────────────────────────────────


def generate_signing_key(path: Path) -> None:
    """Generate a new Ed25519 signing key and persist it to *path*.

    The private key is written in PKCS#8 PEM format with permissions set to
    600 (owner read/write only) on Unix-like systems.
    """
    path = Path(path)
    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem)
    try:
        os.chmod(path, 0o600)
    except (OSError, NotImplementedError):
        pass


def load_signing_key(path: Path) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from *path* (PEM or raw 32-byte private key)."""
    path = Path(path)
    data = path.read_bytes()
    if data.startswith(b"-----BEGIN PRIVATE KEY-----"):
        return serialization.load_pem_private_key(data, password=None)  # type: ignore[return-value]
    if data.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"):
        raise ValueError("encrypted private keys are not supported; provide an unencrypted PEM file")
    # Fallback: treat as raw private key bytes (32 bytes expected for Ed25519)
    raw = base64.b64decode(data) if len(data) != 32 else data
    return Ed25519PrivateKey.from_private_bytes(raw)


def _public_key_pem(public_key: Ed25519PublicKey) -> str:
    """Return the PEM-encoded public key."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _load_public_key(pem_or_b64: str) -> Ed25519PublicKey:
    """Load an Ed25519 public key from PEM or base64-encoded raw bytes."""
    data = pem_or_b64.encode("ascii") if isinstance(pem_or_b64, str) else pem_or_b64
    if data.startswith(b"-----BEGIN PUBLIC KEY-----"):
        return serialization.load_pem_public_key(data)  # type: ignore[return-value]
    # Try base64-decoding raw SubjectPublicKeyInfo bytes
    try:
        raw = base64.b64decode(data)
        return serialization.load_pem_public_key(
            b"-----BEGIN PUBLIC KEY-----\n"
            + base64.b64encode(raw)
            + b"\n-----END PUBLIC KEY-----\n"
        )  # type: ignore[return-value]
    except Exception as exc:
        raise ValueError(f"could not load Ed25519 public key: {exc}") from exc


# ── Canonical serialization and run hash ──────────────────────────────────────


def _sort_dicts(value: object) -> object:
    """Recursively sort dictionary keys for deterministic serialization."""
    if isinstance(value, dict):
        return {k: _sort_dicts(value[k]) for k in sorted(value.keys())}
    if isinstance(value, list):
        return [_sort_dicts(item) for item in value]
    return value


def canonicalize_run(result: WafpassResultSchema | dict) -> bytes:
    """Return a deterministic UTF-8 JSON serialization of *result*.

    The serialization excludes any attestation/certificate metadata so that the
    canonical hash is stable regardless of when or how the run is signed.
    """
    if isinstance(result, dict):
        data = dict(result)
    else:
        data = result.model_dump()

    # Strip validation-related fields that must never affect the run hash.
    data.pop("attestation", None)
    data.pop("certificate", None)
    data.pop("validation", None)

    sorted_data = _sort_dicts(data)
    return json.dumps(
        sorted_data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def compute_run_hash(result: WafpassResultSchema | dict) -> str:
    """Return the SHA-256 hex digest of the canonical run serialization."""
    return hashlib.sha256(canonicalize_run(result)).hexdigest()


# ── Local attestation (organization signature) ────────────────────────────────


def sign_run(
    result: WafpassResultSchema | dict,
    private_key: Ed25519PrivateKey | Path,
    signer_kind: str = "organization",
) -> LocalAttestationSchema:
    """Create a local attestation for *result* using the given private key.

    *private_key* may be an Ed25519PrivateKey or a Path to a PEM key file.
    """
    from wafpass.schema import LocalAttestationSchema

    if isinstance(private_key, Path):
        private_key = load_signing_key(private_key)

    canonical_hash = compute_run_hash(result)
    signature_bytes = private_key.sign(canonical_hash.encode("ascii"))

    return LocalAttestationSchema(
        public_key=_public_key_pem(private_key.public_key()),
        signature=base64.b64encode(signature_bytes).decode("ascii"),
        algorithm="ed25519",
        canonical_hash=canonical_hash,
        signed_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        signer_kind=signer_kind,
    )


def verify_local_attestation(
    result: WafpassResultSchema | dict,
    attestation: LocalAttestationSchema,
) -> tuple[bool, str]:
    """Verify that *attestation* correctly signs *result*.

    Returns (is_valid, reason). Does not raise on invalid input.
    """
    try:
        expected_hash = compute_run_hash(result)
        if attestation.canonical_hash != expected_hash:
            return False, f"canonical hash mismatch: expected {expected_hash}, got {attestation.canonical_hash}"

        public_key = _load_public_key(attestation.public_key)
        signature = base64.b64decode(attestation.signature)
        public_key.verify(signature, expected_hash.encode("ascii"))
        return True, "local attestation valid"
    except InvalidSignature:
        return False, "local signature invalid"
    except Exception as exc:
        return False, f"local attestation verification failed: {exc}"


# ── Server validation helpers ───────────────────────────────────────────────────


def _server_signature_message(canonical_hash: str, validation_id: str, validated_at: str) -> bytes:
    """Build the exact bytestring that the server signs for a validation record."""
    message = f"wafpass-server-validation-v1|{canonical_hash}|{validation_id}|{validated_at}"
    return message.encode("utf-8")


def build_server_validation(
    canonical_hash: str,
    server_private_key: Ed25519PrivateKey | Path,
    server_certificate_pem: str,
    root_certificate_pem: str,
    badge_url: str = "",
    verification_url: str = "",
    validation_id: str | None = None,
    validated_at: str | None = None,
    expires_at: str | None = None,
) -> ServerValidationSchema:
    """Create an official server countersignature for a validated run hash.

    This is intended for use by the central WAF++ server or in tests.
    """
    from wafpass.schema import ServerValidationSchema

    if isinstance(server_private_key, Path):
        server_private_key = load_signing_key(server_private_key)

    validation_id = validation_id or str(uuid.uuid4())
    validated_at = validated_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    message = _server_signature_message(canonical_hash, validation_id, validated_at)
    signature_bytes = server_private_key.sign(message)

    return ServerValidationSchema(
        validation_id=validation_id,
        validated_at=validated_at,
        server_public_key=_public_key_pem(server_private_key.public_key()),
        server_signature=base64.b64encode(signature_bytes).decode("ascii"),
        certificate_chain=[server_certificate_pem, root_certificate_pem],
        badge_url=badge_url,
        verification_url=verification_url,
        expires_at=expires_at,
    )


def verify_server_signature(
    canonical_hash: str,
    server_validation: ServerValidationSchema,
    server_public_key: Ed25519PublicKey | None = None,
) -> tuple[bool, str]:
    """Verify the server countersignature in *server_validation*.

    If *server_public_key* is not provided, it is loaded from
    *server_validation.server_public_key*.
    """
    try:
        if server_public_key is None:
            server_public_key = _load_public_key(server_validation.server_public_key)
        message = _server_signature_message(
            canonical_hash,
            server_validation.validation_id,
            server_validation.validated_at,
        )
        signature = base64.b64decode(server_validation.server_signature)
        server_public_key.verify(signature, message)
        return True, "server signature valid"
    except InvalidSignature:
        return False, "server signature invalid"
    except Exception as exc:
        return False, f"server signature verification failed: {exc}"


# ── Certificate chain verification ────────────────────────────────────────────


def _load_x509_certificate(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode("ascii"))


def _extract_ed25519_public_key_from_certificate(pem: str) -> Ed25519PublicKey:
    cert = _load_x509_certificate(pem)
    public_key = cert.public_key()
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("certificate does not contain an Ed25519 public key")
    return public_key


def verify_certificate_chain(
    certificate_chain: list[str],
    root_public_key_or_cert: str,
) -> tuple[bool, str]:
    """Verify that *certificate_chain* is signed by the trusted root.

    *root_public_key_or_cert* may be a PEM-encoded root certificate or a PEM/base64
    Ed25519 public key. The chain is expected as [server intermediate, root cert].
    """
    try:
        if not certificate_chain:
            return False, "empty certificate chain"

        # Load the root public key from the provided trust anchor.
        if root_public_key_or_cert.strip().startswith("-----BEGIN CERTIFICATE-----"):
            root_public_key = _extract_ed25519_public_key_from_certificate(root_public_key_or_cert)
        else:
            root_public_key = _load_public_key(root_public_key_or_cert)

        # The last entry in the chain must be signed by the root public key.
        root_cert_pem = certificate_chain[-1]
        root_cert = _load_x509_certificate(root_cert_pem)
        root_public_key.verify(
            root_cert.signature,
            root_cert.tbs_certificate_bytes,
        )

        # If there is an intermediate certificate, it must be signed by the root cert.
        if len(certificate_chain) >= 2:
            server_cert_pem = certificate_chain[0]
            server_cert = _load_x509_certificate(server_cert_pem)
            root_cert.public_key().verify(
                server_cert.signature,
                server_cert.tbs_certificate_bytes,
            )

        return True, "certificate chain valid"
    except InvalidSignature:
        return False, "certificate chain signature invalid"
    except Exception as exc:
        return False, f"certificate chain verification failed: {exc}"


# ── Envelope helpers ─────────────────────────────────────────────────────────


def create_offline_envelope(
    result: WafpassResultSchema | dict,
    private_key: Ed25519PrivateKey | Path,
    signer_kind: str = "organization",
) -> ValidationEnvelopeSchema:
    """Create an offline (self-signed) validation envelope when internet is unavailable."""
    from wafpass.schema import ValidationEnvelopeSchema

    attestation = sign_run(result, private_key, signer_kind=signer_kind)
    return ValidationEnvelopeSchema(
        schema_version="1.0",
        run_hash=attestation.canonical_hash,
        status="offline",
        result=result if isinstance(result, dict) else result.model_dump(),
        local_attestation=attestation,
        server_validation=None,
        pending_upgrade=True,
    )


def create_official_envelope(
    result: WafpassResultSchema | dict,
    local_attestation: LocalAttestationSchema,
    server_validation: ServerValidationSchema,
) -> ValidationEnvelopeSchema:
    """Assemble the final official validation envelope after server countersign."""
    from wafpass.schema import ValidationEnvelopeSchema

    return ValidationEnvelopeSchema(
        schema_version="1.0",
        run_hash=local_attestation.canonical_hash,
        status="official",
        result=result if isinstance(result, dict) else result.model_dump(),
        local_attestation=local_attestation,
        server_validation=server_validation,
        pending_upgrade=False,
    )


def upgrade_offline_envelope(
    envelope: ValidationEnvelopeSchema,
    server_validation: ServerValidationSchema,
) -> ValidationEnvelopeSchema:
    """Upgrade an offline envelope to official using a server countersignature."""
    from wafpass.schema import ValidationEnvelopeSchema

    return ValidationEnvelopeSchema(
        schema_version=envelope.schema_version,
        run_hash=envelope.run_hash,
        status="official",
        result=envelope.result,
        local_attestation=envelope.local_attestation,
        server_validation=server_validation,
        pending_upgrade=False,
    )


def verify_envelope(
    envelope: ValidationEnvelopeSchema,
    root_public_key_or_cert: str | None = None,
) -> tuple[bool, str]:
    """Verify an entire validation envelope locally.

    Checks, in order:
      1. Local attestation matches the embedded result.
      2. Server signature is present and valid (for official envelopes).
      3. Certificate chain is valid against the trusted root (if provided).

    Returns (is_valid, reason).
    """
    # 1. Local attestation
    if envelope.result is None:
        return False, "envelope contains no result to verify"

    ok, reason = verify_local_attestation(envelope.result, envelope.local_attestation)
    if not ok:
        return False, reason

    # 2. Server signature (required for official status)
    if envelope.status == "official":
        if envelope.server_validation is None:
            return False, "official envelope missing server_validation"

        ok, reason = verify_server_signature(
            envelope.run_hash,
            envelope.server_validation,
        )
        if not ok:
            return False, reason

        # 3. Certificate chain (when a trust anchor is supplied)
        if root_public_key_or_cert is not None:
            chain = envelope.server_validation.certificate_chain
            ok, reason = verify_certificate_chain(chain, root_public_key_or_cert)
            if not ok:
                return False, reason

    return True, "envelope verified"


# ── Revocation list helpers ──────────────────────────────────────────────────


def _canonicalize_revocation_list(
    revoked_validation_ids: list[str],
    issued_at: str,
) -> bytes:
    """Return deterministic canonical bytes for a revocation list payload."""
    data = {
        "schema_version": "1.0",
        "issued_at": issued_at,
        "revoked_validation_ids": sorted(set(revoked_validation_ids)),
    }
    return json.dumps(
        _sort_dicts(data),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sign_revocation_list(
    revoked_validation_ids: list[str],
    private_key: Ed25519PrivateKey | Path,
    server_certificate_pem: str,
    root_certificate_pem: str,
    issued_at: str | None = None,
) -> dict:
    """Sign a revocation list with the server intermediate key.

    Returns a self-contained JSON-serializable revocation list that includes
    the certificate chain so anyone with the WAF++ root certificate can verify
    both the signer identity and the signature.
    """
    if isinstance(private_key, Path):
        private_key = load_signing_key(private_key)

    issued_at = issued_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    canonical = _canonicalize_revocation_list(revoked_validation_ids, issued_at)
    signature = private_key.sign(canonical)

    return {
        "schema_version": "1.0",
        "issued_at": issued_at,
        "revoked_validation_ids": sorted(set(revoked_validation_ids)),
        "signer_public_key": _public_key_pem(private_key.public_key()),
        "certificate_chain": [server_certificate_pem, root_certificate_pem],
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_revocation_list(
    revocation_list: dict,
    root_public_key_or_cert: str | None = None,
) -> tuple[bool, str]:
    """Verify a signed revocation list.

    Checks the server signature and, if a root trust anchor is supplied,
    validates the certificate chain.
    """
    try:
        signer_public_key = _load_public_key(revocation_list["signer_public_key"])
        canonical = _canonicalize_revocation_list(
            revocation_list["revoked_validation_ids"],
            revocation_list["issued_at"],
        )
        signature = base64.b64decode(revocation_list["signature"])
        signer_public_key.verify(signature, canonical)

        if root_public_key_or_cert is not None:
            chain = revocation_list.get("certificate_chain", [])
            ok, reason = verify_certificate_chain(chain, root_public_key_or_cert)
            if not ok:
                return False, reason

        return True, "revocation list valid"
    except InvalidSignature:
        return False, "revocation list signature invalid"
    except Exception as exc:
        return False, f"revocation list verification failed: {exc}"


# ── Certificate generation helpers (for tests / local root setup) ─────────────


def generate_root_certificate(
    subject_name: str = "WAF++ Root CA",
    validity_days: int = 3650,
) -> tuple[Ed25519PrivateKey, str]:
    """Generate a self-signed root CA certificate and return (private_key, pem)."""
    private_key = Ed25519PrivateKey.generate()
    subject = issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, subject_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, None)
    )
    return private_key, cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def generate_server_certificate(
    server_private_key: Ed25519PrivateKey,
    root_private_key: Ed25519PrivateKey,
    root_cert_pem: str,
    subject_name: str = "WAF++ Validation Server",
    validity_days: int = 365,
) -> str:
    """Sign a server intermediate certificate with the root CA."""
    root_cert = _load_x509_certificate(root_cert_pem)
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, subject_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(server_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_private_key, None)
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
