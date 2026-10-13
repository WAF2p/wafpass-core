"""Unit tests for WAF++ PASS cryptographic attestation primitives."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wafpass.attestation import (
    canonicalize_run,
    compute_run_hash,
    create_official_envelope,
    create_offline_envelope,
    generate_root_certificate,
    generate_server_certificate,
    generate_signing_key,
    load_signing_key,
    sign_run,
    upgrade_offline_envelope,
    verify_certificate_chain,
    verify_envelope,
    verify_local_attestation,
    verify_server_signature,
)
from wafpass.schema import WafpassResultSchema


@pytest.fixture
def sample_result():
    """A minimal WafpassResultSchema for deterministic testing."""
    return WafpassResultSchema(
        schema_version="1.0",
        project="acme-infra",
        branch="main",
        git_sha="abc1234def5678",
        triggered_by="local",
        run={"is_cicd": False},
        iac_framework="terraform",
        stage="prod",
        score=87,
        pillar_scores={"SEC": 90, "OPS": 84},
        path="infra/",
        controls_loaded=70,
        controls_run=65,
        detected_regions=[["eu-central-1", "aws", "eu-central-1a"]],
        source_paths=["infra/"],
        controls_meta=[],
        findings=[],
        secret_findings=[],
    )


@pytest.fixture
def org_key_path(tmp_path: Path):
    """Path to a freshly generated organization signing key."""
    key_path = tmp_path / "org.key"
    generate_signing_key(key_path)
    return key_path


@pytest.fixture
def server_keys(tmp_path: Path):
    """Root + server key pair and certificates for testing."""
    root_key, root_cert = generate_root_certificate(
        subject_name="WAF++ Test Root CA",
        validity_days=365,
    )
    server_key_path = tmp_path / "server.key"
    generate_signing_key(server_key_path)
    server_key = load_signing_key(server_key_path)
    server_cert = generate_server_certificate(
        server_private_key=server_key,
        root_private_key=root_key,
        root_cert_pem=root_cert,
        subject_name="WAF++ Test Validation Server",
        validity_days=180,
    )
    return root_key, root_cert, server_key, server_cert


# ── Key management ────────────────────────────────────────────────────────────


def test_generate_and_load_signing_key(org_key_path: Path):
    """Generated keys must be reloadable and produce a public key."""
    assert org_key_path.exists()
    private_key = load_signing_key(org_key_path)
    public_key = private_key.public_key()
    assert public_key is not None


def test_key_file_permissions(org_key_path: Path):
    """The private key file should be readable only by the owner (Unix)."""
    import os

    mode = org_key_path.stat().st_mode
    # Check owner read/write, group/others no permissions.
    assert mode & 0o777 == 0o600 or os.name == "nt", (
        f"key file permissions should be 0o600, got {oct(mode & 0o777)}"
    )


# ── Canonical serialization and hash ────────────────────────────────────────────


def test_canonicalization_is_deterministic(sample_result: WafpassResultSchema):
    """The same result must always produce the exact same canonical bytes."""
    first = canonicalize_run(sample_result)
    second = canonicalize_run(sample_result)
    assert first == second
    assert isinstance(first, bytes)


def test_canonicalization_excludes_attestation(sample_result: WafpassResultSchema):
    """Adding an attestation field must not change the canonical run hash."""
    from wafpass.schema import LocalAttestationSchema

    hash_before = compute_run_hash(sample_result)

    sample_result.attestation = LocalAttestationSchema(
        public_key="dummy",
        signature="dummy",
        canonical_hash=hash_before,
        signed_at="2026-01-01T00:00:00Z",
    )
    hash_after = compute_run_hash(sample_result)
    assert hash_before == hash_after


def test_canonicalization_sorts_keys(sample_result: WafpassResultSchema):
    """Nested dictionaries must have sorted keys in the output."""
    canonical = canonicalize_run(sample_result)
    text = canonical.decode("utf-8")
    # pillar_scores keys are "OPS", "SEC"; sorted order is "OPS","SEC".
    assert '"OPS"' in text
    assert '"SEC"' in text
    # A simple check that the dict keys appear sorted lexicographically at top level.
    # JSON object key order is preserved by Python's json.dumps with sort_keys=True.
    parsed = json.loads(text)
    assert list(parsed.keys()) == sorted(parsed.keys())


# ── Local attestation ─────────────────────────────────────────────────────────


def test_sign_and_verify_run(sample_result: WafpassResultSchema, org_key_path: Path):
    """A signed run must verify successfully with the matching public key."""
    attestation = sign_run(sample_result, org_key_path)
    assert attestation.algorithm == "ed25519"
    assert attestation.canonical_hash == compute_run_hash(sample_result)

    ok, reason = verify_local_attestation(sample_result, attestation)
    assert ok, reason


def test_tampered_run_fails_verification(
    sample_result: WafpassResultSchema, org_key_path: Path
):
    """Changing the result after signing must break verification."""
    attestation = sign_run(sample_result, org_key_path)
    sample_result.score = 99
    ok, reason = verify_local_attestation(sample_result, attestation)
    assert not ok
    assert "mismatch" in reason.lower()


def test_tampered_signature_fails_verification(
    sample_result: WafpassResultSchema, org_key_path: Path
):
    """Changing the signature must break verification."""
    attestation = sign_run(sample_result, org_key_path)
    attestation.signature = "a" * len(attestation.signature)
    ok, reason = verify_local_attestation(sample_result, attestation)
    assert not ok
    assert "signature" in reason.lower()


# ── Offline and official envelopes ────────────────────────────────────────────


def test_offline_envelope(sample_result: WafpassResultSchema, org_key_path: Path):
    """Offline envelopes are self-signed and pending upgrade."""
    envelope = create_offline_envelope(sample_result, org_key_path)
    assert envelope.status == "offline"
    assert envelope.pending_upgrade is True
    assert envelope.server_validation is None
    assert envelope.run_hash == compute_run_hash(sample_result)

    ok, reason = verify_envelope(envelope)
    assert ok, reason


def test_official_envelope(
    sample_result: WafpassResultSchema,
    org_key_path: Path,
    server_keys: tuple,
):
    """Official envelopes verify both local and server signatures."""
    _root_key, root_cert, server_key, server_cert = server_keys

    attestation = sign_run(sample_result, org_key_path)
    server_validation = build_server_validation_from_fixture(
        attestation.canonical_hash,
        server_key,
        server_cert,
        root_cert,
    )
    envelope = create_official_envelope(sample_result, attestation, server_validation)

    assert envelope.status == "official"
    assert envelope.pending_upgrade is False
    assert envelope.server_validation is not None

    ok, reason = verify_envelope(envelope, root_public_key_or_cert=root_cert)
    assert ok, reason


def test_upgrade_offline_to_official(
    sample_result: WafpassResultSchema,
    org_key_path: Path,
    server_keys: tuple,
):
    """Offline envelopes can be upgraded to official with a server countersign."""
    _root_key, root_cert, server_key, server_cert = server_keys

    offline = create_offline_envelope(sample_result, org_key_path)
    server_validation = build_server_validation_from_fixture(
        offline.run_hash,
        server_key,
        server_cert,
        root_cert,
    )
    official = upgrade_offline_envelope(offline, server_validation)

    assert official.status == "official"
    assert official.pending_upgrade is False
    assert official.server_validation == server_validation

    ok, reason = verify_envelope(official, root_public_key_or_cert=root_cert)
    assert ok, reason


# ── Server signature and certificate chain ────────────────────────────────────


def test_server_signature_verifies(
    sample_result: WafpassResultSchema,
    org_key_path: Path,
    server_keys: tuple,
):
    """The server countersignature must verify independently."""
    _root_key, root_cert, server_key, server_cert = server_keys

    attestation = sign_run(sample_result, org_key_path)
    server_validation = build_server_validation_from_fixture(
        attestation.canonical_hash,
        server_key,
        server_cert,
        root_cert,
    )
    ok, reason = verify_server_signature(
        attestation.canonical_hash,
        server_validation,
    )
    assert ok, reason


def test_server_signature_fails_on_wrong_hash(server_keys: tuple):
    """A server signature must not verify against a different run hash."""
    _root_key, root_cert, server_key, server_cert = server_keys

    canonical_hash = compute_run_hash({"project": "other"})
    server_validation = build_server_validation_from_fixture(
        canonical_hash, server_key, server_cert, root_cert
    )
    ok, reason = verify_server_signature("wrong-hash", server_validation)
    assert not ok
    assert "signature" in reason.lower()


def test_certificate_chain_verifies(server_keys: tuple):
    """A correctly signed chain validates against the root certificate."""
    _root_key, root_cert, server_key, server_cert = server_keys
    chain = [server_cert, root_cert]
    ok, reason = verify_certificate_chain(chain, root_cert)
    assert ok, reason


def test_certificate_chain_fails_with_wrong_root(server_keys: tuple):
    """A chain must not validate against an unrelated root."""
    _root_key, root_cert, server_key, server_cert = server_keys
    other_key, other_cert = generate_root_certificate(subject_name="Other Root")

    chain = [server_cert, root_cert]
    ok, reason = verify_certificate_chain(chain, other_cert)
    assert not ok


# ── End-to-end envelope verification ──────────────────────────────────────────


def test_official_envelope_with_raw_public_key(
    sample_result: WafpassResultSchema,
    org_key_path: Path,
    server_keys: tuple,
):
    """Verification also works when the trust anchor is a raw Ed25519 public key."""
    _root_key, root_cert, server_key, server_cert = server_keys

    attestation = sign_run(sample_result, org_key_path)
    server_validation = build_server_validation_from_fixture(
        attestation.canonical_hash,
        server_key,
        server_cert,
        root_cert,
    )
    envelope = create_official_envelope(sample_result, attestation, server_validation)

    raw_root_public_key = server_validation.certificate_chain[-1]
    ok, reason = verify_envelope(envelope, root_public_key_or_cert=raw_root_public_key)
    assert ok, reason


def test_envelope_without_result_fails_verification(org_key_path: Path):
    """An envelope that dropped the result cannot be verified locally."""
    minimal_result = WafpassResultSchema()
    envelope = create_offline_envelope(minimal_result, org_key_path)
    envelope.result = None

    ok, reason = verify_envelope(envelope)
    assert not ok
    assert "no result" in reason.lower()


# ── Helpers ───────────────────────────────────────────────────────────────────


def build_server_validation_from_fixture(
    canonical_hash: str,
    server_key,
    server_cert: str,
    root_cert: str,
) -> "ServerValidationSchema":
    """Build a server validation record using the test fixture certificates."""
    from wafpass.attestation import build_server_validation

    return build_server_validation(
        canonical_hash=canonical_hash,
        server_private_key=server_key,
        server_certificate_pem=server_cert,
        root_certificate_pem=root_cert,
        badge_url="https://example.com/badge.svg",
        verification_url="https://example.com/verify",
    )
