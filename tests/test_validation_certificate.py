"""Tests for the WAF++ validation certificate PDF renderer."""

from __future__ import annotations

from pathlib import Path

import pytest

from wafpass.attestation import (
    build_server_validation,
    create_official_envelope,
    create_offline_envelope,
    generate_root_certificate,
    generate_server_certificate,
    generate_signing_key,
    load_signing_key,
    sign_run,
)
from wafpass.schema import WafpassResultSchema

_PDF_SKIP_REASON = "reportlab not installed"
try:
    from wafpass.pdf_reporter import generate_validation_certificate
except ImportError as _pdf_import_err:  # pragma: no cover
    generate_validation_certificate = None  # type: ignore[misc,assignment]
    _PDF_SKIP_REASON = f"reportlab not installed: {_pdf_import_err}"


pytestmark = pytest.mark.skipif(
    generate_validation_certificate is None,
    reason=_PDF_SKIP_REASON,
)


@pytest.fixture
def sample_result():
    """A minimal WafpassResultSchema for certificate tests."""
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
        detected_regions=[],
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


@pytest.fixture
def official_envelope(sample_result: WafpassResultSchema, org_key_path: Path, server_keys: tuple):
    """An official validation envelope with a full certificate chain."""
    _root_key, root_cert, server_key, server_cert = server_keys
    attestation = sign_run(sample_result, org_key_path)
    server_validation = build_server_validation(
        canonical_hash=attestation.canonical_hash,
        server_private_key=server_key,
        server_certificate_pem=server_cert,
        root_certificate_pem=root_cert,
        badge_url="https://example.com/badge.svg",
        verification_url="https://example.com/verify",
    )
    return create_official_envelope(sample_result, attestation, server_validation)


@pytest.fixture
def offline_envelope(sample_result: WafpassResultSchema, org_key_path: Path):
    """An offline (self-signed) validation envelope."""
    return create_offline_envelope(sample_result, org_key_path)


def test_official_certificate_pdf_renders(
    tmp_path: Path, official_envelope: object
):
    """An official envelope produces a non-empty PDF certificate."""
    output_path = tmp_path / "certificate.pdf"
    generate_validation_certificate(official_envelope, output_path)

    assert output_path.exists()
    assert output_path.stat().st_size > 0
    # Basic PDF magic-number sanity check.
    assert output_path.read_bytes().startswith(b"%PDF")


def test_offline_certificate_pdf_renders(
    tmp_path: Path, offline_envelope: object
):
    """An offline envelope also produces a valid PDF certificate."""
    output_path = tmp_path / "offline-certificate.pdf"
    generate_validation_certificate(offline_envelope, output_path)

    assert output_path.exists()
    assert output_path.stat().st_size > 0
    assert output_path.read_bytes().startswith(b"%PDF")


def test_certificate_contains_run_metadata(
    tmp_path: Path, official_envelope: object
):
    """The rendered PDF should be large enough to contain metadata tables."""
    output_path = tmp_path / "certificate.pdf"
    generate_validation_certificate(official_envelope, output_path)

    # A certificate with metadata tables should be at least a few KB.
    assert output_path.stat().st_size > 1024
