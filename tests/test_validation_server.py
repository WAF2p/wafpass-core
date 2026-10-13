"""End-to-end tests for the WAF++ validation server endpoints."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from wafpass.attestation import (
    compute_run_hash,
    generate_signing_key,
    load_signing_key,
    sign_run,
    verify_certificate_chain,
    verify_envelope,
    verify_server_signature,
)
from wafpass.schema import (
    ServerValidationSchema,
    ValidationEnvelopeSchema,
    WafpassResultSchema,
)

# Import and reset the in-memory validation store before each test.
from wafpass import validation_server


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    validation_server._validations.clear()
    validation_server._revocations.clear()
    validation_server._root_key = None
    validation_server._root_cert_pem = None
    validation_server._server_key = None
    validation_server._server_cert_pem = None
    monkeypatch.setenv("WAFPASS_SERVER_KEYS_DIR", str(tmp_path / "server-keys"))
    from serve.app import app

    with TestClient(app) as c:
        yield c


@pytest.fixture
def key_path(tmp_path: Path) -> Path:
    path = tmp_path / "org.key"
    generate_signing_key(path)
    return path


@pytest.fixture
def sample_result() -> WafpassResultSchema:
    return WafpassResultSchema(
        project="demo",
        branch="main",
        git_sha="abc1234",
        score=88,
        findings=[],
    )


def _post_validation(client: TestClient, result: WafpassResultSchema, key_path: Path):
    attestation = sign_run(result, key_path)
    payload = {
        "result": result.model_dump(),
        "attestation": attestation.model_dump(),
    }
    return client.post("/api/v1/validations", json=payload)


def test_submit_validation_returns_server_schema(client, key_path, sample_result):
    resp = _post_validation(client, sample_result, key_path)
    assert resp.status_code == 201
    data = resp.json()["data"]
    sv = ServerValidationSchema.model_validate(data)
    assert sv.validation_id
    assert sv.server_signature
    assert len(sv.certificate_chain) == 2
    assert sv.badge_url
    assert sv.verification_url


def test_server_signature_verifies_locally(client, key_path, sample_result):
    resp = _post_validation(client, sample_result, key_path)
    sv = ServerValidationSchema.model_validate(resp.json()["data"])
    run_hash = compute_run_hash(sample_result)
    ok, reason = verify_server_signature(run_hash, sv)
    assert ok, reason


def test_certificate_chain_verifies(client, key_path, sample_result):
    resp = _post_validation(client, sample_result, key_path)
    sv = ServerValidationSchema.model_validate(resp.json()["data"])
    root_cert = sv.certificate_chain[-1]
    ok, reason = verify_certificate_chain(sv.certificate_chain, root_cert)
    assert ok, reason


def test_get_validation_record(client, key_path, sample_result):
    post = _post_validation(client, sample_result, key_path)
    sv = ServerValidationSchema.model_validate(post.json()["data"])
    get = client.get(f"/api/v1/validations/{sv.validation_id}")
    assert get.status_code == 200
    record = get.json()
    assert record["validation_id"] == sv.validation_id
    assert record["canonical_hash"] == compute_run_hash(sample_result)
    assert record["project"] == sample_result.project


def test_public_verify_endpoint(client, key_path, sample_result):
    post = _post_validation(client, sample_result, key_path)
    sv = ServerValidationSchema.model_validate(post.json()["data"])
    verify = client.get(f"/api/v1/validations/{sv.validation_id}/verify")
    assert verify.status_code == 200
    data = verify.json()
    assert data["validation_id"] == sv.validation_id
    assert data["status"] == "official"


def test_badge_svg_endpoint(client, key_path, sample_result):
    post = _post_validation(client, sample_result, key_path)
    sv = ServerValidationSchema.model_validate(post.json()["data"])
    badge = client.get(sv.badge_url)
    assert badge.status_code == 200
    assert badge.headers["content-type"].startswith("image/svg+xml")
    assert "WAF++ Validated" in badge.text


def test_badge_json_endpoint(client, key_path, sample_result):
    post = _post_validation(client, sample_result, key_path)
    sv = ServerValidationSchema.model_validate(post.json()["data"])
    badge_url = sv.badge_url.replace(".svg", ".json")
    badge = client.get(badge_url)
    assert badge.status_code == 200
    data = badge.json()
    assert data["status"] == "official"
    assert data["run_hash"] == compute_run_hash(sample_result)
    assert data["score"] == sample_result.score


def test_revocation_changes_status(client, key_path, sample_result):
    post = _post_validation(client, sample_result, key_path)
    sv = ServerValidationSchema.model_validate(post.json()["data"])
    revoke = client.post(f"/api/v1/validations/{sv.validation_id}/revoke")
    assert revoke.status_code == 200
    verify = client.get(f"/api/v1/validations/{sv.validation_id}/verify")
    assert verify.json()["status"] == "revoked"


def test_submit_rejects_modified_result(client, key_path, sample_result):
    attestation = sign_run(sample_result, key_path)
    tampered = sample_result.model_dump()
    tampered["score"] = 99
    payload = {"result": tampered, "attestation": attestation.model_dump()}
    resp = client.post("/api/v1/validations", json=payload)
    assert resp.status_code == 400
    assert "Canonical hash mismatch" in resp.json()["detail"]


def test_submit_rejects_invalid_signature(client, key_path, sample_result):
    attestation = sign_run(sample_result, key_path)
    # Replace signature with a different base64 string.
    bad_attestation = attestation.model_dump()
    bad_attestation["signature"] = "a" * 44
    payload = {"result": sample_result.model_dump(), "attestation": bad_attestation}
    resp = client.post("/api/v1/validations", json=payload)
    assert resp.status_code == 400
    assert "Local attestation verification failed" in resp.json()["detail"]


def test_verify_envelope_against_root_certificate(client, key_path, sample_result):
    """Build a full envelope and verify it with the published root certificate."""
    post = _post_validation(client, sample_result, key_path)
    sv = ServerValidationSchema.model_validate(post.json()["data"])
    local = sign_run(sample_result, key_path)
    envelope = ValidationEnvelopeSchema(
        schema_version="1.0",
        run_hash=compute_run_hash(sample_result),
        status="official",
        result=sample_result,
        local_attestation=local,
        server_validation=sv,
    )
    root_cert = sv.certificate_chain[-1]
    ok, reason = verify_envelope(envelope, root_public_key_or_cert=root_cert)
    assert ok, reason


def test_validation_id_not_found(client):
    resp = client.get("/api/v1/validations/does-not-exist/verify")
    assert resp.status_code == 404


def test_keys_persisted_and_reused(tmp_path: Path, client, key_path, sample_result):
    """Key generation should reuse previously generated key files."""
    validation_server._root_key = None
    _post_validation(client, sample_result, key_path)
    assert (tmp_path / "server-keys" / "root.key").exists()
    assert (tmp_path / "server-keys" / "server.key").exists()
