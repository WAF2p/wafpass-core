"""WAF++ PASS result schema — the serialisation contract.

This module defines the canonical JSON shape of a wafpass-result.json file.
It is the single source of truth used by:

  * ``wafpass check --output json``  (produces the payload)
  * ``wafpass-server POST /api/v1/runs``     (validates the payload on ingest)
  * Dashboard / CI consumers         (parse the payload)

Consumers should import from here rather than duplicating these types.

Shape
-----
::

    {
      "schema_version": "1.0",
      "project":        "my-infra",
      "branch":         "main",
      "git_sha":        "abc1234",
      "triggered_by":   "github-actions",
      "iac_framework":  "terraform",
      "score":          82,
      "pillar_scores":  {"SEC": 90, "OPS": 75, ...},
      "path":           "infra/",
      "controls_loaded": 70,
      "controls_run":    65,
      "detected_regions": [["eu-central-1", "aws", "eu-central-1a"]],
      "source_paths":   ["infra/"],
      "findings": [
        {
          "check_id":    "WAF-SEC-010-01",
          "check_title": "MFA enabled on root account",
          "control_id":  "WAF-SEC-010",
          "pillar":      "SEC",
          "severity":    "CRITICAL",
          "status":      "FAIL",
          "resource":    "aws_iam_account_password_policy.main",
          "message":     "mfa_delete is false",
          "remediation": "Set mfa_delete = true"
        },
        ...
      ]
    }
"""

from __future__ import annotations

from typing import Any, Optional, Union

from pydantic import BaseModel, Field


class SecretFindingSchema(BaseModel):
    """A single hardcoded-secret finding from the WAF++ secret scanner.

    Note: ``raw_value`` is intentionally excluded — only the masked form is
    persisted so the server never stores live credential material.
    """

    file: str           # relative path to the source file
    line_no: int        # 1-based line number
    pattern_name: str   # human-readable label, e.g. "Hardcoded password"
    severity: str       # critical | high
    matched_key: str    # attribute name, e.g. "password" (empty for format patterns)
    masked_value: str   # first 4 chars + *** — never the full value
    suppressed: bool = False


class FindingSchema(BaseModel):
    """A single check result (one check × one resource)."""

    check_id: str
    check_title: str
    control_id: str
    pillar: str = ""
    severity: str
    status: str  # PASS | FAIL | SKIP | ERROR | WAIVED
    resource: str
    message: str
    remediation: str
    example: Optional[dict[str, Any]] = None
    regulatory_mapping: list[dict[str, Any]] = Field(default_factory=list)


class ControlCheckMetaSchema(BaseModel):
    """Lightweight metadata for a single automated check within a control."""

    id: str
    title: str
    severity: str
    remediation: str = ""
    example: Optional[dict[str, Any]] = None  # {"compliant": str, "non_compliant": str}


class ControlMetaSchema(BaseModel):
    """Metadata for a WAF++ control loaded during the scan.

    Carried inside WafpassResultSchema.controls_meta so that consumers
    (dashboard, CI) know exactly which controls were evaluated without
    needing access to the YAML files.
    """

    id: str
    title: str
    pillar: str
    severity: str
    category: str = ""
    description: str = ""
    rationale: str = ""
    threat: list[str] = Field(default_factory=list)
    regulatory_mapping: list[dict[str, Any]] = Field(default_factory=list)
    checks: list[ControlCheckMetaSchema] = Field(default_factory=list)


class LocalAttestationSchema(BaseModel):
    """Organization-level cryptographic attestation of a single run.

    This proves that a specific entity (organization, CI runner, auditor) signed
    the exact run result. It is produced locally and then submitted to the
    WAF++ central server for countersignature.
    """

    public_key: str = Field(
        description="PEM-encoded Ed25519 public key (or base64-encoded raw key).",
    )
    signature: str = Field(
        description="Base64-encoded Ed25519 signature over the canonical run hash.",
    )
    algorithm: str = Field(default="ed25519", description="Signature algorithm.")
    canonical_hash: str = Field(
        description="SHA-256 hex digest of the canonical JSON serialization of the run.",
    )
    signed_at: str = Field(description="ISO-8601 UTC timestamp of the local signature.")
    signer_kind: str = Field(
        default="organization",
        description="Kind of signer: organization | ci-runner | auditor | offline-fallback.",
    )


class ServerValidationSchema(BaseModel):
    """Official WAF++ server countersignature and validation record.

    This is produced by the central WAF++ server after verifying the local
    attestation and the canonical run hash. It forms a certificate chain back
    to the published WAF++ root certificate.
    """

    validation_id: str = Field(description="UUID assigned by the WAF++ server.")
    validated_at: str = Field(description="ISO-8601 UTC timestamp of server validation.")
    server_public_key: str = Field(
        description="PEM-encoded public key of the server intermediate certificate.",
    )
    server_signature: str = Field(
        description="Base64-encoded Ed25519 signature over canonical_hash + validation_id + validated_at.",
    )
    certificate_chain: list[str] = Field(
        default_factory=list,
        description="PEM-encoded X.509 certificate chain: [server intermediate, WAF++ root].",
    )
    badge_url: str = Field(
        default="",
        description="Public URL to the badge image/JSON for this validation.",
    )
    verification_url: str = Field(
        default="",
        description="Public URL to verify this validation without authentication.",
    )
    expires_at: Optional[str] = Field(
        default=None,
        description="Optional ISO-8601 UTC expiry of the validation.",
    )
    metadata: Optional[dict[str, Any]] = Field(
        default=None,
        description="Optional provenance metadata supplied by the validating dashboard/server.",
    )


class WafpassResultSchema(BaseModel):
    """Top-level wafpass-result.json payload.

    Produced by ``wafpass check --output json`` and consumed by
    ``wafpass-server POST /api/v1/runs``.
    """

    schema_version: str = Field(default="1.0", description="Schema version for forward-compatibility checks.")

    # ── Run metadata ──────────────────────────────────────────────────────────
    project: str = Field(default="", description="Human-readable project / repo name.")
    branch: str = Field(default="", description="VCS branch name, e.g. 'main'.")
    git_sha: str = Field(default="", description="Full or short commit SHA.")
    triggered_by: str = Field(
        default="local",
        description="How this run was triggered: local | github-actions | gitlab-ci | …",
    )
    run: dict[str, Any] = Field(
        default_factory=dict,
        description="Run metadata including CI/CD status. Add {'is_cicd': True} for pipeline runs.",
    )
    iac_framework: str = Field(
        default="terraform",
        description="IaC framework scanned: terraform | cdk | bicep | pulumi | …",
    )
    stage: str = Field(
        default="",
        description="Deployment stage this run was executed against, e.g. dev | staging | prod.",
    )

    # ── Aggregate scores ──────────────────────────────────────────────────────
    score: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Overall compliance score (0–100).",
    )
    pillar_scores: dict[str, int] = Field(
        default_factory=dict,
        description="Per-pillar scores, e.g. {'SEC': 90, 'OPS': 75}.",
    )

    # ── Scan context ──────────────────────────────────────────────────────────
    path: str = Field(default="", description="Display path(s) scanned.")
    controls_loaded: int = Field(default=0, ge=0)
    controls_run: int = Field(default=0, ge=0)
    detected_regions: list[list[str | None]] = Field(
        default_factory=list,
        description="Detected cloud regions: [[region, provider, availability_zone], ...]. "
        "availability_zone may be null for regions that don't use AZs (e.g., GCP multi-regions).",
    )
    source_paths: list[str] = Field(default_factory=list)

    # ── Controls metadata ─────────────────────────────────────────────────────
    controls_meta: list[ControlMetaSchema] = Field(
        default_factory=list,
        description="Metadata for each control that was loaded during this run.",
    )

    # ── Findings ──────────────────────────────────────────────────────────────
    findings: list[FindingSchema] = Field(default_factory=list)

    # ── Secret scanner findings (optional, populated when --no-secrets is NOT set) ──
    secret_findings: list[SecretFindingSchema] = Field(
        default_factory=list,
        description=(
            "Hardcoded-secret findings from the WAF++ regex secret scanner. "
            "Only masked values are stored — raw credential material is never persisted."
        ),
    )

    # ── Terraform plan changes (optional, populated via --plan-file) ──────────
    plan_changes: Optional[dict[str, Any]] = Field(
        default=None,
        description=(
            "Normalised terraform plan change summary. "
            "Populated when --plan-file is passed to wafpass check. "
            "Shape: {terraform_version, format_version, scanned_at, summary, changes}."
        ),
    )

    # ── Source snapshot (optional, populated via --upload-source) ───────────────
    source_snapshot: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Optional map of relative .tf file paths to their full text content. "
            "When uploaded, wafpass-server can render Local preview diffs in the "
            "dashboard without needing filesystem access to the original repository."
        ),
    )

    completed_at: Optional[str] = Field(
        default=None,
        description="ISO-8601 UTC timestamp when the scan finished. Used by the dashboard for duration metrics.",
    )

    # ── Local attestation (optional, populated via --validate) ────────────────────
    attestation: Optional[LocalAttestationSchema] = Field(
        default=None,
        description=(
            "Optional local cryptographic attestation of this run. "
            "Contains the canonical run hash and an Ed25519 signature from the "
            "organization's signing key."
        ),
    )


class ValidationEnvelopeSchema(BaseModel):
    """Complete validation artifact delivered to the user.

    Combines the run result, the local attestation, and (when available) the
    official server countersignature. This is the unit that is written to disk,
    verified, and embedded in badges/certificates.
    """

    schema_version: str = Field(default="1.0", description="Validation envelope schema version.")
    run_hash: str = Field(description="Canonical SHA-256 hash of the run result.")
    status: str = Field(
        description="Validation status: official | offline | pending.",
    )
    result: Optional[WafpassResultSchema] = Field(
        default=None,
        description="The original run result. May be omitted in lightweight envelopes.",
    )
    local_attestation: LocalAttestationSchema
    server_validation: Optional[ServerValidationSchema] = Field(
        default=None,
        description="Official server countersignature; null for offline validations.",
    )
    pending_upgrade: bool = Field(
        default=False,
        description="True when an offline validation can be upgraded to official later.",
    )
    metadata: Optional[dict[str, Any]] = Field(
        default=None,
        description="Optional provenance metadata supplied by the validating dashboard/server.",
    )
