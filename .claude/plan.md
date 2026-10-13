# Plan: WAF++ Official Validation & Certificate Chain

## Goal

Give WAF++ users a way to obtain an **official, cryptographically signed validation** from WAF++ for a specific `wafpass check` run. The validation must:

1. Be **revalidatable** by any third party without trusting the user’s machine.
2. Be issued by a **central WAF++ server** holding the root-of-trust signing key.
3. **Lock the run locally** after validation so the validated artifact cannot be altered or deleted.
4. Require internet for the **official** validation path.
5. Provide an **offline fallback** that still gives strong (but not "official") cryptographic proof.
6. Produce both a **digital badge** and a **certificate chain** document.
7. Make fakes practically impossible through a chain of hashes, signatures, and server-side countersigns.

## Core concepts

- **Run attestation** (`wafpass-result.json`) — the existing Pydantic schema `WafpassResultSchema`. It is the object being certified.
- **Local signing key pair** — generated per organization/machine. It proves *who submitted* the run and binds the run to their identity.
- **Official WAF++ signing key** — held by the central server. It proves *WAF++ officials validated* this exact run.
- **Certificate chain** — `run hash → local signature → server countersignature → WAF++ root certificate`.
- **Badge** — a portable, embeddable JSON/SVG/HTML object that can be displayed in READMEs, CI pipelines, or compliance portals. It contains a verification URL and a short hash.
- **Offline fallback** — when no internet is available, the CLI self-signs the run and stores a *deferred validation token* that the server can countersign later, or the organization can use the local signature as interim proof.

## Trust model

```
┌────────────────────────────────────────────────────────────────────────────┐
│                            WAF++ ROOT CERTIFICATE                            │
│                 (offline HSM / KMS, public key published)                  │
└────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ signs
                                      ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                       WAF++ CENTRAL SERVER CERTIFICATE                     │
│              (intermediate, rotated, published in JWKS / registry)         │
└────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ countersigns
                                      ▼
┌─────────────────────┐        ┌─────────────────────────────┐
│   LOCAL SIGNATURE     │───────►│   SERVER VALIDATION RECORD  │
│ (organization key)    │        │   (immutable, not deletable) │
└─────────────────────┘        └─────────────────────────────┘
                                      │
                                      ▼
                          ┌──────────────────────┐
                          │   CERTIFICATE + BADGE  │
                          │  (delivered to user)   │
                          └──────────────────────┘
```

- The **root key** only signs the **server intermediate certificate**. The root public key is hard-coded / published.
- The **server certificate** signs every individual validation record.
- The **organization key** signs the run itself, proving submission origin and non-repudiation.
- Verification means: recompute the run hash, check the local signature, check the server countersignature, check the chain up to the root.

## Canonical run hash

The run hash is the cryptographic anchor. It must be **deterministic and reproducible** across tools.

Algorithm:

1. Take `WafpassResultSchema.model_dump()` **excluding** any `attestation` / `certificate` / `validation` fields.
2. Serialize to JSON with:
   - UTF-8 encoding
   - Keys sorted recursively
   - No insignificant whitespace
   - No `None` values omitted (so the shape is stable)
   - Lists preserved in their natural order
3. Compute `SHA-256` of the serialized bytes.

This hash is computed by the CLI and recomputed by the server. If the server hash does not match the submitted hash, the validation is rejected. This prevents the user from sending a tampered run.

## New module: `wafpass/attestation.py`

Responsibilities: key management, canonical hashing, signing, verification, and certificate-chain assembly.

Data classes (also exposed as Pydantic schemas):

```python
class LocalAttestationSchema(BaseModel):
    public_key: str            # base64-encoded Ed25519 public key (PEM optional)
    signature: str             # base64 Ed25519 signature
    algorithm: str = "ed25519"
    canonical_hash: str        # sha256 of canonical run JSON
    signed_at: str             # ISO-8601 UTC
    signer_kind: str = "organization"   # or "offline-fallback"

class ServerValidationSchema(BaseModel):
    validation_id: str         # UUID assigned by server
    validated_at: str        # ISO-8601 UTC
    server_public_key: str     # public key of the signing server cert
    server_signature: str      # base64 signature over (canonical_hash + validation_id + validated_at)
    certificate_chain: list[str]  # PEM certs: [server intermediate, WAF++ root]
    badge_url: str             # public URL to the badge image/JSON
    verification_url: str      # public URL to verify this validation
    expires_at: str | None     # optional expiry

class ValidationEnvelopeSchema(BaseModel):
    run_hash: str
    local_attestation: LocalAttestationSchema
    server_validation: ServerValidationSchema | None = None
    status: str  # "official" | "offline" | "pending"
```

Functions:

- `generate_signing_key(path)` — create Ed25519 key pair, chmod 600.
- `load_signing_key(path)` — load private key.
- `canonicalize_run(result: WafpassResultSchema) -> bytes` — produce deterministic JSON bytes.
- `compute_run_hash(result) -> str` — SHA-256 hex digest.
- `sign_run(result, private_key, signer_kind) -> LocalAttestationSchema`.
- `verify_local_attestation(result, attestation) -> tuple[bool, str]`.
- `verify_server_validation(envelope, root_public_key) -> tuple[bool, str]`.
- `build_certificate_chain(server_cert_pem, root_cert_pem) -> list[str]`.

Dependencies to add to `pyproject.toml`:

```toml
"cryptography>=42.0",
```

## Schema changes (`wafpass/schema.py`)

Add to `WafpassResultSchema`:

```python
attestation: Optional[LocalAttestationSchema] = Field(
    default=None,
    description="Local cryptographic attestation of this run (organization-signed).",
)
```

The server-side response (used by CLI after validation) is a `ValidationEnvelopeSchema`, but that is **not** part of `WafpassResultSchema` because the envelope wraps the result. Instead, the CLI writes the envelope to a separate file:

- `wafpass-validation-<run_hash>.json` — full validation envelope.
- `wafpass-badge-<run_hash>.{json,svg}` — badge.
- `wafpass-certificate-<run_hash>.pdf` — human-readable certificate.

## CLI changes (`wafpass/cli.py`)

### New command group: `wafpass validate`

```bash
# 1. Generate a local signing key for this organization
wafpass validate generate-key --path ~/.wafpass/validation.key

# 2. Run a check and immediately request official validation
wafpass check ./infra --validate official --validation-key ~/.wafpass/validation.key

# 3. Validate a previously produced wafpass-result.json
wafpass validate official --result wafpass-result.json --key ~/.wafpass/validation.key

# 4. Create an offline (self-signed) validation when internet is unavailable
wafpass validate offline --result wafpass-result.json --key ~/.wafpass/validation.key

# 5. Upgrade an offline validation to official once online
wafpass validate upgrade --envelope wafpass-validation-<hash>.json

# 6. Verify any validation envelope locally
wafpass verify --envelope wafpass-validation-<hash>.json

# 7. Show the badge / certificate
wafpass validate show --envelope wafpass-validation-<hash>.json --format badge|certificate|chain
```

### New flags on `wafpass check`

```text
--validate MODE        "official" | "offline" | "none" (default: none)
--validation-key PATH  Path to Ed25519 private key (auto-generated if missing and --validate requested)
--validation-output DIR  Directory for badge, envelope, and certificate (default: current dir)
--skip-validation-on-offline  When internet is unavailable, fall back to offline mode instead of failing
```

### `--validate official` flow

1. Run the scan as today, producing `WafpassResultSchema`.
2. Load or generate local signing key.
3. Compute canonical run hash.
4. Create `LocalAttestationSchema` (organization signature).
5. POST to central server:
   - `POST /api/v1/validations`
   - Body: `{result: <WafpassResultSchema>, attestation: <LocalAttestationSchema>}`
   - Auth: JWT session (`wafpass login`) or API key (`X-Api-Key`).
6. Server verifies the local signature and recomputes the run hash.
7. Server creates an immutable validation record, countersigns it, and returns `ValidationEnvelopeSchema`.
8. CLI writes:
   - `wafpass-validation-<run_hash>.json`
   - `wafpass-badge-<run_hash>.json` + `.svg`
   - `wafpass-certificate-<run_hash>.pdf`
9. CLI **locks the local run state** so the validated snapshot cannot be deleted or overwritten (see locking below).

### `--validate offline` flow

1. Same local signing steps as official.
2. Do **not** contact the server.
3. Set `ValidationEnvelope.status = "offline"` and `server_validation = None`.
4. Write envelope, badge, and certificate with a clear "OFFLINE — NOT OFFICIALLY VALIDATED" watermark.
5. Add a `pending_server_countersign` boolean so `wafpass validate upgrade` knows what to do.
6. Do **not** lock the run (offline validation is not immutable in the official sense).

### `wafpass verify`

1. Load envelope.
2. Recompute canonical run hash from the embedded result.
3. Check local signature.
4. If `server_validation` present:
   - Check server signature.
   - Validate certificate chain against the hard-coded WAF++ root public key.
   - Optionally query the server verification URL to confirm the record still exists.
5. Print status and chain.

## Local locking mechanism

When a run receives an **official** validation, the CLI must ensure the local run snapshot, envelope, and badge remain intact and mappable.

Implementation in `wafpass/state.py`:

1. Add a `validated: bool` flag and `validation_id` to each `index.json` run entry.
2. On official validation, mark the run entry as validated and set `validation_id`.
3. Rename / hard-link the run file to `runs/run-<run_id>-validated.json` and make it read-only (`chmod 444` on Unix; ACL/read-only flag on Windows).
4. Store the validation envelope path in the index entry.
5. Refuse deletion/overwrite of validated runs in `save_run()` and any future delete command.
6. Add a `state.lock_run(run_id, validation_id)` helper and `state.is_locked(run_id)` query.

The lock is **local and advisory** — it prevents accidental modification by WAF++ tooling. It does not stop a malicious root user, but the cryptographic chain already makes tampering detectable.

## Central server API contract (to be implemented in `wafpass-server`)

The CLI interacts with these endpoints. They are versioned under `/api/v1` to match the existing server API.

### `POST /api/v1/validations`

Submit a run for official validation.

Request body:

```json
{
  "result": { "schema_version": "1.0", "project": "...", "findings": [...], ... },
  "attestation": {
    "public_key": "base64...",
    "signature": "base64...",
    "algorithm": "ed25519",
    "canonical_hash": "sha256...",
    "signed_at": "2026-08-16T12:00:00Z",
    "signer_kind": "organization"
  }
}
```

Server actions:

1. Authenticate the caller (JWT / API key).
2. Recompute the canonical hash of `result` and compare with `attestation.canonical_hash`. Reject on mismatch.
3. Verify the local Ed25519 signature. Reject on bad signature.
4. Optionally run a lightweight re-scan or policy check (e.g., minimum number of controls, no tampered `controls_meta`).
5. Create an immutable record in the database with columns:
   - `id` (UUID)
   - `account_id` / `organization_id`
   - `project`, `branch`, `git_sha`
   - `canonical_hash`
   - `local_public_key`
   - `server_signature`
   - `server_certificate_id`
   - `validated_at`
   - `status` = `active`
   - `result_json` (full result, encrypted at rest if required)
6. Countersign: `signature = Ed25519_sign(server_private_key, canonical_hash + id + validated_at)`.
7. Return `ValidationEnvelopeSchema` with `status: "official"`.

### `GET /api/v1/validations/{validation_id}`

Return the validation envelope (without the full result unless authorized).

### `GET /api/v1/validations/{validation_id}/verify`

Public endpoint (no auth). Returns:

```json
{
  "canonical_hash": "sha256...",
  "validated_at": "...",
  "server_public_key": "...",
  "server_signature": "...",
  "certificate_chain": [...],
  "status": "active"
}
```

This is the URL embedded in badges so anyone can verify a validation.

### `GET /api/v1/validations/{validation_id}/badge.{json,svg}`

Return a generated badge. SVG version contains the score and validation ID.

### `GET /api/v1/validations/{validation_id}/certificate.pdf`

Return the official PDF certificate.

### Important: immutability on the server

- Validation records are **append-only**.
- No `DELETE /api/v1/validations/{id}` endpoint.
- If a validation must be revoked, use a **revocation list**: `POST /api/v1/validations/{id}/revoke` (admin only) creates a signed revocation record. Verifiers check the revocation list.
- Database should have row-level security / audit triggers matching the existing `user_audit_logs` and `api_key_usage_logs` tables (per `server_auth_system.md` memory).

## Badge & certificate formats

### Badge JSON (`wafpass-badge-<hash>.json`)

```json
{
  "schema_version": "1.0",
  "kind": "wafpass-official-validation",
  "status": "official",
  "score": 87,
  "project": "my-infra",
  "branch": "main",
  "git_sha": "abc1234",
  "canonical_hash": "sha256...",
  "validation_id": "uuid",
  "validated_at": "2026-08-16T12:00:00Z",
  "badge_url": "https://wafpass.waf2p.dev/api/v1/validations/uuid/badge.svg",
  "verification_url": "https://wafpass.waf2p.dev/api/v1/validations/uuid/verify",
  "svg": "<svg>...</svg>"
}
```

### Badge SVG

A compact SVG with:
- WAF++ logo
- "Validated" / "Offline" status
- Score
- Short validation ID / hash
- Verification URL as a link

### Certificate PDF

A one-page PDF certificate containing:
- WAF++ header and validation title
- Project, branch, git SHA
- Score and pillar scores
- Canonical hash
- Validation ID and timestamp
- QR code linking to `verification_url`
- Statement: "This run was validated by WAF++ officials and is cryptographically bound to the above hash."
- Signature block: local signature, server signature, certificate chain fingerprints
- Revocation-check URL

Use the existing `wafpass/pdf_reporter.py` infrastructure; add a new renderer `generate_validation_certificate(envelope, path)`.

## Offline fallback details

When `--validate official` is requested but the server is unreachable:

1. If `--skip-validation-on-offline` is set, automatically fall back to offline mode.
2. Otherwise, fail with a clear error:
   ```
   ERROR: Official validation requires internet access to the WAF++ central server.
   Re-run with --validate offline to create a self-signed interim proof,
   or with --skip-validation-on-offline to auto-fallback.
   ```

The offline envelope contains:
- Local attestation (organization-signed run hash).
- `status: "offline"`.
- `server_validation: null`.
- `pending_upgrade: true`.

Later, `wafpass validate upgrade --envelope <file>`:
1. Reads the offline envelope.
2. Sends the result + attestation to the server.
3. Receives the server countersignature.
4. Rewrites the envelope with `status: "official"`.
5. Generates official badge and certificate.
6. Locks the local run.

## Security hardening

### Key management

- Local keys are Ed25519, stored PEM-encoded with `chmod 600`.
- Server intermediate key should be in a KMS/HSM (AWS KMS, HashiCorp Vault, Google Cloud KMS).
- Root key is offline; only used to sign/re-sign the intermediate certificate on rotation.
- Publish root public key in the WAF++ documentation and hard-code a fingerprint in the CLI for verification.

### Replay / fake protection

- Each server signature includes the unique `validation_id` and `validated_at` timestamp, so a signature cannot be replayed for a different run.
- The run hash binds every finding, score, and metadata field, so changing any detail breaks verification.
- The local signature binds the run to the submitting organization’s public key.
- The server verifies the local signature before countersigning, preventing submission of unsigned or wrongly signed runs.

### Time and revocation

- Validation records carry `validated_at` and optional `expires_at`.
- Maintain a signed revocation list at a well-known URL (e.g., `/api/v1/revocations`).
- Verifiers check the revocation list (with caching and TTL).

### Transport

- All server communication uses HTTPS with certificate pinning or at least strict TLS verification (no `--no-verify` for validation endpoints).
- API keys or JWT required for submission; public endpoints are read-only.

## Files to modify / create

### In this repo (`pass`)

| File | Change |
|------|--------|
| `pyproject.toml` | Add `cryptography>=42.0` dependency. |
| `wafpass/schema.py` | Add `LocalAttestationSchema`, `ServerValidationSchema`, `ValidationEnvelopeSchema`; add `attestation` field to `WafpassResultSchema`. |
| `wafpass/attestation.py` | **New module.** Key generation, canonicalization, hashing, signing, verification, chain validation. |
| `wafpass/runner.py` | Optionally sign the result when `ScanConfig.signing_key` is set. |
| `wafpass/models.py` | Add optional attestation to internal `Report` if needed for local state. |
| `wafpass/state.py` | Add `validated` / `validation_id` to index entries; implement `lock_run` / `is_locked`. |
| `wafpass/cli.py` | Add `--validate`, `--validation-key`, `--validation-output`, `--skip-validation-on-offline` flags; add `wafpass validate` command group; add `wafpass verify`. |
| `wafpass/pdf_reporter.py` | Add `generate_validation_certificate()` renderer. |
| `wafpass/badge.py` | **New module.** SVG/JSON badge generation. |
| `tests/test_attestation.py` | **New tests.** Hash canonicalization, sign/verify round-trip, offline/official flows. |
| `tests/test_state_lock.py` | **New tests.** Run locking behavior. |
| `README.md` / `TECH.md` | Document validation workflow, key management, verification, and server API. |

### In `wafpass-server` repo (referenced, not in this filesystem)

| Component | Change |
|-----------|--------|
| Database migrations | New `validations` table + `validation_revocations` table. |
| `models/validation.py` | SQLAlchemy models. |
| `api/v1/validations.py` | FastAPI router for `POST`, `GET`, `verify`, `badge`, `certificate`. |
| `services/validation.py` | Canonical hash recompute, signature verification, countersigning. |
| `crypto/kms.py` | KMS/HSM integration for server intermediate key. |
| `crypto/root.py` | Root certificate loading / public key publication. |
| Background job | Periodic revocation list signing and publishing. |

## Implementation phases

### Phase 1 — Cryptographic primitives (this repo)

- `wafpass/attestation.py`
- Schema additions
- Unit tests for canonicalization, signing, verification, certificate chain

### Phase 2 — CLI integration (this repo)

- `wafpass check --validate official|offline`
- `wafpass validate` subcommands
- `wafpass verify`
- Local key generation

### Phase 3 — Local locking & state (this repo)

- `wafpass/state.py` lock logic
- Prevent overwrite/deletion of validated runs
- Map run entries to validation envelopes

### Phase 4 — Badge & certificate (this repo)

- `wafpass/badge.py`
- SVG badge renderer
- PDF certificate renderer

### Phase 5 — Central server (separate `wafpass-server` repo)

- Database models
- `/api/v1/validations` endpoints
- KMS countersigning
- Revocation list
- Public verification/badge endpoints

### Phase 6 — Integration & documentation

- End-to-end test: CLI run → official validation → verify locally and via server URL
- README / TECH.md updates
- Publish root public key and verification guide

## Risks & decisions to confirm

1. **KMS choice**: Do you already have a preferred HSM/KMS provider (AWS KMS, Vault, Google Cloud KMS)? This affects the server-side implementation.
2. **Offline mode policy**: Should offline validations ever expire, or can they always be upgraded to official?
3. **Revocation model**: Who can revoke a validation? Admin-only via server dashboard, or also the submitting organization?
4. **Badge hosting**: Should badges be served by the central server only, or also embeddable as data-URI SVG in the CLI output?
5. **Scope of certificate content**: Should the PDF certificate include the full findings list, or only summary/score?
6. **Monetization gate**: Should validation require a paid subscription / license key from the start, or be free-tier limited?

## Suggested next step

Approve this plan, then begin **Phase 1** (cryptographic primitives) in this repo. I can implement `wafpass/attestation.py`, schema changes, and the first unit tests as a self-contained PR before touching the CLI or server.
