# WAF++ PASS — wafpass-core

**WAF++ PASS** (`wafpass-core` v1.0.0) is the compliance engine, CLI tool, and result schema contract for the [WAF++ framework](https://waf2p.dev).

It checks IaC (Infrastructure-as-Code) files against YAML control definitions and produces a structured compliance report. As of v1.0.0 it is the core library in a three-component monorepo:

| Component | Package | Description |
|-----------|---------|-------------|
| **`pass/`** | `wafpass-core` | Engine, CLI, IaC adapters, result schema ← **this module** |
| **`wafpass-server/`** | `wafpass-server` | FastAPI + PostgreSQL API for persisting scan results |
| **`wafpass-dashboard/`** | — (React) | Standalone dashboard consuming the server API |

Supported IaC frameworks are loaded as **plugins** — Terraform, AWS CDK (TypeScript), and Pulumi (Python) are fully implemented; Bicep is available as a stub ready for contribution.

> **BREAKING CHANGE:** The server API is now versioned under `/api/v1`. CLI commands that push to or read from `wafpass-server` have been updated to use `/api/v1/runs`, `/api/v1/controls`, `/api/v1/evidence`, etc. Update `WAFPASS_SERVER_URL` and any `--push` URLs accordingly.

## Installation

### Option A — GitHub release artifact (recommended for users)

Download the latest `.whl` from the [GitHub Releases page](https://github.com/WAF2p/pass/releases) and install it:

```bash
pip install wafpass_core-*.whl
# or with uv (recommended)
uv pip install wafpass_core-*.whl
```

### Option B — From source

```bash
git clone https://github.com/WAF2p/pass.git
cd pass

# Using uv (recommended)
uv pip install -e .

# Using pip
pip install -e .

# With PDF support
pip install -e ".[pdf]"

# With dev dependencies
pip install -e ".[dev]"
```

### macOS (Apple M-series)

```bash
brew install git python uv
git clone https://github.com/WAF2p/pass.git
cd pass
uv pip install -e .

# Verify
wafpass -V
```

> **Rosetta not required.** WAF++ PASS is pure Python and runs natively on arm64.

## Pre-commit hook

WAF++ PASS ships a pre-commit hook that runs `wafpass check` against staged IaC files before every commit — blocking non-compliant code before it enters git history.  The hook is stored in `hooks/` and works with the standard git CLI, VS Code, and IntelliJ / JetBrains IDEs without any IDE-specific setup.

### Install

```bash
# macOS / Linux / Git Bash
bash hooks/install.sh

# Windows PowerShell
.\hooks\install.ps1
```

That's it.  The installer symlinks `hooks/pre-commit` into `.git/hooks/pre-commit` and prints IDE-specific notes.

### What gets checked

On every `git commit` the hook detects staged IaC file types and runs the appropriate compliance checks:

| Staged files | Plugin |
|---|---|
| `*.tf`, `*.tfvars` | Terraform |
| `*.bicep` | Bicep |
| `*.ts` when `cdk.json` is present | CDK |
| `*.py` when `Pulumi.yaml` is present | Pulumi |

If staged files include `controls/*.yml`, those are validated with `wafpass control validate` as well.

When a check fails the commit is blocked and the hook prints:

```
[wafpass] compliance check FAILED.

  Options:
    • Fix the violations in your IaC code
    • Add a time-boxed waiver to risk_acceptance.yml
    • Bypass (not recommended): git commit --no-verify
```

### Configuration

Set any of these as environment variables or in `.env`:

| Variable | Default | Description |
|---|---|---|
| `WAFPASS_CONTROLS_DIR` | `controls` | Path to the controls directory |
| `WAFPASS_SEVERITY` | `high` | Minimum severity to enforce |
| `WAFPASS_FAIL_ON` | `fail` | `fail` / `skip` / `any` — when to exit non-zero |
| `WAFPASS_STRICT` | `0` | `1` = abort the commit when wafpass is not installed |

If `wafpass` is not found on `PATH` and `WAFPASS_STRICT` is `0` (the default), the hook prints a warning and lets the commit through.  This keeps the team unblocked during onboarding or on machines where wafpass is not yet installed.

### IDE notes

**VS Code** — the built-in Git integration runs `.git/hooks` automatically.  No extra configuration needed.

**IntelliJ / JetBrains IDEs** — git hooks are enabled by default (Settings → Version Control → Git → "Run Git hooks").  If wafpass is not found, go to Settings → Tools → Terminal, set the **Shell path** to your login shell (e.g. `/bin/zsh`), and restart the IDE so it inherits your full `PATH`.  Alternatively set `WAFPASS_STRICT=0` to make the hook advisory rather than blocking.

---

## Python library API

`wafpass-core` can be used as a library as well as a CLI:

```python
from wafpass import run_scan, WafpassResultSchema

result: WafpassResultSchema = run_scan(
    paths=["infra/"],
    controls_dir="controls/",
)

print(result.score)                        # overall compliance score (0–100)
print(result.pillar_scores)                # {"SEC": 90, "OPS": 75, ...}
print(result.model_dump_json(indent=2))    # wafpass-result.json payload

# Post to wafpass-server (or set WAFPASS_SERVER_URL=http://localhost:8000/api/v1/runs to push automatically)
import httpx
httpx.post("http://localhost:8000/api/v1/runs", content=result.model_dump_json(),
           headers={"Content-Type": "application/json"})
```

Public symbols exported from `wafpass`:

| Symbol | Type | Description |
|--------|------|-------------|
| `run_scan()` | function | Run a compliance scan, return `WafpassResultSchema` |
| `WafpassResultSchema` | Pydantic model | Top-level `wafpass-result.json` contract |
| `FindingSchema` | Pydantic model | Single finding within a result |
| `Report` | dataclass | Internal report (used by CLI, PDF reporter) |
| `IaCPlugin`, `IaCBlock`, `IaCState` | Protocol types | IaC adapter interfaces |

## Result schema

`wafpass-result.json` is the contract between `wafpass-core` and all consumers (CI pipelines, `wafpass-server`, dashboards). It is defined in `wafpass/schema.py` and is the **single source of truth** — never duplicated.

```json
{
  "schema_version": "1.1",
  "project":        "my-infra",
  "branch":         "main",
  "git_sha":        "abc1234",
  "triggered_by":   "github-actions",
  "iac_framework":  "terraform",
  "score":          82,
  "pillar_scores":  {"SEC": 90, "OPS": 75},
  "controls_loaded": 70,
  "controls_run":    65,
  "findings": [
    {
      "check_id":    "WAF-SEC-010-01",
      "control_id":  "WAF-SEC-010",
      "pillar":      "SEC",
      "severity":    "CRITICAL",
      "status":      "FAIL",
      "resource":    "aws_iam_account_password_policy.main",
      "message":     "mfa_delete is false",
      "remediation": "Set mfa_delete = true"
    }
  ]
}
```

Generate from the CLI:

```bash
wafpass check ./infra/ --output json > wafpass-result.json

# Enrich with VCS metadata before posting to the server
python - <<'EOF'
import json, subprocess, httpx

result = json.load(open("wafpass-result.json"))
result.update({
    "project":      "my-infra",
    "branch":       subprocess.check_output(["git","rev-parse","--abbrev-ref","HEAD"]).decode().strip(),
    "git_sha":      subprocess.check_output(["git","rev-parse","HEAD"]).decode().strip(),
    "triggered_by": "github-actions",
})
httpx.post("http://localhost:8000/api/v1/runs", json=result)
EOF
```

To let the dashboard render Local preview diffs for auto-fix, include source snapshots when you generate the result:

```bash
wafpass check ./infra/ --output json --upload-source > wafpass-result.json
```

## Controls directory setup

PASS reads controls from a local `controls/` directory. Controls are **not bundled** with the tool — they are published separately by the WAF++ framework and must be downloaded once before the first run.

If you run `wafpass check` without controls present, the tool will print step-by-step download instructions and exit with a helpful error.

**Option A — Download from the WAF++ website (no Git required):**

1. Visit **https://waf2p.dev/wafpass/** and click **"Download Controls"**
2. Unzip the archive and copy the YAML files into your controls directory:

```bash
cp /path/to/download/*.yml controls/
```

**Option B — Clone the framework repository:**

```bash
git clone https://github.com/WAF2p/framework.git
cp framework/modules/controls/controls/*.yml controls/
```

Then run `wafpass check` as normal. Use `--controls-dir /path/to/controls` if your controls live outside the project root.

## Authentication (`wafpass login`)

WAF++ PASS can push scan results directly to a `wafpass-server` instance. Log in once to store a session token — subsequent `wafpass check --push @` calls use it automatically.

```bash
# Log in and store session (tokens saved to ~/.wafpass/credentials.json, chmod 600)
wafpass login https://wafpass.example.com

# Show the stored session
wafpass whoami

# Revoke session (local + server-side)
wafpass logout
```

Credentials file: `~/.wafpass/credentials.json`. Only JWT tokens are stored — the password is **never** written to disk. The access token is auto-refreshed when expired (30-second grace window).

```bash
# Push scan results using stored credentials
wafpass check ./infra/ --push @

# Push to an explicit URL with an API key (no login required)
wafpass check ./infra/ --output json --push http://localhost:8000/api/v1/runs --api-key $WAFPASS_API_KEY

# Upload source snapshots so the dashboard can render Local preview diffs
wafpass check ./infra/ --output json --push @ --upload-source

# Auto-push via environment variable (equivalent to --push URL)
WAFPASS_SERVER_URL=http://localhost:8000/api/v1/runs wafpass check ./infra/
```

> **Dashboard auto-fix / Local preview:** The dashboard can show git-style diffs for auto-fix suggestions only when the run includes the original source files for the selected IaC plugin (e.g. `.tf`, `.ts`, or `.py`). Add `--upload-source` whenever you push results that will be reviewed in the dashboard's **Auto-Fix** page. Requires `--output json` and `--push`.

---

## Evidence commands (`wafpass evidence`)

Lock server-side run snapshots as cryptographically-signed, immutable audit packages.

```bash
# Lock a run as an evidence package
wafpass evidence lock \
  --run-id <uuid> \
  --title "Q1 2026 SOC2 Evidence" \
  --prepared-by "Jane Smith" \
  --organization "Acme Corp" \
  --audit-period "Q1 2026" \
  --frameworks "SOC2,ISO 27001"

# List locked evidence packages
wafpass evidence list
wafpass evidence list --project my-infra --limit 10

# Show evidence package details (includes SHA-256 hash and public URL)
wafpass evidence show <evidence-id>
wafpass evidence show <evidence-id> --hash   # print only the hash digest
```

Each locked package gets a SHA-256 hash of its canonical snapshot and a unique public token. Auditors access the frozen HTML report at `/api/v1/evidence/p/{token}` — no login required.

---

## Usage

```bash
# Check all controls against a Terraform directory (default plugin)
wafpass check ./infra/

# Explicitly select the Terraform plugin
wafpass check ./infra/ --iac terraform

# Check a CDK project (reads cdk.out/*.template.json)
wafpass check ./my-cdk-app/ --iac cdk

# Multi-cloud: scan multiple folders and merge into a single report
wafpass check ./aws ./azure ./gcp

# Filter by pillar
wafpass check ./infra/ --pillar cost

# Run specific controls only
wafpass check ./infra/ --controls WAF-COST-010,WAF-COST-020

# Filter by minimum severity and show all results
wafpass check ./infra/ --severity high --verbose

# Exit non-zero if any check is skipped (strictest mode)
wafpass check ./infra/ --fail-on any

# Use a custom controls directory
wafpass check ./infra/ --controls-dir /path/to/controls

# Show only the summary table
wafpass check ./infra/ --summary

# Generate a PDF report (includes carbon footprint automatically)
wafpass check ./aws ./azure --output pdf --pdf-out report.pdf

# PDF + blast radius + secret scan
wafpass check ./infra/ --output pdf --pdf-out report.pdf --blast-radius

# Disable hardcoded-secret scanning
wafpass check ./infra/ --no-secrets

# Print version
wafpass --version

# Auto-fix failing checks (dry-run by default)
wafpass fix ./infra/
wafpass fix ./infra/ --apply

# Web UI server management
wafpass ui start
wafpass ui status
wafpass ui stop
```

### PDF report structure

The PDF report is divided into five parts plus an appendix, each introduced by a coloured divider page that identifies the intended audience:

| Part | Title | Audience | Sections |
|------|-------|----------|----------|
| **I** | Security Alerts | DevSecOps · Engineering Leads | Hardcoded Secrets (if any) |
| **II** | Executive Briefing | C-Suite · Board · Sponsors | Decision Brief, Change Tracking |
| **III** | Risk & Sustainability | CISO · CTO · CFO · ESG Team | Risk Dashboard, Carbon Footprint, Data Geography |
| **IV** | Technical Deep Dive | Architects · Senior Engineers | Root Cause, Blast Radius, Summary, Regulatory Alignment |
| **V** | Remediation | Engineering · DevOps | Roadmap, Detailed Findings |
| **APP** | Appendix | Auditors · GRC · Legal | Controls Inventory, Passed & Skipped, Risk Acceptance Register |

### Multi-cloud / multi-path scanning

Pass multiple paths to `check` to scan IaC code spread across separate folders (e.g. one per cloud provider) and get a single unified report:

```bash
wafpass check ./infra/aws ./infra/azure ./infra/gcp
```

Each path is parsed independently; resources, providers, and detected regions are merged before controls are evaluated. All other flags (`--pillar`, `--fail-on`, `--output`, etc.) apply to the merged result as usual. When multiple paths are provided, the tool prints a `Scanning [terraform]: <path>` line for each one so progress is visible in CI logs.

A typical multi-cloud repository layout:

```
infra/
├── aws/
│   ├── main.tf
│   └── variables.tf
├── azure/
│   ├── main.tf
│   └── variables.tf
└── gcp/
    ├── main.tf
    └── variables.tf
```

```bash
wafpass check infra/aws infra/azure infra/gcp --fail-on fail
```

---

## IaC plugin system

WAF++ PASS uses a plugin architecture so that different IaC frameworks can be supported without changing the core engine or the YAML control definitions.

### Available plugins

| Plugin | `--iac` flag | File type | Status |
|--------|-------------|-----------|--------|
| Terraform | `terraform` (default) | `*.tf` | Fully implemented |
| AWS CDK | `cdk` | `*.ts` (source) / `cdk.out/*.template.json` (synthesized) | Fully implemented |
| Pulumi | `pulumi` | `*.py` | Fully implemented |
| Bicep | `bicep` | `*.bicep` | Stub – not yet implemented |

Stub plugins register themselves in the global registry and log a clear warning when invoked, but return an empty state. They serve as the integration skeleton for contributors.

### Selecting a plugin

```bash
# Default (Terraform)
wafpass check ./infra/

# Explicit plugin selection
wafpass check ./cdk-app/ --iac cdk
wafpass check ./bicep-modules/ --iac bicep
wafpass check ./pulumi-app/ --iac pulumi
```

### How plugins work

Every plugin is a Python class that satisfies the `IaCPlugin` protocol:

```python
class IaCPlugin(Protocol):
    name: str                    # e.g. "terraform"
    file_extensions: list[str]   # e.g. [".tf"]

    def can_parse(self, path: Path) -> bool: ...
    def parse(self, path: Path) -> IaCState: ...
    def extract_regions(self, state: IaCState) -> list[tuple[str, str]]: ...
```

`parse()` returns an `IaCState` — a framework-agnostic bag of `IaCBlock` objects (resources, providers, variables, modules, config blocks). The assertion engine operates exclusively on `IaCState`, so adding a new plugin does not require touching the engine, controls, or reporters.

### Writing a new plugin

1. Create `wafpass/iac/plugins/myframework.py`:

```python
from pathlib import Path
from wafpass.iac.base import IaCBlock, IaCPlugin, IaCState
from wafpass.iac.registry import registry

class MyFrameworkPlugin:
    name = "myframework"
    file_extensions = [".mf"]

    def can_parse(self, path: Path) -> bool:
        return path.is_dir() and any(path.rglob("*.mf"))

    def parse(self, path: Path) -> IaCState:
        state = IaCState()
        # … parse files and append IaCBlock objects to state.resources etc. …
        return state

    def extract_regions(self, state: IaCState) -> list[tuple[str, str]]:
        # … return [(region_name, provider_name), …] …
        return []

registry.register(MyFrameworkPlugin())
```

2. Add an import to `wafpass/iac/plugins/__init__.py`:

```python
from wafpass.iac.plugins import myframework  # noqa: F401
```

3. Write WAF++ controls with `engine: myframework` in the YAML `checks:` section.

### IaCState and IaCBlock

| Field | Description |
|-------|-------------|
| `IaCState.resources` | All resource declarations |
| `IaCState.providers` | Cloud provider configuration blocks |
| `IaCState.variables` | Input variable declarations |
| `IaCState.modules` | Module references |
| `IaCState.config_blocks` | Framework-level config (`terraform {}`, target scope, stack config, …) |

Each `IaCBlock` carries:
- `block_type` — `"resource"`, `"provider"`, `"variable"`, `"module"`, `"config"`, …
- `type` — resource type string (e.g. `"aws_s3_bucket"`, `"AWS::S3::Bucket"`)
- `name` — logical name within the IaC source
- `address` — fully-qualified address (e.g. `"aws_s3_bucket.example"`)
- `attributes` — dict of configuration attributes (what assertions are evaluated against)
- `raw` — original parsed representation (plugin-specific)

### Controls and the `engine` field

Each check in a WAF++ control YAML declares which engine it targets:

```yaml
checks:
  - id: "waf-cost-010.tf.aws.compute-mandatory-tags"
    engine: "terraform"        # ← only evaluated when --iac terraform
    provider: "aws"
    …
```

When you run `wafpass check --iac cdk`, only checks with `engine: cdk` are evaluated; Terraform-specific checks are silently skipped. This lets a single control file hold checks for multiple frameworks side by side.

### CDK plugin

The CDK plugin parses synthesised CloudFormation templates (`cdk.out/*.template.json`) produced by `cdk synth`.  It does not require the CDK CLI at runtime — only the JSON output.

**What is parsed**

| CloudFormation section | Maps to |
|------------------------|---------|
| `Resources` | `IaCBlock(block_type="resource", type="AWS::S3::Bucket", …)` |
| `Parameters` | `IaCBlock(block_type="variable")` |
| `manifest.json` | `IaCBlock(block_type="manifest")` — used for region extraction |

**Attribute normalisation** applied before assertions run:

| Resource type | Normalisation |
|---|---|
| All | Tags array `[{"Key":…,"Value":…}]` → plain dict |
| `AWS::S3::Bucket` | `_EncryptionAlgorithm`, `_EncryptionKeyId`, `_VersioningStatus`, `_HasLifecycleRules` added as top-level attributes |
| `AWS::IAM::Role/Policy` | `_HasWildcardActions`, `_HasWildcardResources` (bool) derived from inline policy statements |
| `AWS::KMS::Key` | `deletion_window_in_days` alias added for `PendingWindowInDays` |
| `AWS::RDS::DBInstance/Cluster` | PascalCase properties kept as-is (`MultiAZ`, `StorageEncrypted`, `BackupRetentionPeriod`) |

**Region detection** reads `aws://ACCOUNT/REGION` environment strings from `cdk.out/manifest.json`.

**CDK checks shipped with WAF++ controls**

| Control | Check | What it verifies |
|---------|-------|-----------------|
| WAF-COST-010 | `waf-cost-010.cdk.aws.resource-mandatory-tags` | All 4 cost tags on S3/RDS/EC2/Lambda/ECS |
| WAF-COST-040 | `waf-cost-040.cdk.aws.s3-lifecycle-rules-defined` | `_HasLifecycleRules = true` |
| WAF-SOV-030 | `waf-sov-030.cdk.aws.s3-versioning-enabled` | `_VersioningStatus = "Enabled"` |
| WAF-SOV-030 | `waf-sov-030.cdk.aws.rds-backup-retention` | `BackupRetentionPeriod >= 7` |
| WAF-SOV-050 | `waf-sov-050.cdk.aws.kms-key-rotation-enabled` | `EnableKeyRotation = true` |
| WAF-SOV-050 | `waf-sov-050.cdk.aws.s3-kms-encryption` | `_EncryptionAlgorithm = "aws:kms"` + CMK set |
| WAF-SOV-050 | `waf-sov-050.cdk.aws.rds-storage-encrypted` | `StorageEncrypted = true` |
| WAF-REL-010 | `waf-rel-010.cdk.aws.rds-multi-az` | `MultiAZ = true` |
| WAF-REL-010 | `waf-rel-010.cdk.aws.rds-automated-backups` | `BackupRetentionPeriod >= 1` |

**CDK dummy project**

A ready-to-use dummy CDK project lives at `../dummy_cdk/` (relative to this repo), mirroring the Terraform demo code in `../dummy_code/`.

```
dummy_cdk/
├── bin/app.ts                              # CDK app entry point (eu-central-1)
├── lib/wafpp-demo-stack.ts                 # TypeScript stack source with PASS/FAIL annotations
├── cdk.out/
│   ├── WafppDemoStack.template.json        # Synthesised CloudFormation — the plugin's parse target
│   └── manifest.json                       # Stack environment (region) metadata
├── cdk.json
└── package.json
```

The template intentionally contains both **compliant** and **non-compliant** resources so every result state (PASS / FAIL / SKIP) is exercised:

| Resource | Controls hit | Expected result |
|----------|-------------|-----------------|
| `DataLakeBucket` | WAF-COST-010, WAF-COST-040, WAF-SOV-030, WAF-SOV-050 | PASS |
| `LogsRawBucket` | WAF-COST-010, WAF-COST-040, WAF-SOV-030, WAF-SOV-050 | FAIL |
| `SovereignCmk` | WAF-SOV-050 | PASS |
| `MainDb` | WAF-COST-010, WAF-SOV-030, WAF-SOV-050, WAF-REL-010 | PASS |
| `SingleAzDb` | WAF-COST-010, WAF-SOV-030, WAF-REL-010 | FAIL |

```bash
# Run the CDK plugin against the demo project
wafpass check ../dummy_cdk --iac cdk --verbose

# Summary only
wafpass check ../dummy_cdk --iac cdk --summary

# Filter to the 5 controls that have CDK checks
wafpass check ../dummy_cdk --iac cdk \
  --controls WAF-COST-010,WAF-COST-040,WAF-SOV-030,WAF-SOV-050,WAF-REL-010 \
  --verbose
```

---

## Intentional waivers (skipping controls on purpose)

Some controls may not apply to your setup, or you may have accepted the risk through an alternative compensating control. PASS lets you explicitly waive controls with a written justification so that:

- The control is shown as **WAIVED** (○) instead of FAIL or SKIP.
- The waiver reason is recorded in both the console output and the PDF report.
- Waived controls **never** cause a non-zero exit code, so CI pipelines are not blocked.
- Expired waivers trigger a warning, prompting the team to revisit the accepted risk.

### Waiver file format

Create a `.wafpass-skip.yml` file (auto-discovered in the current directory, or specify a path with `--skip-file`):

```yaml
# .wafpass-skip.yml
waivers:
  - id: WAF-SEC-020
    reason: "Handled by quarterly external IAM review — tracked in SEC-1234"
    expires: "2026-09-30"   # optional ISO-8601 date; triggers a warning when past

  - id: WAF-COST-010
    reason: "Cost tagging enforced at the Terraform module level, not individual resources"

  - id: WAF-SOV-030
    reason: "Sovereign data residency confirmed via contractual DPA with cloud provider"
    expires: "2027-01-01"
```

Each entry requires:
- `id` — the WAF++ control ID (e.g. `WAF-SEC-020`)
- `reason` — a mandatory plain-text justification

And optionally:
- `expires` — ISO-8601 date (`YYYY-MM-DD`); once past, a warning is printed but the waiver is still applied

### Using waivers

```bash
# Auto-discovery: place .wafpass-skip.yml in the current directory
wafpass check ./infra/

# Explicit path
wafpass check ./infra/ --skip-file ./compliance/accepted-risks.yml

# Works with multi-cloud paths too
wafpass check ./aws ./azure --skip-file ./accepted-risks.yml
```

Console output shows the waiver reason inline:

```
 WAF-SEC-020  Least Privilege & RBAC  [CRITICAL]  ○
  ○ WAIVED  Handled by quarterly external IAM review — tracked in SEC-1234
```

The summary line includes the WAIVED count:

```
  Summary   Controls: 70   ✓ PASS: 5   ✗ FAIL: 2   ─ SKIP: 61   ○ WAIVED: 2
```

The PDF report includes a **Waived Controls** table (purple header) listing every waived control and its recorded justification.

### Waivers and CI/CD

Waivers are safe to use in pipelines. A `WAIVED` control never increments `total_fail` or `total_skip`, so it cannot trigger a non-zero exit code regardless of the `--fail-on` mode. This means you can block a pipeline on real failures while allowing acknowledged exceptions to pass through.

If a waiver has expired, the tool prints a warning to stderr but continues normally — a deliberate choice so pipelines do not break unexpectedly. The intent is to prompt a human review, not an automated failure.

```yaml
# GitHub Actions: block on failures, allow waivers
- name: Run WAF++ PASS
  run: wafpass check ./infra/ --skip-file compliance/accepted-risks.yml --fail-on fail
```

---

## Risk acceptance register

Waivers are a lightweight in-line mechanism for skipping controls. **Risk acceptances** are the formal, auditable counterpart — they record *who* approved a risk, *why*, what ticket or RFC covers it, the residual risk level, and when the acceptance expires.

Risk acceptances differ from waivers in two ways:

- They carry richer governance metadata (approver, RFC, Jira link, residual risk, accepted date).
- They are rendered as a dedicated **Risk Acceptance Register** one-pager in the PDF report — suitable for auditor handover — including a sign-off block with CISO and approver lines.

### `risk_acceptance.yml`

Drop a `risk_acceptance.yml` file in the directory you pass to `wafpass check`. PASS auto-discovers it before falling back to `.wafpass-skip.yml`.

```yaml
# risk_acceptance.yml
waivers:
  - id: WAF-SEC-020
    reason: >
      Covered by external quarterly IAM review — approved via ticket SEC-1234
      on 2026-03-01. Internal review scheduled for Q3 2026.
    expires: "2026-09-30"

  - id: WAF-COST-010
    reason: >
      Cost tagging is enforced at the Terraform module level via a shared
      locals block; individual resource-level tags are therefore redundant.
      Approved by Platform Lead on 2026-01-15 (ticket PLAT-0042).
```

Each entry requires `id` and `reason`. `expires` is optional (ISO-8601); expired entries trigger a CLI warning and are flagged in the PDF.

```bash
# Auto-discovery: place risk_acceptance.yml in the current directory
wafpass check ./infra/

# Explicit path
wafpass check ./infra/ --skip-file ./compliance/risk_acceptance.yml
```

### PDF Risk Acceptance Register

When a `risk_acceptance.yml` is present, the Appendix of the PDF report gains a **Risk Acceptance Register** section containing:

- A KPI banner: total / active / expiring within 30 days / expired counts
- A full register table: Control ID · Title · Pillar · Severity · Justification · Expiry · Status (colour-coded ACTIVE / EXPIRES SOON / EXPIRED / PERMANENT)
- A printable sign-off block with CISO and Approver signature lines

### Web UI

The **Risk Acceptance** page in the web UI (`#risk-acceptance`) provides a full CRUD interface for acceptances with richer fields (approver, owner, RFC, Jira link, risk treatment, residual risk, accepted date). Entries are stored in `serve/risk_acceptances.yml` and applied automatically on every scan.

---

## Auto-fix (`wafpass fix`)

`wafpass fix` analyses your IaC files, determines which failing assertions can be patched automatically, and either previews a coloured diff or writes the changes to disk.

### How it works

The engine:

1. Runs the same check pipeline as `wafpass check`.
2. Builds a framework-specific `ResourceLocator` that scans the plugin's file extensions (e.g. `.tf`, `.ts`, `.py`) and maps resources back to their source files.
3. For each failing assertion derives the minimum change needed — e.g. `is_true → true`, `equals 14 → 14`, `in ["AES256","aws:kms"] → "AES256"`.
4. Deduplicates patches by `(file, address, attribute)` so the same attribute is never written twice.
5. Guards against overwriting dynamic expressions (`var.`, `local.`, `${…}`, `merge(…)`, etc.) — those lines are left untouched.

**Dry-run is the default.** Pass `--apply` to write changes.

### Usage

```bash
# Preview what would change (dry-run)
wafpass fix ./infra/

# Apply patches and create .bak backups
wafpass fix ./infra/ --apply

# Apply without backups
wafpass fix ./infra/ --apply --no-backup

# Scope to a single pillar
wafpass fix ./infra/ --pillar security

# Scope to specific controls
wafpass fix ./infra/ --controls WAF-SEC-010,WAF-REL-030

# Fix only high-severity and above
wafpass fix ./infra/ --severity high --apply
```

### What can be auto-fixed

| Operator | Example fix |
|----------|-------------|
| `is_true` | `require_symbols = false` → `true` |
| `is_false` | `publicly_accessible = true` → `false` |
| `equals` | `minimum_password_length = 6` → `14` |
| `greater_than_or_equal` | `backup_retention_period = 1` → `7` |
| `less_than_or_equal` | `max_password_age = 365` → `90` |
| `in` | `sse_algorithm = "NONE"` → `"AES256"` |
| `key_exists` | adds `"Environment" = "TODO-fill-in"` to a `tags` block |

Operators that require judgement (`block_exists`, `not_contains`, `matches`, `has_associated_resource`, all runtime-state operators) are reported as **skipped** with a plain-English reason.

### Output

```
Dry-run — no files changed (pass --apply to write patches)

 security/iam.tf — aws_iam_account_password_policy.corporate
  ╔══ diff ════════════════════════════════════════╗
  ║ - minimum_password_length = 6                  ║
  ║ + minimum_password_length = 14                 ║
  ║ - require_symbols         = false              ║
  ║ + require_symbols         = true               ║
  ╚════════════════════════════════════════════════╝

Patches ready: 7  ·  Files affected: 1  ·  Skipped (manual fix needed): 3
```

After `--apply` the command re-runs the checks and reports a **delta**: how many previously failing checks are now passing.

### Safety

- `.bak` backups are created by default (disable with `--no-backup`).
- Dynamic references are never overwritten.
- Each `(file, address, attribute)` triple is patched at most once.
- The command exits non-zero if any failing check remains after apply.

---

## Hardcoded secret detection

WAF++ PASS scans your IaC source files for hardcoded credentials **before** evaluating controls. Findings are printed prominently to the console and included as the first section of the PDF report.

The scanner is **enabled by default** on every `wafpass check` run. Disable it with `--no-secrets` if needed.

### What is detected

| Category | Example attribute names matched |
|---|---|
| Passwords | `password`, `passwd`, `db_password`, `MASTER_PASSWORD`, … |
| Secrets | `secret`, `client_secret`, `APP_SECRET`, … |
| API keys | `api_key`, `apikey`, `SUBSCRIPTION_KEY`, … |
| Tokens | `token`, `auth_token`, `SLACK_BOT_TOKEN`, `GITHUB_TOKEN`, … |
| Access keys | `access_key`, `access_key_id`, `AWS_ACCESS_KEY_ID`, … |
| Secret keys | `secret_key`, `secret_access_key`, `AWS_SECRET_ACCESS_KEY`, … |
| Private keys | `private_key`, `rsa_private_key`, `TLS_PRIVATE_KEY`, … |
| Connection strings | `connection_string`, `database_url`, `POSTGRES_URL`, … |
| AWS AKIA key IDs | Any value matching `AKIA[A-Z0-9]{16}` |
| PEM private key blocks | `-----BEGIN … PRIVATE KEY-----` |

Compound underscore-delimited key names (e.g. `SLACK_BOT_TOKEN`, `DB_MASTER_PASSWORD`) are matched regardless of casing.

### What is NOT flagged (safe values)

The scanner skips values that are clearly IaC references or placeholders:

- Terraform variable references: `var.db_password`, `${var.secret}`
- Data source references: `data.aws_secretsmanager_secret_version.db.secret_string`
- Module outputs: `module.secrets.api_key`
- Vault / Key Vault / Secrets Manager paths (contain the words `vault`, `secretsmanager`, `keyvault`)
- Common placeholder strings: `REPLACE_…`, `YOUR_…`, `changeme`, `dummy`, `example`, `<YOUR_KEY>`, `****`, …

### Console output

When secrets are found, a red warning panel is printed to stderr **before** the main report:

```
╭──────────────────── ⚠  HARDCODED SECRETS DETECTED ─────────────────────╮
│  Severity  File : Line               Finding              Attribute       │
│  CRITICAL  providers.tf:35           Hardcoded access key access_key      │
│  CRITICAL  providers.tf:36           Hardcoded secret key secret_key      │
│  CRITICAL  database.tf:48            Hardcoded password   password        │
│  HIGH      monitoring.tf:39          Hardcoded token      SLACK_BOT_TOKEN │
╰─────────────────────────────────────────────────────────────────────────╯

4 hardcoded secret(s) found. These must be remediated before deployment.
```

Values are always **masked** in output (`Wafp********`) — the raw secret is never printed.

### PDF report

Secret findings appear in **Part I — Security Alerts** of the PDF report (first section after the table of contents), with:
- A severity KPI strip (Critical / High / Medium / Suppressed counts)
- A findings table with file path, line number, matched attribute, and masked value
- Inline remediation guidance for AWS, Azure, GCP, and HashiCorp Vault

### How to fix

Instead of hardcoding credentials, reference a managed secret:

```hcl
# ✗ Before — hardcoded
password = "Wafpp@Postgres2024!"

# ✓ After — AWS Secrets Manager
password = data.aws_secretsmanager_secret_version.db.secret_string

# ✓ After — AWS SSM Parameter Store
password = data.aws_ssm_parameter.db_password.value

# ✓ After — Terraform variable (pass value via TF_VAR_db_password env var)
variable "db_password" {}
password = var.db_password

# ✓ After — Azure Key Vault
password = "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/db-pass)"

# ✓ After — HashiCorp Vault
password = data.vault_generic_secret.db.data["password"]
```

### Suppressing a finding

If a value is intentionally non-sensitive (e.g. a known-public test credential or a CI seed value), suppress the finding on that line with an inline comment:

```hcl
password = "ci-seed-only-not-real"  # wafpass:ignore-secret  reason: non-sensitive CI seed value
```

Suppressed findings are excluded from the console output and counted separately in the PDF report. Use sparingly — every suppression should include a `reason`.

### CLI flag

```bash
# Run with secret scanning (default)
wafpass check ./infra/

# Disable secret scanning
wafpass check ./infra/ --no-secrets
```

---

## Run versioning & change tracking

WAF++ PASS automatically records every run as a versioned JSON snapshot in a local state directory (default: `.wafpass-state/`). On subsequent runs, changes in control status are detected and shown in the console report and the PDF.

### State directory layout

```
.wafpass-state/
  index.json          ← lightweight index of all runs (machine-readable)
  runs/
    run-20260321-152251-a1e136bd.json   ← full snapshot per run
    run-20260321-160000-def67890.json
    …
```

### Snapshot content

Each run file is a self-contained JSON document:

```json
{
  "schema_version": 1,
  "run_id": "20260321-152251-a1e136bd",
  "generated_at": "2026-03-21T15:22:51+00:00",
  "tool_version": "0.3.0",
  "iac_plugin": "terraform",
  "source_paths": ["./infra"],
  "score": 45,
  "totals": { "controls_run": 70, "pass": 55, "fail": 10, "skip": 5, "waived": 0 },
  "pillar_scores": { "cost": 20, "security": 60, "sovereign": 0 },
  "control_statuses": { "WAF-COST-010": "PASS", "WAF-SEC-020": "FAIL" },
  "control_details": { "WAF-COST-010": { "status": "PASS", "severity": "high", … } },
  "diff_from_previous": {
    "previous_run_id": "…",
    "score_delta": 5,
    "regressions": [{ "control_id": "WAF-SEC-020", "from": "PASS", "to": "FAIL", … }],
    "improvements": [],
    "other_changes": []
  }
}
```

### Console output — Changes section

After each run (when a previous run exists), the console shows a **Changes from Previous Run** section:

```
────────────────────────── Changes from Previous Run ───────────────────────────
  Previous run: 2026-03-20 10:00 UTC  (20260320-100000-abc12345)
  Risk score delta: +7 (worse)

  Regressions  (2 control(s) newly FAILED)
    ✗  WAF-COST-010  [HIGH]  PASS → FAIL  Cost Allocation Tagging Enforced
    ✗  WAF-SEC-020   [CRITICAL]  PASS → FAIL  Encryption at Rest

  Improvements  (1 control(s) left FAIL)
    ✓  WAF-COST-030  [MEDIUM]  FAIL → PASS  Budget Alerts Configured
────────────────────────────────────────────────────────────────────────────────
```

The same information appears as a dedicated **Run Change Tracking** page in PDF reports.

### State CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--state-dir PATH` | `.wafpass-state` | Directory for versioned state files |
| `--no-state` | off | Disable state saving and change tracking |

```bash
# Use a custom state directory (e.g. shared across teams via a mounted volume)
wafpass check ./infra/ --state-dir /var/wafpass-state

# Disable state tracking (useful for one-off ad-hoc runs)
wafpass check ./infra/ --no-state
```

---

## Monitoring & observability export plugins

WAF++ PASS ships a monitoring export plugin system that pushes run snapshots to external observability platforms after every check. This feeds dashboards, alerts, and time-series trend analysis without requiring a separate CI job.

### Quick start

```bash
# Push to Grafana via Prometheus Pushgateway
wafpass check ./infra/ --export grafana

# Push to multiple targets in one run
wafpass check ./infra/ --export grafana,slack,webhook
```

### Export config file

Create `.wafpass-export.yml` in your working directory (auto-discovered) or pass `--export-config`:

```yaml
# .wafpass-export.yml
exports:

  # ── Grafana via Prometheus Pushgateway (fully implemented) ─────────────────
  grafana:
    pushgateway_url: "http://pushgateway.monitoring.svc:9091"
    job: "wafpass"                    # Pushgateway job label (default: wafpass)
    instance: "my-project"            # Pushgateway instance label (default: run_id)
    # username: "12345"               # optional Basic Auth (Grafana Cloud proxy)
    # password: "${GRAFANA_CLOUD_TOKEN}"

  # ── Prometheus Pushgateway — standalone (stub, delegates to grafana plugin) ──
  prometheus:
    pushgateway_url: "http://pushgateway:9091"
    job: "wafpass"

  # ── Datadog Metrics API v2 (stub) ─────────────────────────────────────────
  datadog:
    api_key: "${DD_API_KEY}"
    site: "datadoghq.eu"              # or datadoghq.com

  # ── Splunk HTTP Event Collector (stub) ────────────────────────────────────
  splunk:
    hec_url: "https://splunk.example.com:8088/services/collector"
    token: "${SPLUNK_HEC_TOKEN}"
    index: "main"

  # ── Slack incoming webhook (stub) ─────────────────────────────────────────
  slack:
    webhook_url: "${SLACK_WEBHOOK_URL}"
    only_on_regression: true          # only post when new FAILs appear

  # ── Generic HTTP webhook (fully implemented) ──────────────────────────────
  webhook:
    url: "https://my-webhook.example.com/wafpass"
    headers:
      Authorization: "Bearer ${WEBHOOK_TOKEN}"
    include_full_snapshot: true       # false = lightweight summary only
```

Secret values may use `${ENV_VAR}` placeholders — they are expanded from the environment at runtime and never stored in state files.

### Available export plugins

| Plugin | `--export` name | Status | Description |
|--------|----------------|--------|-------------|
| Grafana (Pushgateway) | `grafana` | **Implemented** | Prometheus text format → Pushgateway |
| Prometheus Pushgateway | `prometheus` | Stub (delegates to grafana) | Direct Pushgateway without Grafana branding |
| Datadog | `datadog` | **Stub** | Datadog Metrics API v2 |
| Splunk | `splunk` | **Stub** | Splunk HTTP Event Collector |
| Slack | `slack` | **Stub** | Slack incoming webhook with Block Kit |
| Generic webhook | `webhook` | **Implemented** | POST JSON snapshot to any HTTP endpoint |

### Grafana setup — step-by-step

The full observability stack is three services: **Pushgateway** (receives metrics from WAF++ after each run), **Prometheus** (scrapes and stores them), **Grafana** (visualises them). Everything needed to spin them up is in the `docker/` folder.

```
docker/
  docker-compose.yml                         ← all three services, pre-wired
  prometheus.yml                             ← scrape config for the Pushgateway
  .wafpass-export.yml                        ← WAF++ export config pointing to localhost
  grafana-provisioning/
    datasources/prometheus.yml               ← auto-provisions Prometheus datasource
    dashboards/dashboard.yml                 ← auto-provisions the WAF++ dashboard
```

---

#### Option A — Docker Compose (quickest, everything local)

**Prerequisites:** Docker + Docker Compose installed.

**Step 1 — Start the stack**

```bash
cd docker/
docker compose up -d
```

Three containers start:

| Container | URL | Credentials |
|-----------|-----|-------------|
| Grafana | http://localhost:3000 | admin / wafpass |
| Prometheus | http://localhost:9090 | — |
| Pushgateway | http://localhost:9091 | — |

The WAF++ dashboard and Prometheus datasource are **auto-provisioned** — no manual import needed. Open http://localhost:3000 and navigate to **Dashboards → WAF++ PASS — Compliance Monitor**.

> **Note:** The dashboard uses HTML text panels to render the embedded WAF++ logo. The compose file sets `GF_PANELS_DISABLE_SANITIZE_HTML=true` to allow this. Remove that variable if you don't need the logo and want stricter HTML policy.

**Step 2 — Configure WAF++ to push metrics**

Copy the included export config to your project root (or use `--export-config`):

```bash
# From your IaC project directory:
cp /path/to/waf++/pass/docker/.wafpass-export.yml ./.wafpass-export.yml
```

The file points to `http://localhost:9091` (the Pushgateway from Step 1):

```yaml
# .wafpass-export.yml
exports:
  grafana:
    pushgateway_url: "http://localhost:9091"
    job: "wafpass"
```

**Step 3 — Run WAF++ and push your first metrics**

```bash
wafpass check ./infra/ --export grafana
```

You should see output like:

```
Run state saved: .wafpass-state/runs/run-20260321-152251-a1e136bd.json
Exporting to [grafana]...
  ✓ grafana: Pushed to Pushgateway: HTTP 200
```

**Step 4 — Open the dashboard**

Go to http://localhost:3000 → **Dashboards → WAF++ PASS — Compliance Monitor**.

The dashboard auto-refreshes every minute. Run WAF++ a few more times (against different fixture paths or after changing your IaC) to build up trend data:

```bash
# Non-compliant run
wafpass check tests/fixtures/non_compliant/ --export grafana

# Compliant run — watch the improvements appear
wafpass check tests/fixtures/compliant/ --export grafana
```

After two or more runs, the **Change Tracking** row shows regressions, improvements, and score delta. After several runs, the time-series charts show trends.

**Step 5 — Verify raw metrics (optional)**

Check that metrics arrived in the Pushgateway:

```
http://localhost:9091  →  "wafpass" job should appear
```

Check that Prometheus scraped them:

```
http://localhost:9090/graph  →  query: wafpass_score
```

---

#### Option B — Import the dashboard manually into an existing Grafana

If you already have Grafana + Prometheus + a Pushgateway running:

**Step 1 — Point WAF++ at your Pushgateway**

Create `.wafpass-export.yml` in your project root:

```yaml
exports:
  grafana:
    pushgateway_url: "http://<your-pushgateway-host>:9091"
    job: "wafpass"
```

**Step 2 — Verify Prometheus scrapes the Pushgateway**

In your `prometheus.yml` (or equivalent), add a scrape job if not already present:

```yaml
scrape_configs:
  - job_name: wafpass
    honor_labels: true          # ← required: preserves WAF++ label values
    static_configs:
      - targets:
          - <pushgateway-host>:9091
```

Reload Prometheus: `curl -X POST http://localhost:9090/-/reload`

**Step 3 — Import the dashboard**

1. Open Grafana → **Dashboards** (left sidebar) → **Import**
2. Click **Upload dashboard JSON file**
3. Select `assets/grafana-dashboard.json`
4. Under **Prometheus**, select your Prometheus datasource
5. Click **Import**

The dashboard opens immediately. Run `wafpass check ./infra/ --export grafana` to push the first data point.

> **Logo rendering:** The dashboard embeds the WAF++ logo as a base64 PNG in an HTML text panel. To display it, enable `GF_PANELS_DISABLE_SANITIZE_HTML=true` in Grafana's environment, or add `disable_sanitize_html = true` under `[panels]` in `grafana.ini`. Without this setting, the logo panel shows empty — all metric panels work regardless.

---

#### Option C — Grafana Cloud

Grafana Cloud's Prometheus endpoint requires binary `remote_write` format, which the WAF++ export plugin does not produce directly (to avoid heavy protobuf dependencies). The recommended path:

**Step 1 — Run a local Pushgateway**

```bash
docker run -d -p 9091:9091 prom/pushgateway:v1.9.0
```

**Step 2 — Install Grafana Alloy (or Grafana Agent)**

[Grafana Alloy](https://grafana.com/docs/alloy/latest/) is the current recommended agent. Add this scrape + remote_write config:

```alloy
prometheus.scrape "wafpass" {
  targets = [{"__address__" = "localhost:9091"}]
  honor_labels = true
  forward_to   = [prometheus.remote_write.grafana_cloud.receiver]
}

prometheus.remote_write "grafana_cloud" {
  endpoint {
    url = "https://prometheus-prod-XX-eu-west-X.grafana.net/api/prom/push"
    basic_auth {
      username = "<your-numeric-user-id>"
      password = env("GRAFANA_CLOUD_TOKEN")
    }
  }
}
```

**Step 3 — Push metrics and import dashboard**

```bash
wafpass check ./infra/ --export grafana
```

In Grafana Cloud: **Dashboards → Import → Upload JSON file** → select `assets/grafana-dashboard.json` → choose your Cloud Prometheus datasource.

---

#### Dashboard panels reference

| Panel | Type | What it shows |
|-------|------|----------------|
| Risk Score | Gauge (0–100) | Current weighted failure score — green below 20, red above 75 |
| PASS / FAIL / SKIP / WAIVED | Stat | Control counts for the latest run |
| Score Delta | Stat | Score change vs. previous run — red when positive (worse) |
| Regressions / Improvements | Stat | Controls newly FAILing or leaving FAIL this run |
| Last Run | Stat | Timestamp of the most recent push |
| Risk Score Over Time | Time series | Score trend across all runs |
| Controls by Status Over Time | Time series | PASS/FAIL/SKIP/WAIVED counts over time |
| Risk Score per Pillar | Bar gauge | Per-pillar score — identify which pillar is most at risk |
| Score Delta vs Previous Run | Time series | Run-to-run score change trend |
| Regressions & Improvements | Time series | How many controls changed state per run |
| Control Status (current) | Table | Every control: ID, severity, pillar, status — filterable |
| Checks by Status Over Time | Time series | Individual check counts (more granular than control counts) |

**Dashboard variables** (top of page, filter all panels simultaneously):

| Variable | Description |
|----------|-------------|
| Data Source | Switch between Prometheus instances |
| IaC Plugin | Filter to `terraform`, `cdk`, etc. |
| Source Path | Filter to a specific scanned directory |

---

#### Metrics reference

All metrics carry labels: `iac_plugin`, `run_id`, `tool_version`, `source`.

| Metric | Type | Description |
|--------|------|-------------|
| `wafpass_score` | gauge | Overall risk score (0 = fully compliant, 100 = all critical controls failing) |
| `wafpass_controls_total{status}` | gauge | Control count by `pass`, `fail`, `skip`, `waived` |
| `wafpass_checks_total{status}` | gauge | Individual check count by status |
| `wafpass_pillar_score{pillar}` | gauge | Risk score per WAF++ pillar |
| `wafpass_control_status{control_id,severity,pillar}` | gauge | Per-control numeric status: 0=PASS 1=FAIL 2=SKIP 3=WAIVED |
| `wafpass_score_delta` | gauge | Score change vs previous run (+ve = worse, −ve = improved) |
| `wafpass_regressions_total` | gauge | Controls newly entering FAIL this run |
| `wafpass_improvements_total` | gauge | Controls leaving FAIL this run |
| `wafpass_run_timestamp_seconds` | gauge | Unix timestamp of this run |

**Example alert rules:**

```promql
# Fire when any control newly fails
increase(wafpass_regressions_total[1h]) > 0

# Fire when overall risk score exceeds threshold
wafpass_score > 50

# Fire when a specific critical control fails
wafpass_control_status{control_id="WAF-SEC-020", severity="critical"} == 1
```

### Writing a new export plugin

1. Create `wafpass/export/plugins/mytool.py`:

```python
from wafpass.export.base import ExportPlugin, ExportResult
from wafpass.export.registry import registry

class MyToolPlugin:
    name = "mytool"
    description = "Push WAF++ metrics to MyTool."

    def export(self, snapshot: dict, config: dict) -> ExportResult:
        url = config.get("url") or ""
        if not url:
            return ExportResult(success=False, message="mytool: 'url' is required.")
        try:
            # … send snapshot to MyTool …
            return ExportResult(success=True, message="OK")
        except Exception as exc:
            return ExportResult(success=False, message=str(exc))

registry.register(MyToolPlugin())
```

2. Add an import to `wafpass/export/plugins/__init__.py`:

```python
from wafpass.export.plugins import mytool  # noqa: F401
```

3. Add a config block to `.wafpass-export.yml`:

```yaml
exports:
  mytool:
    url: "https://mytool.example.com/ingest"
```

4. Run:

```bash
wafpass check ./infra/ --export mytool
```

The `snapshot` dict passed to `export()` is the complete run snapshot from `wafpass.state.build_run_snapshot()` — see the schema in the **Run versioning** section above.

### CI/CD with export

```yaml
# GitHub Actions: push metrics to Grafana on every PR and main branch run
- name: Run WAF++ PASS + push to Grafana
  env:
    GRAFANA_CLOUD_TOKEN: ${{ secrets.GRAFANA_CLOUD_TOKEN }}
  run: |
    pip install -e .
    wafpass check ./infra/ \
      --fail-on fail \
      --export grafana \
      --export-config .wafpass-export.yml \
      --output pdf \
      --pdf-out wafpass-report.pdf
```

---

## Blast radius analysis

When a resource fails a control, other resources that *reference* it inherit part of that risk — this is the blast radius. Run `--blast-radius` to visualise the propagation:

```bash
wafpass check ./infra/ --blast-radius
wafpass check ./infra/ --blast-radius --blast-radius-out diagrams/blast.md
wafpass check ./infra/ --blast-radius --output pdf --pdf-out report.pdf
```

### How it works

1. **Reference extraction** — the scanner reads every Terraform `${resource_type.name.attr}` interpolation in attribute values to build a downstream dependency graph.
2. **BFS propagation** — starting from every resource that failed at least one control, a breadth-first search walks the graph and assigns each downstream resource a *hop distance*.
3. **Criticality labelling** — hop distance maps to an impact tier:

| Hop | Label | Meaning |
|-----|-------|---------|
| 0 | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` | Root cause — the resource itself failed a control; label = failing control severity |
| 1 | `HIGH` | Directly references a failing resource |
| 2 | `MEDIUM` | Two hops away |
| 3+ | `LOW` | Residual / tertiary exposure |

### Console output

A colour-coded Rich tree is printed after the main report:

```
🔴 aws_kms_key.main  [WAF-SEC-010]  CRITICAL
 └── 🟠 aws_db_instance.prod  HIGH
      └── 🟡 aws_lambda_function.api  MEDIUM

  🔴 CRITICAL  🟠 HIGH  🟡 MEDIUM  ⚪ LOW
```

### Mermaid diagram

A `blast_radius.md` file is written containing a `graph LR` Mermaid diagram with colour-coded nodes, renderable natively in GitHub, GitLab, and Notion:

```markdown
​```mermaid
graph LR
  aws_kms_key__main["aws_kms_key.main\nFAIL: WAF-SEC-010\nCRITICAL"]
  aws_db_instance__prod["aws_db_instance.prod\nHIGH"]
  aws_kms_key__main --> aws_db_instance__prod
  style aws_kms_key__main fill:#c0392b,stroke:#c0392b,color:#ffffff
  style aws_db_instance__prod fill:#e67e22,stroke:#e67e22,color:#ffffff
​```
```

### PDF report

When `--blast-radius` is combined with `--output pdf`, the PDF report includes a **Blast Radius Analysis** section with:
- KPI strip: root-cause resource count, downstream affected count, total impacted
- Root-cause resources table (with failed control IDs and severity)
- Downstream affected resources table (with hop distance and parent resources)

---

## Carbon footprint & sustainability

WAF++ PASS automatically estimates the monthly carbon footprint of your cloud infrastructure whenever a PDF report is generated (`--output pdf`). No extra flag is needed.

### How the estimate is calculated

1. **Resource inventory** — counts every resource type in the parsed IaC state (EC2, RDS, Lambda, S3, EKS, etc.).
2. **Power lookup** — maps each resource type to an estimated watt draw based on SPECpower benchmarks and the [Cloud Carbon Footprint](https://www.cloudcarbonfootprint.org/) project.
3. **Grid emission factor** — multiplies energy (kWh/month) by the carbon intensity of the detected deployment region (kgCO₂e/kWh).
4. **Waste multiplier** — if WAF-COST controls for rightsizing, lifecycle, or FinOps review are **FAIL**, an additional 25% is added to reflect over-provisioned, unoptimised workloads.

> All figures are **directional estimates**. Actual cloud emissions depend on real workload utilisation and provider renewable-energy purchases (RECs).

### What the PDF report shows

The **Carbon Footprint & Sustainability** section (Part III) includes:

| Element | Description |
|---|---|
| Monthly CO₂e | Estimated kilograms of CO₂ equivalent per month |
| Annual CO₂e | 12-month projection in metric tonnes |
| Monthly energy | Total kWh/month across all resources |
| Region intensity | Grid emission factor (kgCO₂e/kWh) for the detected region |
| Real-world equivalences | Car miles, trees needed to offset, phone charges, flight hours |
| Over-provisioning alert | Extra CO₂e from failing WAF-COST controls (waste) |
| Region comparison | How much CO₂e would be saved by deploying to the greenest available region |
| Breakdown by type | Per-resource-type table sorted by CO₂ contribution with % bar |

### Region carbon intensities

Some regions are dramatically cleaner than others:

| Region | Provider | Intensity (kgCO₂e/kWh) | Grid mix |
|---|---|---|---|
| `eu-north-1` (Sweden) | AWS | 0.008 | Hydro + nuclear |
| `eu-central-2` (Switzerland) | AWS | 0.029 | Hydro |
| `eu-west-3` (France) | AWS | 0.052 | Nuclear |
| `sa-east-1` (Brazil) | AWS | 0.074 | Hydro |
| `us-west-2` (Oregon) | AWS | 0.136 | Hydro |
| `eu-west-1` (Ireland) | AWS | 0.316 | Wind + gas |
| `eu-central-1` (Germany) | AWS | 0.338 | Mixed |
| `us-east-1` (Virginia) | AWS | 0.415 | Mixed |
| `ap-south-1` (Mumbai) | AWS | 0.708 | Coal-heavy |
| `af-south-1` (Cape Town) | AWS | 0.900 | Coal |

Moving from `eu-central-1` to `eu-north-1` reduces compute emissions by ~**98%**.

### Sustainability recommendations

- **Choose low-carbon regions** — `eu-north-1`, `eu-west-3`, `sa-east-1`, `us-west-2`
- **Fix WAF-COST controls** — each rightsizing/lifecycle failure adds ~25% to your estimated footprint
- **Use managed / serverless** — Lambda and DynamoDB have much lower per-unit power draw than EC2/RDS equivalents
- **Enable instance scheduling** — stopping non-production workloads nights/weekends cuts footprint by up to 70%
- **Tag for lifecycle** — resources without lifecycle tags cannot be automatically shut down or right-sized

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | All checks passed |
| `1`  | Failures detected (or skips, depending on `--fail-on`) |
| `2`  | Errors (missing controls dir, unreadable IaC files, unknown plugin, etc.) |

## `--fail-on` modes

| Mode  | Exits non-zero when… |
|-------|----------------------|
| `fail` (default) | Any check status is FAIL |
| `skip` | Any check status is FAIL or SKIP |
| `any`  | Any check status is not PASS |

## Supported pillars

| Pillar | Prefix |
|--------|--------|
| `cost` | `WAF-COST-*` |
| `sovereign` | `WAF-SOV-*` |
| `security` | `WAF-SEC-*` |
| `reliability` | `WAF-REL-*` |
| `operations` | `WAF-OPS-*` |
| `architecture` | `WAF-ARCH-*` |
| `governance` | `WAF-GOV-*` |

## CI/CD integration

PASS is designed to run unattended in pipelines. The exit code reflects the check outcome; use `--fail-on` to tune the strictness.

Run state is saved to `.wafpass-state/` by default. Persist this directory between pipeline runs (via cache or an artifact) to get cross-run change tracking. Without persistence, each run starts fresh with no previous state to compare against.

**GitHub Actions — Terraform (multi-cloud) with state persistence:**

```yaml
- name: Restore WAF++ state cache
  uses: actions/cache@v4
  with:
    path: .wafpass-state
    key: wafpass-state-${{ github.ref }}
    restore-keys: wafpass-state-

- name: Run WAF++ PASS
  run: |
    pip install wafpass_core-*.whl     # or: pip install -e . from source
    wafpass check infra/aws infra/azure infra/gcp \
      --iac terraform \
      --fail-on fail \
      --output pdf \
      --pdf-out wafpass-report.pdf

- name: Upload compliance report
  uses: actions/upload-artifact@v4
  with:
    name: wafpass-report
    path: wafpass-report.pdf
```

**GitHub Actions — AWS CDK:**

```yaml
- name: Synthesise CDK app
  run: npx cdk synth          # produces cdk.out/

- name: Run WAF++ PASS
  run: |
    pip install -e .
    wafpass check . --iac cdk --fail-on fail --output pdf --pdf-out wafpass-report.pdf

- name: Upload compliance report
  uses: actions/upload-artifact@v4
  with:
    name: wafpass-report
    path: wafpass-report.pdf
```

**GitHub Actions — with Grafana export:**

```yaml
- name: Run WAF++ PASS + push metrics to Grafana
  env:
    GRAFANA_CLOUD_TOKEN: ${{ secrets.GRAFANA_CLOUD_TOKEN }}
  run: |
    pip install -e .
    wafpass check ./infra/ \
      --fail-on fail \
      --export grafana \
      --output pdf \
      --pdf-out wafpass-report.pdf
```

**GitLab CI — Terraform with state persistence:**

```yaml
wafpass:
  cache:
    key: wafpass-state-$CI_COMMIT_REF_SLUG
    paths:
      - .wafpass-state/
  script:
    - pip install -e .
    - wafpass check infra/aws infra/azure --fail-on fail --summary
  artifacts:
    paths:
      - wafpass-report.pdf
```

**GitLab CI — CDK:**

```yaml
wafpass-cdk:
  script:
    - npx cdk synth
    - pip install -e .
    - wafpass check . --iac cdk --fail-on fail --summary
```

## Releases & versioning

Releases are published automatically on every merge to `main` via the GitHub Actions workflow at `.github/workflows/release.yml`.

### How the version number works

The `VERSION` file in the repository root controls the **major.minor** part:

```
0.3
```

The pipeline reads this file, finds the highest existing git tag matching `vMAJOR.MINOR.*`, and increments the patch number automatically. The first release for a given major.minor is always patch `0`.

| Merge content | Result |
|---|---|
| Any code change | `v0.3.0` → `v0.3.1` → `v0.3.2` … |
| Edit `VERSION`: `0.3` → `0.4` | Next release becomes `v0.4.0` |
| Edit `VERSION`: `0.3` → `1.0` | Next release becomes `v1.0.0` |

### What each release does

1. Reads `VERSION` and computes the next `vMAJOR.MINOR.PATCH`
2. Updates `pyproject.toml` with the new version (the package reads it from metadata at runtime)
3. Runs `pytest`
4. Builds a Python wheel (`.whl`) and source distribution (`.tar.gz`)
5. Creates a git tag and a GitHub release with auto-generated notes and both dist files attached

### Bumping the major or minor version

Edit `VERSION` and merge to `main` — no other file needs changing:

```bash
# bump minor
echo "0.4" > VERSION
git commit -am "chore: start 0.4 release series"
git push
```

The patch counter resets to `0` automatically because no tags exist yet for the new major.minor.

## Full stack (docker-compose)

The WAF++ monorepo ships a `docker-compose.yml` at the repo root that starts the complete stack:

```bash
# From the waf++ repo root
cp .env.example .env    # fill in POSTGRES_PASSWORD
docker compose up
```

| Service | URL | Description |
|---------|-----|-------------|
| wafpass-dashboard | http://localhost:3000 | React dashboard (wafpass-dashboard/) |
| wafpass-server | http://localhost:8000 | FastAPI results API (wafpass-server/) |
| postgres | localhost:5432 | PostgreSQL results store |

Post a result from `wafpass-core`:

```bash
wafpass check ./infra/ --output json \
  | python -c "
import json,sys,httpx
r=json.load(sys.stdin)
r.update({'project':'my-infra','branch':'main'})
httpx.post('http://localhost:8000/api/v1/runs',json=r)
"
```

To enable dashboard Local preview / auto-fix diffs, upload the source snapshot as well:

```bash
wafpass check ./infra/ --output json --upload-source \
  | python -c "
import json,sys,httpx
r=json.load(sys.stdin)
r.update({'project':'my-infra','branch':'main'})
httpx.post('http://localhost:8000/api/v1/runs',json=r)
"
```

## Web UI (embedded, legacy)

> **Note:** As of v0.3.0 the standalone `wafpass-dashboard` (Vite + React) is the recommended dashboard. The embedded web UI below remains available for local quick-start use without requiring Docker.

WAF++ PASS ships with a browser-based dashboard that lets CISOs and security teams interact with controls, manage waivers, and view findings — **no YAML knowledge required**.

### Starting the server

The simplest way to manage the server is through the `wafpass ui` sub-command:

```bash
# Start in the background, open browser automatically
wafpass ui start

# Custom host / port
wafpass ui start --host 0.0.0.0 --port 9090

# Start without opening the browser
wafpass ui start --no-browser

# Check whether the server is running
wafpass ui status

# Stop the server
wafpass ui stop
```

The server PID is stored in `~/.wafpass/ui.pid` and log output in `~/.wafpass/ui.log`. The `start` command detects if a server is already running and refuses to start a second one.

For development, use `--reload` to enable uvicorn auto-reload:

```bash
wafpass ui start --reload
```

You can also start the server directly with uvicorn if you prefer:

```bash
pip install -e ".[web]"
uvicorn serve.app:app --reload --port 8080
```

### Internal serve (production)

A **FastAPI** web server that connects directly to the WAF++ PASS engine. Reads real controls from `controls/`, runs live scans, and persists waivers and risk acceptances to disk.

| Feature | Details |
|---------|---------|
| Executive Dashboard | Score gauge, pillar breakdown, severity chart, architectural debt heatmap, quick wins |
| Controls Library | Browse/search all 70+ controls, filter by pillar/severity |
| Waiver Manager | Add waivers with reason + expiry, export `.wafpass-skip.yml` |
| Risk Acceptance | Full CRUD for formal risk acceptances with approver, RFC, Jira link, residual risk, expiry |
| Findings | Per-check breakdown with remediation guidance, IDE deep-links |
| Compliance Matrix | GDPR, ISO 27001:2022, BSI C5:2020, EUCS, CSRD mapping |
| Run Scan | Trigger scans from the browser, results persist across page loads |
| Auto-Fix *(α)* | Preview and apply surgical IaC patches directly from the UI |
| PDF Export | Generate and download the full PDF report from the browser |

#### Auto-Fix in the UI

The **Auto-Fix** feature *(alpha)* lets you preview and apply patches without leaving the browser:

1. After a scan, click **Auto-Fix** in the Quick Wins section or Findings filter bar to analyse all failing checks.
2. Alternatively, open any FAIL finding and click **Auto-Fix this Control** to scope the analysis to a single control.
3. A diff preview modal shows the exact line-level changes grouped by file, plus a list of checks that require manual remediation.
4. Click **Apply N Patch(es)** to write the changes to disk — `.tf.bak` backups are created automatically.

> Auto-Fix is in alpha. Always review the diff and run `terraform plan` before deploying.

See [`serve/README.md`](serve/README.md) for the full API reference and deployment guide.

### Demo (standalone)

A **self-contained, no-server** interactive demo with embedded sample data. Open in any browser — no Python, no install.

```bash
# From the repository root
open ../web-ui/index.html

# Or serve locally
python3 -m http.server 3000 --directory ../web-ui
```

The demo (`../web-ui/index.html`) has the **same UI/UX** as the internal serve but uses embedded JavaScript data instead of a live backend. It includes 17 representative controls, pre-loaded scan results with 7 failures, fully working waiver management with YAML export, and a simulated Auto-Fix preview (the diff is computed client-side; applying redirects to the CLI).

See [`../web-ui/README.md`](../web-ui/README.md) for more details.

---

## Running tests

```bash
pytest

# With coverage
pytest --cov=wafpass --cov-report=term-missing
```

## Links

- Framework documentation: [waf2p.dev](https://waf2p.dev)
- WAF++ GitHub: [github.com/waf2p](https://github.com/waf2p)
