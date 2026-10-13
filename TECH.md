# wafpass-core — Technical Reference

This document covers internal architecture, design decisions, technical debt, and contribution guidance for `wafpass-core` (`pass/`). For user-facing documentation see `README.md`.

> **BREAKING CHANGE:** `wafpass-server` endpoints are now under `/api/v1`. The CLI, wizard, and loader have been updated to call `/api/v1/auth/login`, `/api/v1/runs`, `/api/v1/controls`, `/api/v1/evidence`, etc.

---

## Directory structure

```
pass/
├── wafpass/
│   ├── __init__.py          # Public API surface (run_scan, WafpassResultSchema, …)
│   ├── engine.py            # run_controls() — assertion evaluation loop
│   ├── models.py            # Core dataclasses (Control, Check, CheckResult, …)
│   ├── schema.py            # Pydantic models for wafpass-result.json contract
│   ├── loader.py            # load_controls() — YAML → Control objects
│   ├── control_schema.py    # Pydantic validation models for control authoring
│   ├── cli.py               # Typer CLI — check, fix, login, logout, whoami, ui, control, evidence
│   ├── auth.py              # Credential store — JWT tokens in ~/.wafpass/credentials.json
│   ├── reporter.py          # Rich terminal output
│   ├── pdf_reporter.py      # ReportLab PDF generation
│   ├── baseline.py          # Baseline comparison (change tracking)
│   ├── blast_radius.py      # Impact graph computation
│   ├── blast_renderer.py    # Impact graph rendering helpers
│   ├── carbon.py            # Carbon footprint estimation
│   ├── fixer.py             # Auto-remediation suggestions
│   ├── secret_scanner.py    # Hardcoded credential detection
│   ├── plan_parser.py       # Terraform plan JSON parsing
│   ├── state.py             # Run versioning and change tracking
│   ├── waivers.py           # Waiver file load and apply
│   ├── wizard.py            # Interactive control authoring CLI
│   ├── parser.py            # Legacy shim (backwards compat)
│   ├── iac/
│   │   ├── base.py          # Protocol: IaCBlock, IaCState, IaCPlugin
│   │   ├── registry.py      # PluginRegistry singleton
│   │   └── plugins/
│   │       ├── terraform.py # Terraform HCL parser (python-hcl2)
│   │       ├── cdk.py       # AWS CDK parser
│   │       ├── bicep.py     # Bicep/ARM parser (stub)
│   │       └── pulumi.py    # Pulumi YAML/JSON parser (stub)
│   └── export/              # Observability export plugins
│       ├── base.py          # ExportPlugin protocol, ExportResult dataclass
│       ├── config.py        # .wafpass-export.yml loader (${ENV_VAR} expansion)
│       ├── registry.py      # Export plugin registry singleton
│       └── plugins/
│           ├── grafana.py   # Prometheus Pushgateway (fully implemented)
│           ├── prometheus.py # Direct Pushgateway push
│           ├── datadog.py   # Datadog Metrics API v2 (stub)
│           ├── splunk.py    # Splunk HEC (stub)
│           ├── slack.py     # Slack webhook (stub)
│           └── webhook.py   # Generic HTTP POST (fully implemented)
├── controls/                # 73 WAF++ control YAML files (WAF-*.yml)
├── hooks/
│   ├── pre-commit           # Pre-commit hook script (bash, POSIX-compatible)
│   ├── install.sh           # Installer for macOS / Linux / Git Bash
│   └── install.ps1          # Installer for Windows PowerShell
├── tests/
└── pyproject.toml
```

---

## Architecture

### Data flow

```
CLI / library call
       │
       ▼
load_controls(controls_dir)          ← YAML → list[Control]
       │
       ▼
plugin.parse(path)                   ← HCL/CDK/Bicep → IaCState
       │
       ▼
run_controls(controls, state)        ← evaluate assertions
       │
       ▼
list[ControlResult]
       │
       ▼
WafpassResultSchema.model_dump_json() ← serialize to wafpass-result.json
```

### IaC plugin system

Plugins are registered as a module-level singleton (`registry` in `iac/registry.py`). Each plugin is a class implementing the `IaCPlugin` protocol:

```python
class IaCPlugin(Protocol):
    name: str                       # "terraform"
    file_extensions: list[str]      # [".tf"]
    def can_parse(path: Path) -> bool: ...
    def parse(path: Path) -> IaCState: ...
    def extract_regions(state: IaCState) -> list[tuple[str, str]]: ...
```

Plugins auto-register on import of `wafpass/__init__.py`. The registry is keyed by name, so `registry.get("terraform")` always returns the Terraform plugin.

**Adding a new plugin:** Create a class in `iac/plugins/`, implement the protocol, and call `registry.register(MyPlugin())` at module level. No changes needed elsewhere.

### Assertion evaluation (`engine.py`)

`run_controls()` performs a triple-nested loop:

```
for control in controls:
    for check in control.checks (automated only):
        find matching IaCBlocks by scope (block_type + resource_types)
        if no matching blocks → CheckResult(status=SKIP)
        for block in matching_blocks:
            evaluate all assertions against block.attributes
            if any assertion fails → FAIL, else PASS
```

Assertions support 22+ operators. The `op` field maps to a handler function in `engine.py`. Unknown operators yield `SKIP` rather than errors, which is intentional — it allows controls that use cross-resource operators (e.g. `has_associated_resource`) to degrade gracefully when the operator is not yet implemented.

**Attribute resolution** uses dot-path notation (`tags.cost-center`). The resolver walks nested dicts, with special handling for lists (any-match semantics for `in` operators).

### Result schema contract (`schema.py`)

`WafpassResultSchema` is the stable JSON contract between `wafpass-core`, `wafpass-server`, and any downstream tooling. The server's `RunCreate` schema mirrors it. The schema is versioned (`schema_version = "1.1"`).

**Design rule:** Never add required fields to `WafpassResultSchema` without a default — doing so is a breaking change for clients that POST stored results.

### Control YAML format

Each YAML file defines one control. The engine ignores any check where `automated: false`. The full format is documented in `README.md` under _Controls directory setup_.

Key YAML fields that affect engine behaviour:

| Field | Effect |
|-------|--------|
| `checks[].automated` | `false` → check is never run, only stored as metadata |
| `checks[].engine` | Used to filter checks when `engine_name` is passed to `run_controls()` |
| `checks[].scope.block_type` | Determines which `IaCState` attribute to search (`resources`, `providers`, etc.) |
| `checks[].scope.resource_types` | Filters blocks by `IaCBlock.type` |
| `assertions[].op` | Operator; unknown ops yield SKIP |
| `assertions[].fallback_attribute` | Used only with `attribute_exists_or_fallback` |

---

## Authentication module (`auth.py`)

`wafpass/auth.py` is a zero-knowledge credential store. It handles the full token lifecycle for the `wafpass login` / `logout` / `whoami` CLI commands and the `--push @` shorthand in `wafpass check`.

### Credentials file

`~/.wafpass/credentials.json` (mode `0o600`). Stored fields:

| Field | Description |
|-------|-------------|
| `server_url` | Base URL of the wafpass-server (no trailing slash) |
| `access_token` | Short-lived HS256 JWT |
| `refresh_token` | Opaque long-lived token |
| `username` | Username (informational) |
| `role` | Role string returned by the server on login |
| `expires_at` | ISO-8601 UTC — decoded from the JWT `exp` claim |

The password is **never** written to disk.

### Token flow

```
wafpass login <server_url>
    │  POST /api/v1/auth/login {username, password}
    ▼
do_login() → Credentials stored in ~/.wafpass/credentials.json
    │  access_token, refresh_token, role, expires_at
    ▼
wafpass check --push @
    │  resolve_push_target("@")
    ▼
get_valid_credentials()
    ├─ load() → Credentials
    ├─ if is_expired() → do_refresh() → update stored token
    └─ bearer() → "Bearer <access_token>"
    │  (push_url, {"Authorization": "Bearer ..."})
    ▼
httpx.post(push_url, content=result_json, headers=auth_headers)
```

### `Credentials.is_expired()`

Treats the token as expired 30 seconds before the actual `exp` timestamp to avoid race conditions with the server's clock.

### `resolve_push_target(push_arg)`

| `push_arg` | Behaviour |
|------------|-----------|
| `None` / `""` | No push |
| `"@"` | Uses `{server_url}/api/v1/runs` from stored credentials with Bearer token |
| Any URL | Uses that URL; injects Bearer token if the URL prefix matches `server_url` |

### Evidence CLI subcommands

`wafpass evidence` is a Typer sub-app that wraps three server endpoints:

| Subcommand | Server call | Description |
|------------|-------------|-------------|
| `evidence lock` | `POST /api/v1/evidence` | Freeze a run snapshot; print hash, public URL, QR link |
| `evidence list` | `GET /api/v1/evidence` | List locked packages (with optional `--project` filter) |
| `evidence show` | `GET /api/v1/evidence/{id}` | Print metadata; `--hash` prints only the SHA-256 digest |

All three subcommands require an active `wafpass login` session.

---

## Key design decisions

### Dataclasses over Pydantic for internal models

`Control`, `Check`, `CheckResult`, and `ControlResult` in `models.py` are plain Python `@dataclass` objects. This keeps the engine fast and dependency-light. Pydantic is used only at the boundary (`schema.py`) where JSON serialization is needed.

### Waivers applied after evaluation

`apply_waivers()` is called after `run_controls()` returns, not during evaluation. This is intentional: it means the raw check results (PASS/FAIL) are always present and can be audited. The waiver only changes the `ControlResult.waived_reason` field and the computed `status` property.

### SKIP semantics

A control emits `SKIP` if no matching IaC blocks are found (e.g. no `aws_s3_bucket` resources in the scanned code). This is distinct from `PASS` — it means "not applicable" rather than "compliant". The score denominator excludes `SKIP` controls.

### Scoring formula

```python
score = round(100 * check_pass / (check_pass + check_fail)) if (check_pass + check_fail) > 0 else 100
```

SKIP and WAIVED checks are excluded from both numerator and denominator. Pillar scores use the same formula applied per-pillar.

---

## Unsupported assertion operators (known technical debt)

Nine assertion operators are declared in control YAMLs but not implemented in `engine.py`. They silently return `SKIP`:

| Operator | Reason not implemented |
|----------|----------------------|
| `has_associated_metric_filter` | Requires cross-resource graph lookup |
| `references_cloudtrail_bucket` | Requires resource reference resolution |
| `region_in_arn_matches` | Requires ARN parsing + provider config |
| `in_variable` | Requires variable value resolution |
| `not_equals_with_sibling` | Requires sibling block lookup |
| `not_all_true_with` | Requires aggregation across block instances |
| `attribute_exists_on_all_providers` | Requires provider-level aggregation |
| `attribute_exists_if` | Conditional evaluation not yet wired |
| `json_not_contains_pattern` | Requires embedded JSON parsing |

**Impact:** Controls using these operators always show as SKIP rather than FAIL. For most controls this affects only some checks, so the control still evaluates correctly on other checks.

**Fix path:** Implement each operator in `engine.py` by adding a handler function to the `_OPERATORS` dict. Most need `IaCState` to be passed into the assertion context (currently only the current block's attributes are available).

---

## IaC plugin completeness

| Plugin | Status | Notes |
|--------|--------|-------|
| Terraform | Production | python-hcl2 parser, all scope types supported |
| CDK | Production | TypeScript source + synthesized CloudFormation JSON |
| Pulumi | Production | Python source via `ast` |
| Bicep | Stub | ARM template parsing, limited assertion coverage |

Bicep is functional but has significantly less assertion operator coverage than the Terraform plugin, because the 73 controls were primarily written and tested against Terraform. CDK and Pulumi reuse the same Terraform-style control assertions via canonical resource addressing.

---

## Git hooks

The `hooks/` directory contains a pre-commit hook that runs `wafpass check` against staged IaC files before every commit.  It is committed to the repository so the whole team can install it from source with a single command.

### Installation

```bash
# macOS / Linux / Git Bash
bash hooks/install.sh

# Windows PowerShell
.\hooks\install.ps1
```

The installer symlinks `hooks/pre-commit` into `.git/hooks/pre-commit` (Unix) or copies it (Windows).  A symlink means updates to `hooks/pre-commit` take effect immediately without re-running the installer.

### What the hook does

On every `git commit` the hook:

1. Augments `PATH` with common Python tool locations (`~/.local/bin`, Homebrew, `.venv/bin`, pyenv shims) so the script works in IDE-launched git environments where PATH is restricted.
2. Detects IaC types from staged file extensions:

   | Staged files | IaC plugin used |
   |---|---|
   | `*.tf`, `*.tfvars` | `terraform` |
   | `*.bicep` | `bicep` |
   | `*.ts` / `*.py` when `cdk.json` is present | `cdk` |
   | `*.ts` / `*.py` / `*.go` when `Pulumi.yaml` is present | `pulumi` |

3. Runs `wafpass check --iac <type> --controls-dir <dir> --severity <level> --fail-on fail` for each detected IaC type.
4. Validates any staged `controls/*.yml` files with `wafpass control validate`.
5. Blocks the commit and prints remediation guidance if any check fails.

When `wafpass` is not found on `PATH` the hook prints a warning but **does not block the commit** (unless `WAFPASS_STRICT=1` is set).

### Configuration

All settings are optional and can be set as environment variables or in `.env`:

| Variable | Default | Description |
|---|---|---|
| `WAFPASS_CONTROLS_DIR` | `controls` | Path to the controls directory |
| `WAFPASS_SEVERITY` | `high` | Minimum severity to enforce (`low`, `medium`, `high`, `critical`) |
| `WAFPASS_FAIL_ON` | `fail` | When to exit non-zero: `fail`, `skip`, or `any` |
| `WAFPASS_STRICT` | `0` | Set to `1` to abort the commit when wafpass is not installed |

### IDE compatibility

| IDE | Behaviour |
|---|---|
| **Git CLI** | Hook runs automatically via `.git/hooks/pre-commit`. |
| **VS Code** | The built-in Git integration invokes `.git/hooks` automatically — no extra setup needed. |
| **IntelliJ / JetBrains IDEs** | Hooks run by default (Settings → Version Control → Git → "Run Git hooks"). If wafpass is not found, ensure the IDE shell path resolves to your login shell (Settings → Tools → Terminal → Shell path), or set `WAFPASS_STRICT=0` to make the hook advisory rather than blocking. |

### Bypassing the hook

For exceptional cases (e.g. a WIP commit or a control waiver that hasn't been committed yet):

```bash
git commit --no-verify
```

Prefer adding a waiver to `risk_acceptance.yml` over bypassing the hook permanently.

---

## Testing

```bash
pip install -e ".[dev]"
pytest
pytest -k "test_engine"          # filter by test name
pytest --tb=short                # shorter tracebacks
```

Tests live in `tests/`. Key test areas:
- `test_engine.py` — assertion operator coverage
- `test_loader.py` — YAML parsing edge cases
- `test_schema.py` — serialization roundtrip

**Known gap:** Integration tests that parse real Terraform against real controls are sparse. Most engine tests use synthetic `IaCState` objects constructed in-test.

---

## Adding a new control

1. Create `controls/WAF-XXX-NNN.yml` following the schema in `README.md`
2. Set `automated: true` on any checks the engine can evaluate
3. Run `wafpass check tests/fixtures/` to validate parsing
4. Validate schema: `python -c "from wafpass.loader import load_controls; from pathlib import Path; cs = load_controls(Path('controls')); print(len(cs), 'controls loaded')`

Controls with no `automated: true` checks are still returned by `load_controls()` and stored in `controls_meta` by the server, but they never generate findings.

---

## Environment variables

`wafpass-core` is stateless and works fully offline without any environment configuration. All variables are optional.

Copy `.env.example` to `.env` and source it (or use direnv) to avoid passing flags on every invocation:

```bash
cp .env.example .env
export $(grep -v '^#' .env | xargs)
```

| Variable | Description |
|----------|-------------|
| `WAFPASS_SERVER_URL` | Auto-POST results to wafpass-server after every `wafpass check` run. Equivalent to `--push <url>`. Must include the `/api/v1/runs` path: `http://localhost:8000/api/v1/runs`. |
| `${*}` in `.wafpass-export.yml` | Any `${VAR}` placeholder in export config is expanded from the environment at load time. See `.env.example` for common export plugin secrets. |
| `EDITOR` | Editor launched by `wafpass wizard` for interactive control authoring. Falls back to `vi` if unset. |

---

## Release process

1. Bump `VERSION` file and `pyproject.toml` `version` field
2. Update `CHANGELOG.md`
3. `python -m build` → produces `dist/wafpass_core-X.Y.Z-py3-none-any.whl`
4. Upload to PyPI: `twine upload dist/*`
5. Tag the release in git

---

## Dependencies rationale

| Dependency | Why |
|------------|-----|
| `python-hcl2` | Only production-quality Python HCL parser |
| `pydantic>=2` | Fast schema validation + JSON serialization for the result contract |
| `pyyaml` | YAML control definitions |
| `typer` + `rich` | CLI framework + terminal formatting; typer wraps Click with type annotations |
| `reportlab` (optional) | PDF generation — optional so the core package stays lightweight |
| `fastapi` (optional) | Only needed for `wafpass ui` — pulls in uvicorn; optional extra `[web]` |
