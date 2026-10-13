"""Load WAF++ YAML control files and parse them into dataclasses."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from wafpass.models import Assertion, Check, Control, Scope

# Optional auth support for server fetch
try:
    from wafpass.auth import get_valid_credentials
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False

# Optional server fetch support
try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

logger = logging.getLogger(__name__)

# Operators that skip during evaluation (not supported in automated checks)
SKIP_OPERATORS = frozenset(
    {
        "has_associated_metric_filter",
        "references_cloudtrail_bucket",
        "region_in_arn_matches",
        "in_variable",
        "not_equals_with_sibling",
        "not_all_true_with",
        "attribute_exists_on_all_providers",
        "attribute_exists_if",
        "json_not_contains_pattern",
    }
)

# Pillar prefix mapping: pillar name -> YAML id prefix
PILLAR_PREFIXES: dict[str, str] = {
    "cost": "WAF-COST-",
    "sovereign": "WAF-SOV-",
    "security": "WAF-SEC-",
    "reliability": "WAF-REL-",
    "operations": "WAF-OPS-",
    "operational": "WAF-OPS-",  # Alias for "operations"
    "architecture": "WAF-ARCH-",
    "governance": "WAF-GOV-",
    "agentic": "WAF-AGN-",
}


def _parse_assertion(raw: dict) -> Assertion:
    """Parse a single assertion dict into an Assertion dataclass."""
    # Normalise: YAML may use 'expected', 'value' (scalar) or 'values' (list);
    # all map to Assertion.expected.  'expected' takes precedence.
    expected: object = None
    if "expected" in raw:
        expected = raw["expected"]
    elif "value" in raw:
        expected = raw["value"]
    elif "values" in raw:
        expected = raw["values"]

    return Assertion(
        attribute=raw.get("attribute", ""),
        op=raw.get("op", ""),
        expected=expected,
        key=raw.get("key"),
        pattern=raw.get("pattern"),
        message=raw.get("message"),
        fallback_attribute=raw.get("fallback_attribute"),
    )


def _parse_scope(raw: dict) -> Scope:
    """Parse a scope dict into a Scope dataclass."""
    return Scope(
        block_type=raw.get("block_type", "resource"),
        resource_types=raw.get("resource_types", []),
        provider_name=raw.get("provider_name"),
    )


def _parse_check(raw: dict, control_severity: str | None = None) -> Check | None:
    """Parse a check dict. Returns None if not automated."""
    if not raw.get("automated", False):
        return None

    scope_raw = raw.get("scope", {})
    assertions_raw = raw.get("assertions", [])

    # Use check's severity if present, otherwise fall back to control's severity, then default to medium
    check_severity = raw.get("severity")
    if check_severity is None and control_severity is not None:
        check_severity = control_severity
    if check_severity is None:
        check_severity = "medium"

    return Check(
        id=raw.get("id", ""),
        engine=raw.get("engine", ""),
        provider=raw.get("provider", ""),
        automated=raw.get("automated", False),
        severity=check_severity,
        title=raw.get("title", ""),
        scope=_parse_scope(scope_raw),
        assertions=[_parse_assertion(a) for a in assertions_raw],
        on_fail=raw.get("on_fail", "violation"),
        remediation=str(raw.get("remediation", "")).strip(),
        example=raw.get("example"),
    )


def _parse_control(raw: dict) -> Control | None:
    """Parse a control dict. Returns None if no automated checks are present."""
    checks_raw = raw.get("checks", [])
    if not checks_raw:
        return None

    # Get control severity for check fallback
    control_severity = raw.get("severity")

    checks: list[Check] = []
    for check_raw in checks_raw:
        parsed = _parse_check(check_raw, control_severity=control_severity)
        if parsed is not None:
            checks.append(parsed)

    if not checks:
        return None

    # Parse regulatory_mapping: list of {framework, controls} dicts
    regulatory_mapping: list[dict] = []
    for entry in raw.get("regulatory_mapping", []):
        if isinstance(entry, dict) and "framework" in entry:
            regulatory_mapping.append({
                "framework": str(entry["framework"]),
                "controls": [str(c) for c in entry.get("controls", [])],
            })

    return Control(
        id=raw.get("id", ""),
        title=raw.get("title", ""),
        pillar=raw.get("pillar", ""),
        severity=raw.get("severity", "medium"),
        category=raw.get("category", ""),
        description=str(raw.get("description", "")).strip(),
        checks=checks,
        regulatory_mapping=regulatory_mapping,
        rationale=str(raw.get("rationale", "")).strip(),
        threat=[str(t) for t in raw.get("threat", [])],
    )


def load_controls(
    controls_dir: Path,
    pillar: str | None = None,
    ids: list[str] | None = None,
    server_url: str | None = None,
) -> list[Control]:
    """Load all YAML control files from controls_dir.

    Args:
        controls_dir: Directory containing WAF-*.yml files.
        pillar: Optional pillar name to filter by (e.g. 'cost', 'sovereign').
        ids: Optional explicit list of control IDs to load.
        server_url: Optional wafpass-server URL to fetch controls from instead of filesystem.

    Returns:
        List of parsed Control objects with at least one automated check.
    """
    # Fetch from server if URL provided
    if server_url and _HTTPX_AVAILABLE:
        return _load_controls_from_server(server_url, pillar=pillar, ids=ids)

    # Load from filesystem (default behavior)
    if not controls_dir.exists():
        logger.warning("Controls directory does not exist: %s", controls_dir)
        return []

    yml_files = sorted(controls_dir.glob("*.yml")) + sorted(controls_dir.glob("*.yaml"))

    if not yml_files:
        logger.warning("No YAML files found in: %s", controls_dir)
        return []

    # Build pillar prefix filter
    pillar_prefix: str | None = None
    if pillar:
        pillar_lower = pillar.lower()
        pillar_prefix = PILLAR_PREFIXES.get(pillar_lower)
        if pillar_prefix is None:
            # Fallback: construct prefix from pillar name
            pillar_prefix = f"WAF-{pillar_lower.upper()}-"

    controls: list[Control] = []
    for yml_path in yml_files:
        # Filter by filename prefix before loading file
        stem = yml_path.stem.upper()
        if pillar_prefix and not stem.startswith(pillar_prefix.upper()):
            continue
        if ids:
            ids_upper = [i.upper() for i in ids]
            if stem not in ids_upper:
                continue

        try:
            with yml_path.open("r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            logger.error("Failed to parse YAML %s: %s", yml_path, exc)
            continue

        if not isinstance(raw, dict):
            logger.warning("Skipping non-dict YAML: %s", yml_path)
            continue

        control = _parse_control(raw)
        if control is None:
            logger.debug("Skipping control with no automated checks: %s", yml_path)
            continue

        controls.append(control)

    return controls


def _load_controls_from_server(
    server_url: str,
    pillar: str | None = None,
    ids: list[str] | None = None,
) -> list[Control]:
    """Fetch controls from a wafpass-server and parse them.

    Args:
        server_url: Base URL of the wafpass-server (e.g. http://localhost:8000).
        pillar: Optional pillar name to filter by.
        ids: Optional explicit list of control IDs to load.

    Returns:
        List of parsed Control objects.
    """
    controls_dir = Path(".wafpass-server-controls")
    controls_dir.mkdir(exist_ok=True)
    loaded_from_server = False

    # Try to fetch from /export endpoint first (full check structure)
    zip_downloaded = False
    try:
        # Fetch controls ZIP from server export endpoint
        url = f"{server_url.rstrip('/')}/api/v1/controls/export"
        params: dict[str, str] = {}
        if pillar:
            params["pillar"] = pillar
        if ids:
            params["id"] = ",".join(ids)

        # Add auth header if credentials exist for this server
        headers: dict[str, str] = {}
        if _AUTH_AVAILABLE:
            creds = get_valid_credentials()
            if creds and creds.server_url.rstrip("/") == server_url.rstrip("/"):
                headers["Authorization"] = creds.bearer()
                logger.debug("Using Bearer token for server fetch")
            elif creds:
                logger.debug("Server URL mismatch: stored=%s, requested=%s",
                             creds.server_url, server_url)
            else:
                logger.debug("No valid credentials available")

        resp = httpx.get(url, params=params, headers=headers, timeout=60)
        resp.raise_for_status()

        # Write ZIP to temp file and extract
        zip_path = controls_dir / "controls_export.zip"
        zip_path.write_bytes(resp.content)

        # Extract ZIP contents
        import zipfile
        with zipfile.ZipFile(zip_path, "r") as zf:
            # Only extract YAML files
            for member in zf.namelist():
                if member.endswith(".yml") and not member.startswith("__MACOSX"):
                    zf.extract(member, controls_dir)

        zip_path.unlink()  # Remove temp ZIP file
        zip_downloaded = True
        loaded_from_server = True

    except httpx.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            logger.warning("No controls found in database, fetching via /api/v1/controls endpoint")
            # Fall through to fetch from /api/v1/controls endpoint
        elif exc.response is not None and exc.response.status_code == 401:
            logger.error(
                "Authentication required. Run 'wafpass login %s' to authenticate.",
                server_url
            )
            # Clear stale cache on auth failure
            try:
                for p in controls_dir.glob("*.yml"):
                    p.unlink(missing_ok=True)
            except OSError:
                pass
            return []
        else:
            logger.error("Failed to fetch controls from server: %s", exc)
            return []
    except Exception as exc:
        logger.error("Error loading controls from server: %s", exc)
        return []

    # If /export didn't work, try fetching from /api/v1/controls endpoint
    if not zip_downloaded:
        try:
            url = f"{server_url.rstrip('/')}/api/v1/controls"
            params: dict[str, str] = {}
            if pillar:
                params["pillar"] = pillar
            if ids:
                params["id"] = ",".join(ids)
            params["per_page"] = "200"  # Max page size

            headers: dict[str, str] = {}
            if _AUTH_AVAILABLE:
                creds = get_valid_credentials()
                if creds and creds.server_url.rstrip("/") == server_url.rstrip("/"):
                    headers["Authorization"] = creds.bearer()
                elif creds:
                    logger.debug("Server URL mismatch: stored=%s, requested=%s",
                                 creds.server_url, server_url)

            resp = httpx.get(url, params=params, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, dict) and "data" in data:
                controls_data = data["data"]
            else:
                controls_data = data if isinstance(data, list) else []

            if not controls_data:
                logger.info("No controls found on server")
                return []

            # Write controls to a local cache directory for reuse
            for ctrl in controls_data:
                if not isinstance(ctrl, dict) or "id" not in ctrl:
                    continue

                # Build YAML from control data
                control_id = ctrl["id"]
                yaml_lines = [
                    f"# Retrieved from wafpass-server: {server_url}",
                    f"# ID: {control_id}",
                    f"id: {control_id}",
                    f"pillar: {ctrl.get('pillar', '')}",
                    f"severity: {ctrl.get('severity', 'medium')}",
                ]

                # Build type list
                types = ctrl.get("type", [])
                if types:
                    yaml_lines.append("type:")
                    for t in types:
                        yaml_lines.append(f"  - {t}")
                else:
                    yaml_lines.append("type: []")

                # Description
                desc = str(ctrl.get("description", "")).strip()
                if desc:
                    yaml_lines.append("description: |")
                    for line in desc.split("\n"):
                        yaml_lines.append(f"  {line}")
                else:
                    yaml_lines.append("description: ''")

                # Regulatory mapping
                reg_map = ctrl.get("regulatory_mapping", [])
                if reg_map:
                    yaml_lines.append("regulatory_mapping:")
                    for entry in reg_map:
                        if isinstance(entry, dict):
                            framework = entry.get("framework", "")
                            controls_list = entry.get("controls", [])
                            yaml_lines.append(f"  - framework: {framework!r}")
                            if controls_list:
                                yaml_lines.append("    controls:")
                                for c in controls_list:
                                    yaml_lines.append(f"      - {c!r}")

                # Checks - include all available fields for full check structure
                checks = ctrl.get("checks", [])
                if checks:
                    yaml_lines.append("checks:")
                    for ch in checks:
                        if isinstance(ch, dict):
                            yaml_lines.append(f"  - id: {ch.get('id', '')}")
                            yaml_lines.append(f"    engine: {ch.get('engine', 'terraform')}")
                            yaml_lines.append(f"    automated: true")
                            if ch.get('title'):
                                yaml_lines.append(f"    title: {ch['title']!r}")
                            if ch.get('provider'):
                                yaml_lines.append(f"    provider: {ch['provider']}")
                            desc_str = ch.get("description", "")
                            yaml_lines.append(f"    description: {desc_str!r}")
                            expected = ch.get("expected", "")
                            yaml_lines.append(f"    expected: {expected!r}")
                            if ch.get('remediation'):
                                yaml_lines.append(f"    remediation: {ch['remediation']!r}")
                            if ch.get('example'):
                                yaml_lines.append(f"    example:")
                                example = ch['example']
                                for ex_key, ex_val in example.items():
                                    yaml_lines.append(f"      {ex_key}: |")
                                    for line in ex_val.split("\n"):
                                        yaml_lines.append(f"        {line}")
                            if ch.get('scope'):
                                scope = ch['scope']
                                yaml_lines.append(f"    scope:")
                                yaml_lines.append(f"      block_type: {scope.get('block_type', 'resource')}")
                                if scope.get('resource_types'):
                                    yaml_lines.append(f"      resource_types:")
                                    for rt in scope['resource_types']:
                                        yaml_lines.append(f"        - {rt}")
                            if ch.get('assertions'):
                                yaml_lines.append(f"    assertions:")
                                for assertion in ch['assertions']:
                                    if isinstance(assertion, dict):
                                        yaml_lines.append(f"      - attribute: {assertion.get('attribute', '')!r}")
                                        if assertion.get('op'):
                                            yaml_lines.append(f"        op: {assertion['op']!r}")
                                        if assertion.get('key'):
                                            yaml_lines.append(f"        key: {assertion['key']!r}")
                                        if assertion.get('message'):
                                            yaml_lines.append(f"        message: {assertion['message']!r}")
                                        if assertion.get('expected'):
                                            yaml_lines.append(f"        expected: {assertion['expected']!r}")
                                        if assertion.get('pattern'):
                                            yaml_lines.append(f"        pattern: {assertion['pattern']!r}")
                            if ch.get('on_fail'):
                                yaml_lines.append(f"    on_fail: {ch['on_fail']}")

                # Write to cache file
                control_path = controls_dir / f"{control_id}.yml"
                control_path.write_text("\n".join(yaml_lines) + "\n", encoding="utf-8")

        except httpx.HTTPError as exc:
            logger.error("Failed to fetch controls from server: %s", exc)
            if exc.response is not None and exc.response.status_code == 401:
                logger.error(
                    "Authentication required. Run 'wafpass login %s' to authenticate.",
                    server_url
                )
            return []
        except Exception as exc:
            logger.error("Error loading controls from server: %s", exc)
            return []

    # Now load from the cached/extracted YAML files
    yml_files = sorted(controls_dir.glob("*.yml"))

    if not yml_files:
        logger.info("No YAML files found in cached server controls")
        return []

    # Build pillar prefix filter
    pillar_prefix: str | None = None
    if pillar:
        pillar_lower = pillar.lower()
        pillar_prefix = PILLAR_PREFIXES.get(pillar_lower)
        if pillar_prefix is None:
            pillar_prefix = f"WAF-{pillar_lower.upper()}-"

    controls: list[Control] = []
    for yml_path in yml_files:
        # Filter by filename prefix
        stem = yml_path.stem.upper()
        if pillar_prefix and not stem.startswith(pillar_prefix.upper()):
            continue
        if ids:
            ids_upper = [i.upper() for i in ids]
            if stem not in ids_upper:
                continue

        try:
            with yml_path.open("r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            logger.error("Failed to parse cached YAML %s: %s", yml_path, exc)
            continue

        if not isinstance(raw, dict):
            continue

        control = _parse_control(raw)
        if control is None:
            continue

        controls.append(control)

    return controls
