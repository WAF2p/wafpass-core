"""High-level scan orchestration for WAF++ PASS.

This module keeps all scanning logic in wafpass-core so that both the CLI and
wafpass-server are thin wrappers around the same implementation.
"""
from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from wafpass.engine import SEVERITY_ORDER, run_controls
from wafpass.iac import registry
from wafpass.iac.base import IaCState
from wafpass.loader import load_controls
from wafpass.models import ControlResult, Report
from wafpass.schema import (
    ControlCheckMetaSchema,
    ControlMetaSchema,
    FindingSchema,
    SecretFindingSchema,
    WafpassResultSchema,
)
from wafpass.secret_scanner import SecretFinding, scan_secrets
from wafpass.waivers import apply_waivers, load_waivers


def _git(cmd: list[str]) -> str:
    """Run a git command and return stdout, swallowing errors."""
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return ""


def _detect_triggered_by(triggered_by: str | None) -> str:
    """Detect the trigger source from environment variables."""
    if triggered_by:
        return triggered_by
    if os.environ.get("GITHUB_ACTIONS"):
        return "github-actions"
    if os.environ.get("GITLAB_CI"):
        return "gitlab-ci"
    if os.environ.get("CI"):
        return "ci"
    return "local"


class ScanConfig:
    """Configuration for a single scan run."""

    def __init__(
        self,
        paths: list[Path],
        controls_dir: Path,
        iac: str = "terraform",
        project: str = "",
        branch: str = "",
        git_sha: str = "",
        triggered_by: str = "",
        is_cicd: bool = False,
        stage: str = "",
        control_ids: list[str] | None = None,
        severity: str | None = None,
        pillar: str | None = None,
        waivers_file: Path | None = None,
        plan_file: Path | None = None,
        no_secrets: bool = False,
        upload_source: bool = False,
        server_url: str | None = None,
    ) -> None:
        self.paths = paths
        self.controls_dir = controls_dir
        self.iac = iac
        self.project = project
        self.branch = branch
        self.git_sha = git_sha
        self.triggered_by = triggered_by
        self.is_cicd = is_cicd
        self.stage = stage
        self.control_ids = control_ids
        self.severity = severity
        self.pillar = pillar
        self.waivers_file = waivers_file
        self.plan_file = plan_file
        self.no_secrets = no_secrets
        self.upload_source = upload_source
        self.server_url = server_url


def _build_source_snapshot(paths: list[Path], extensions: list[str]) -> dict[str, str]:
    """Read all source files matching the plugin extensions under paths."""
    snapshot: dict[str, str] = {}
    ext_set = set(extensions)
    for base in paths:
        if base.is_file() and base.suffix in ext_set:
            try:
                snapshot[base.name] = base.read_text(encoding="utf-8")
            except OSError:
                continue
            continue
        if base.is_dir():
            for ext in extensions:
                for source_path in sorted(base.rglob(f"*{ext}")):
                    try:
                        rel = str(source_path.relative_to(base))
                        snapshot[rel] = source_path.read_text(encoding="utf-8")
                    except OSError:
                        continue
    return snapshot


def _filter_by_severity(
    control_results: list[ControlResult], min_severity: str | None
) -> list[ControlResult]:
    """Drop check results below the requested severity threshold."""
    if not min_severity:
        return control_results

    min_level = SEVERITY_ORDER.get(min_severity.lower(), 0)
    filtered: list[ControlResult] = []
    for cr in control_results:
        filtered_results = [
            r
            for r in cr.results
            if SEVERITY_ORDER.get(r.severity.lower(), 0) >= min_level
        ]
        filtered.append(ControlResult(control=cr.control, results=filtered_results))
    return filtered


def run_scan(config: ScanConfig) -> tuple[Report, WafpassResultSchema]:
    """Run the full WAF++ scan and build the serialisable result.

    This is the single core entry point used by both the CLI and the server.
    """
    plugin = registry.get(config.iac.lower())
    if plugin is None:
        available = ", ".join(registry.available) or "(none)"
        raise ValueError(f"Unknown IaC plugin '{config.iac}'. Available: {available}")

    for p in config.paths:
        if not p.exists():
            raise FileNotFoundError(f"Path does not exist: {p}")

    controls = load_controls(
        config.controls_dir,
        pillar=config.pillar,
        ids=config.control_ids,
        server_url=config.server_url,
    )
    if not controls:
        raise ValueError(f"No controls found in {config.controls_dir}")

    # Parse IaC files (merge across all paths) and run engine
    merged_state = IaCState()
    all_regions: list[tuple[str, str, str]] = []
    for p in config.paths:
        state = plugin.parse(p)
        merged_state.resources.extend(state.resources)
        merged_state.providers.extend(state.providers)
        merged_state.variables.extend(state.variables)
        merged_state.modules.extend(state.modules)
        merged_state.config_blocks.extend(state.config_blocks)
        all_regions.extend(plugin.extract_regions(state))

    # Deduplicate regions while preserving order
    seen_region_keys: set[tuple[str, str, str]] = set()
    unique_regions: list[tuple[str, str, str]] = []
    for r in all_regions:
        key = (r[0].lower(), r[1], r[2] if len(r) > 2 else "")
        if key not in seen_region_keys:
            seen_region_keys.add(key)
            unique_regions.append(r)

    results = run_controls(controls, merged_state, engine_name=config.iac.lower())

    # Secret scanning
    secret_findings: list[SecretFinding] = []
    if not config.no_secrets:
        secret_findings = scan_secrets(config.paths)

    # Waivers
    waivers_data: list[dict[str, Any]] = []
    if config.waivers_file and config.waivers_file.exists():
        waivers_data = load_waivers(config.waivers_file)
    if waivers_data:
        apply_waivers(results, waivers_data)

    # Severity filter
    results = _filter_by_severity(results, config.severity)

    # Compute scores
    pillar_totals: dict[str, list[int]] = {}
    for cr in results:
        pillar_totals.setdefault(cr.control.pillar, []).append(
            1 if cr.status == "PASS" else 0
        )
    pillar_scores = {
        p: int(sum(v) / len(v) * 100) if v else 0
        for p, v in pillar_totals.items()
    }
    score = int(sum(pillar_scores.values()) / len(pillar_scores)) if pillar_scores else 0

    # Build Report
    source_paths = [str(p) for p in config.paths]
    report = Report(
        path=" | ".join(source_paths),
        controls_loaded=len(controls),
        controls_run=len(results),
        results=results,
        detected_regions=unique_regions,
        source_paths=source_paths,
        state=merged_state,
        secret_findings=secret_findings,
    )

    # Build findings list
    findings: list[FindingSchema] = []
    for cr in results:
        for chk in cr.results:
            findings.append(FindingSchema(
                check_id=chk.check_id,
                check_title=chk.check_title,
                control_id=chk.control_id,
                pillar=cr.control.pillar,
                severity=chk.severity,
                status=chk.status,
                resource=chk.resource,
                message=chk.message,
                remediation=chk.remediation,
                example=chk.example,
                regulatory_mapping=cr.control.regulatory_mapping,
            ))
        if cr.status == "WAIVED" and not cr.results:
            findings.append(FindingSchema(
                check_id=f"{cr.control.id}-WAIVED",
                check_title=cr.control.title,
                control_id=cr.control.id,
                pillar=cr.control.pillar,
                severity=cr.control.severity,
                status="WAIVED",
                resource="",
                message=cr.waived_reason or "",
                remediation="",
                example=None,
                regulatory_mapping=cr.control.regulatory_mapping,
            ))

    # Build controls metadata
    controls_meta: list[ControlMetaSchema] = []
    for ctrl in controls:
        checks = [
            ControlCheckMetaSchema(
                id=chk.id,
                title=chk.title,
                severity=chk.severity,
                remediation=chk.remediation,
                example=chk.example,
            )
            for chk in ctrl.checks
        ]
        controls_meta.append(ControlMetaSchema(
            id=ctrl.id,
            title=ctrl.title,
            pillar=ctrl.pillar,
            severity=ctrl.severity,
            category=ctrl.category,
            description=ctrl.description,
            rationale=ctrl.rationale,
            threat=ctrl.threat,
            regulatory_mapping=ctrl.regulatory_mapping,
            checks=checks,
        ))

    # Plan changes
    plan_changes: dict[str, Any] | None = None
    if config.plan_file:
        from wafpass.plan_parser import parse_plan_file
        if config.plan_file.exists():
            plan_changes = parse_plan_file(config.plan_file)

    secret_schema_findings = [
        SecretFindingSchema(
            file=str(sf.file),
            line_no=sf.line_no,
            pattern_name=sf.pattern_name,
            severity=sf.severity,
            matched_key=sf.matched_key,
            masked_value=sf.masked_value,
            suppressed=sf.suppressed,
        )
        for sf in secret_findings
    ]

    # Source snapshot
    source_snapshot: dict[str, str] = {}
    if config.upload_source:
        source_snapshot = _build_source_snapshot(config.paths, plugin.file_extensions)

    # Git metadata
    branch = config.branch or _git(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    git_sha = config.git_sha or _git(["git", "rev-parse", "HEAD"])
    triggered_by = _detect_triggered_by(config.triggered_by)

    completed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    result = WafpassResultSchema(
        project=config.project,
        branch=branch,
        git_sha=git_sha,
        triggered_by=triggered_by,
        run={"is_cicd": config.is_cicd},
        iac_framework=config.iac.lower(),
        stage=config.stage,
        score=score,
        pillar_scores=pillar_scores,
        path=report.path,
        controls_loaded=report.controls_loaded,
        controls_run=report.controls_run,
        detected_regions=[list(r) for r in unique_regions],
        source_paths=source_paths,
        controls_meta=controls_meta,
        findings=findings,
        secret_findings=secret_schema_findings,
        plan_changes=plan_changes,
        source_snapshot=source_snapshot,
        completed_at=completed_at,
    )

    return report, result
