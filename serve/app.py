"""WAF++ PASS – internal web UI server.

Start with:
    cd pass/
    uvicorn serve.app:app --reload --port 8080

Or directly:
    python -m serve.app

Requires:
    pip install fastapi uvicorn
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Allow importing wafpass from the parent directory when run without install
sys.path.insert(0, str(Path(__file__).parent.parent))

from wafpass.validation_server import router as validation_router  # noqa: E402

# ── Paths ──────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
CONTROLS_DIR = BASE_DIR.parent / "controls"
TEMPLATES_DIR = BASE_DIR / "templates"
WAIVERS_FILE = BASE_DIR / "waivers.yml"
RISK_ACCEPTANCES_FILE = BASE_DIR / "risk_acceptances.yml"
LAST_RESULTS_FILE = BASE_DIR / "last_results.json"

# ── In-memory cache for the last Report object (needed for PDF export) ────────
_last_report: Any = None

# ── App ────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="WAF++ PASS Web UI",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url=None,
)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
app.include_router(validation_router)

_TEMPLATE_TEXT: str | None = None

def _render_index(controls_json: str, waivers_json: str, results_json: str, risk_acceptances_json: str = "{}") -> str:
    """Read the HTML template and substitute data placeholders (no Jinja2 required)."""
    global _TEMPLATE_TEXT
    if _TEMPLATE_TEXT is None:
        _TEMPLATE_TEXT = (TEMPLATES_DIR / "index.html").read_text(encoding="utf-8")
    html = _TEMPLATE_TEXT
    html = html.replace("__CONTROLS_JSON__", controls_json)
    html = html.replace("__WAIVERS_JSON__", waivers_json)
    html = html.replace("__RESULTS_JSON__", results_json)
    html = html.replace("__RISK_ACCEPTANCES_JSON__", risk_acceptances_json)
    # Replace the mode marker exactly once (the string literal in the script block)
    html = html.replace('window.__MODE__ = "__MODE__";', 'window.__MODE__ = "internal";', 1)
    return html


# ── Helpers ────────────────────────────────────────────────────────────────

def _controls_as_dicts() -> list[dict]:
    """Load all controls and return as JSON-serialisable list."""
    try:
        from wafpass.loader import load_controls
        controls = load_controls(CONTROLS_DIR)
    except Exception:
        return []

    result = []
    for c in controls:
        result.append({
            "id": c.id,
            "title": c.title,
            "pillar": c.pillar,
            "severity": c.severity,
            "category": c.category,
            "description": c.description,
            "rationale": c.rationale,
            "threat": c.threat,
            "checks_count": len(c.checks),
            "automated_checks": [
                {
                    "id": ch.id,
                    "title": ch.title,
                    "severity": ch.severity,
                    "remediation": ch.remediation,
                    "example": ch.example,
                    "resource_types": ch.scope.resource_types,
                }
                for ch in c.checks
            ],
            "regulatory_mapping": c.regulatory_mapping,
        })
    return result


def _raw_control(control_id: str) -> dict | None:
    """Return raw YAML dict for a single control."""
    for f in CONTROLS_DIR.glob("WAF-*.yml"):
        with f.open() as fh:
            data = yaml.safe_load(fh)
        if isinstance(data, dict) and data.get("id") == control_id:
            return data
    return None


def _load_waivers() -> dict[str, dict]:
    """Load waivers.yml and return dict keyed by control ID."""
    if not WAIVERS_FILE.exists():
        return {}
    with WAIVERS_FILE.open() as fh:
        data = yaml.safe_load(fh) or {}
    return {e["id"]: e for e in data.get("waivers", []) if "id" in e}


def _save_waivers(waivers: dict[str, dict]) -> None:
    with WAIVERS_FILE.open("w") as fh:
        yaml.safe_dump({"waivers": list(waivers.values())}, fh, default_flow_style=False)


def _load_risk_acceptances() -> dict[str, dict]:
    """Load risk_acceptances.yml and return dict keyed by control ID."""
    if not RISK_ACCEPTANCES_FILE.exists():
        return {}
    with RISK_ACCEPTANCES_FILE.open() as fh:
        data = yaml.safe_load(fh) or {}
    return {e["id"]: e for e in data.get("risk_acceptances", []) if "id" in e}


def _save_risk_acceptances(acceptances: dict[str, dict]) -> None:
    with RISK_ACCEPTANCES_FILE.open("w") as fh:
        yaml.safe_dump({"risk_acceptances": list(acceptances.values())}, fh, default_flow_style=False)


def _compute_score(results: list[dict]) -> int:
    weights = {"critical": 10, "high": 5, "medium": 2, "low": 1}
    total_w = pass_w = 0
    for r in results:
        if r["status"] in ("SKIP", "WAIVED"):
            continue
        w = weights.get(r.get("severity", "medium"), 2)
        total_w += w
        if r["status"] == "PASS":
            pass_w += w
    return round(pass_w / total_w * 100) if total_w else 100


def _pillar_scores(results: list[dict]) -> dict[str, int]:
    pillars: dict[str, tuple[int, int]] = {}  # pillar -> (pass, total)
    for r in results:
        pillar = r.get("pillar", "unknown")
        if r["status"] in ("SKIP", "WAIVED"):
            continue
        p, t = pillars.get(pillar, (0, 0))
        pillars[pillar] = (p + (1 if r["status"] == "PASS" else 0), t + 1)
    return {
        p: round(ps / t * 100) if t else 100
        for p, (ps, t) in pillars.items()
    }


def _policy_version() -> str:
    """Return the wafpass package version, used as the policy/controls version."""
    try:
        from importlib.metadata import version
        return version("wafpass")
    except Exception:
        return "0.2.0"


def _report_to_dict(report: Any) -> dict:
    from wafpass.models import Report
    results = []
    for cr in report.results:
        results.append({
            "control_id": cr.control.id,
            "control_title": cr.control.title,
            "pillar": cr.control.pillar,
            "severity": cr.control.severity,
            "category": cr.control.category,
            "description": cr.control.description,
            "status": cr.status,
            "waived_reason": cr.waived_reason,
            "regulatory_mapping": cr.control.regulatory_mapping,
            "check_results": [
                {
                    "check_id": r.check_id,
                    "check_title": r.check_title,
                    "severity": r.severity,
                    "status": r.status,
                    "resource": r.resource,
                    "message": r.message,
                    "remediation": r.remediation,
                    "example": r.example,
                    "regulatory_mapping": cr.control.regulatory_mapping,
                }
                for r in cr.results
            ],
        })

    return {
        "path": report.path,
        "run_id": datetime.now().strftime("%Y%m%d-%H%M%S"),
        "timestamp": datetime.now().isoformat(),
        "policy_version": _policy_version(),
        "controls_loaded": report.controls_loaded,
        "controls_run": report.controls_run,
        "total_pass": report.total_pass,
        "total_fail": report.total_fail,
        "total_skip": report.total_skip,
        "total_waived": report.total_waived,
        "score": _compute_score(results),
        "pillar_scores": _pillar_scores(results),
        "detected_regions": [[r, p] for r, p in report.detected_regions],
        "results": results,
    }


# ── Pydantic models ────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    path: str
    iac: str = "terraform"
    pillar: str | None = None
    severity: str | None = None


class WaiverEntry(BaseModel):
    id: str
    reason: str
    owner: str = ""
    expires: str = ""


class WaiversPayload(BaseModel):
    waivers: list[WaiverEntry]


class RiskAcceptanceEntry(BaseModel):
    id: str
    reason: str
    approver: str = ""
    owner: str = ""
    rfc: str = ""
    jira_link: str = ""
    other_link: str = ""
    notes: str = ""
    risk_level: str = "accepted"
    residual_risk: str = "medium"
    expires: str = ""
    accepted_at: str = ""

class RiskAcceptancesPayload(BaseModel):
    acceptances: list[RiskAcceptanceEntry]


class SandboxRequest(BaseModel):
    content: str
    iac: str = "terraform"
    pillar: str | None = None


class AutoFixRequest(BaseModel):
    path: str
    iac: str = "terraform"
    control_ids: list[str] | None = None
    apply: bool = False


class AutoFixRollbackRequest(BaseModel):
    path: str
    iac: str = "terraform"


class AutoFixFindingInput(BaseModel):
    control_id: str
    check_id: str
    resource: str | None = None
    message: str | None = None


class AutoFixClassifyRequest(BaseModel):
    iac: str = "terraform"
    findings: list[AutoFixFindingInput]
    control_ids: list[str] | None = None


# ── Routes ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    controls = _controls_as_dicts()
    waivers = _load_waivers()
    last_results: dict | None = None
    if LAST_RESULTS_FILE.exists():
        with LAST_RESULTS_FILE.open() as fh:
            last_results = json.load(fh)

    risk_acceptances = _load_risk_acceptances()
    html = _render_index(
        controls_json=json.dumps(controls),
        waivers_json=json.dumps(waivers),
        results_json=json.dumps(last_results),
        risk_acceptances_json=json.dumps(risk_acceptances),
    )
    return HTMLResponse(content=html)


@app.get("/api/controls")
async def api_controls():
    return _controls_as_dicts()


@app.get("/api/controls/{control_id}")
async def api_control_detail(control_id: str):
    data = _raw_control(control_id)
    if not data:
        raise HTTPException(status_code=404, detail="Control not found")
    return data


@app.get("/api/waivers")
async def api_get_waivers():
    return _load_waivers()


@app.put("/api/waivers")
async def api_save_waivers(payload: WaiversPayload):
    waivers = {w.id: w.model_dump() for w in payload.waivers}
    _save_waivers(waivers)
    return {"saved": len(waivers)}


@app.delete("/api/waivers/{control_id}")
async def api_delete_waiver(control_id: str):
    waivers = _load_waivers()
    waivers.pop(control_id, None)
    _save_waivers(waivers)
    return {"ok": True}


@app.get("/api/waivers/export")
async def api_export_waivers():
    waivers = _load_waivers()
    skip = {
        "version": "1",
        "waivers": [
            {k: v for k, v in e.items() if v}
            for e in waivers.values()
        ],
    }
    content = yaml.safe_dump(skip, default_flow_style=False, sort_keys=False)
    return Response(
        content=content,
        media_type="text/yaml",
        headers={"Content-Disposition": 'attachment; filename=".wafpass-skip.yml"'},
    )


@app.get("/api/risk-acceptances")
async def api_get_risk_acceptances():
    return _load_risk_acceptances()


@app.put("/api/risk-acceptances")
async def api_save_risk_acceptances(payload: RiskAcceptancesPayload):
    acceptances = {a.id: a.model_dump() for a in payload.acceptances}
    _save_risk_acceptances(acceptances)
    return {"saved": len(acceptances)}


@app.delete("/api/risk-acceptances/{control_id}")
async def api_delete_risk_acceptance(control_id: str):
    acceptances = _load_risk_acceptances()
    acceptances.pop(control_id, None)
    _save_risk_acceptances(acceptances)
    return {"ok": True}


@app.get("/api/risk-acceptances/export")
async def api_export_risk_acceptances():
    acceptances = _load_risk_acceptances()
    content = yaml.safe_dump(
        {"version": "1", "risk_acceptances": [
            {k: v for k, v in e.items() if v}
            for e in acceptances.values()
        ]},
        default_flow_style=False, sort_keys=False,
    )
    return Response(
        content=content,
        media_type="text/yaml",
        headers={"Content-Disposition": 'attachment; filename="risk_acceptances.yml"'},
    )


@app.get("/api/compliance-readiness")
async def api_compliance_readiness():
    """Compute compliance evidence readiness metrics."""
    controls = _controls_as_dicts()
    waivers = _load_waivers()
    risk_acceptances = _load_risk_acceptances()

    # Load results if available
    results = None
    if LAST_RESULTS_FILE.exists():
        with LAST_RESULTS_FILE.open() as fh:
            results = json.load(fh)

    # Framework data from controls mapping
    fw_map = {}
    fw_desc = {
        'GDPR': 'General Data Protection Regulation (EU) 2016/679',
        'ISO 27001:2022': 'Information Security Management Systems',
        'BSI C5:2020': 'Cloud Computing Compliance Criteria Catalogue',
        'EUCS (ENISA)': 'EU Cybersecurity Certification Scheme for Cloud',
        'CSRD': 'Corporate Sustainability Reporting Directive',
    }

    for ctrl in controls:
        for mapping in ctrl.get('regulatory_mapping', []):
            fw_name = mapping['framework']
            if fw_name not in fw_map:
                fw_map[fw_name] = {
                    'name': fw_name,
                    'description': fw_desc.get(fw_name, ''),
                    'controls': [],
                    'mapped': 0,
                }
            fw_map[fw_name]['controls'].append({'id': ctrl['id'], 'title': ctrl['title']})
            fw_map[fw_name]['mapped'] += 1

    # Evidence completeness
    # Check if controls have evidence requirements defined in YAML
    evidence_data = {}
    for ctrl in controls:
        # Controls from YAML may not have evidence field in dict - need raw YAML
        raw = _raw_control(ctrl['id'])
        has_evidence = False
        if raw and 'evidence' in raw:
            evidence = raw.get('evidence', {})
            if evidence.get('required') and len(evidence['required']) > 0:
                has_evidence = True
        for mapping in ctrl.get('regulatory_mapping', []):
            fw_name = mapping['framework']
            if fw_name not in evidence_data:
                evidence_data[fw_name] = {'total': 0, 'complete': 0}
            evidence_data[fw_name]['total'] += 1
            if has_evidence:
                evidence_data[fw_name]['complete'] += 1

    # Controls missing remediation
    controls_without_remediation = [
        {'id': c['id'], 'title': c['title'], 'category': c.get('category', ''), 'severity': c.get('severity', '')}
        for c in controls if not c.get('checks_count', 0) or c.get('description', '').strip() == ''
    ]

    # Calculate metrics
    total_controls = len(controls)
    mapped_controls = sum(1 for c in controls if c.get('regulatory_mapping') and len(c.get('regulatory_mapping', [])) > 0)
    framework_coverage = round(mapped_controls / total_controls * 100) if total_controls > 0 else 0

    # Evidence completeness
    evidence_keys = list(evidence_data.keys())
    if evidence_keys:
        evidence_completeness = round(
            sum(ed['complete'] / ed['total'] * 100 for ed in evidence_data.values()) / len(evidence_keys)
        )
    else:
        evidence_completeness = 0

    # Framework details
    frameworks = []
    for fw_name, fw_data in fw_map.items():
        controls_len = len(fw_data['controls'])
        pct = round(fw_data['mapped'] / controls_len * 100) if controls_len > 0 else 0
        frameworks.append({
            'name': fw_name,
            'description': fw_data['description'],
            'controls': controls_len,
            'pct': pct,
        })
    frameworks.sort(key=lambda x: x['pct'], reverse=True)

    # Readiness score
    findings_without_remediation = len(controls_without_remediation)
    remediation_penalty = min(20, round(findings_without_remediation / total_controls * 20)) if total_controls > 0 else 0
    readiness_score = max(0, round((framework_coverage * 0.4) + (evidence_completeness * 0.4) - remediation_penalty))

    return {
        'totalFrameworkCoverage': framework_coverage,
        'frameworkCount': len(fw_map),
        'evidenceCompleteness': evidence_completeness,
        'findingsWithoutRemediation': findings_without_remediation,
        'readinessScore': readiness_score,
        'frameworks': frameworks,
        'controlsWithoutRemediation': controls_without_remediation[:20],
    }


@app.post("/api/scan")
async def api_run_scan(req: ScanRequest):
    """Run an in-process WAF++ PASS scan and return results as JSON."""
    path = Path(req.path)
    if not path.exists():
        raise HTTPException(status_code=400, detail=f"Path not found: {req.path}")

    try:
        from wafpass.engine import run_controls
        from wafpass.iac import registry
        from wafpass.iac.base import IaCState
        from wafpass.loader import load_controls
        from wafpass.models import Report
        from wafpass.waivers import apply_waivers, load_waivers

        controls = load_controls(CONTROLS_DIR, pillar=req.pillar)
        if not controls:
            raise HTTPException(status_code=422, detail="No controls loaded from controls directory.")

        plugin = registry.get(req.iac.lower())
        if plugin is None:
            raise HTTPException(status_code=422, detail=f"Unknown IaC plugin: {req.iac}")

        state = plugin.parse(path)
        # Extract regions from the parsed IaC state
        detected_regions = plugin.extract_regions(state)
        results = run_controls(controls, state)

        waivers_data = []
        if WAIVERS_FILE.exists():
            waivers_data = load_waivers(WAIVERS_FILE)
        apply_waivers(results, waivers_data)

        # Apply risk acceptances (treated as waivers with richer metadata)
        risk_acceptances_data = _load_risk_acceptances()
        for cr in results:
            ra = risk_acceptances_data.get(cr.control.id)
            if ra and cr.waived_reason is None:
                cr.waived_reason = f"[Risk Accepted by {ra.get('approver', 'N/A')}] {ra.get('reason', '')}"

        report = Report(
            path=str(path),
            controls_loaded=len(controls),
            controls_run=len([r for r in results if r.results]),
            results=results,
            detected_regions=detected_regions,
            source_paths=[str(path)],
        )
        data = _report_to_dict(report)

        # Cache report object for PDF export and persist JSON for next page load
        global _last_report
        _last_report = report
        with LAST_RESULTS_FILE.open("w") as fh:
            json.dump(data, fh, indent=2)

        return data

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/auto-fix")
async def api_auto_fix(req: AutoFixRequest):
    """Build (and optionally apply) a fix plan for failing checks."""
    path = Path(req.path)
    if not path.exists():
        raise HTTPException(status_code=400, detail=f"Path not found: {req.path}")

    try:
        from wafpass.engine import run_controls
        from wafpass.fixer import (
            ResourceLocator,
            FixApplyResult,
            apply_fix_plan,
            build_fix_plan,
            compute_fix_delta,
            render_diff,
        )
        from wafpass.iac import registry
        from wafpass.loader import load_controls
        from wafpass.waivers import apply_waivers, load_waivers

        controls = load_controls(CONTROLS_DIR, ids=req.control_ids)
        if not controls:
            raise HTTPException(status_code=422, detail="No controls loaded.")

        plugin = registry.get(req.iac.lower())
        if plugin is None:
            raise HTTPException(status_code=422, detail=f"Unknown IaC plugin: {req.iac}")

        state = plugin.parse(path)
        results = run_controls(controls, state, engine_name=req.iac.lower())

        waivers_data = []
        if WAIVERS_FILE.exists():
            waivers_data = load_waivers(WAIVERS_FILE)
        apply_waivers(results, waivers_data)

        from wafpass.fixer import make_locator

        source_paths = [path] if path.is_file() else [
            f
            for ext in plugin.file_extensions
            for f in path.rglob(f"*{ext}")
        ]
        locator = make_locator(req.iac.lower(), source_paths).build()

        plan = build_fix_plan(results, state, controls, locator, framework=req.iac.lower())

        base = path if path.is_dir() else path.parent

        patches_data = [
            {
                "file": str(p.file_path.relative_to(base)),
                "address": p.address,
                "attribute": p.attribute_path,
                "kind": p.patch_kind.name,
                "new_value": p.hcl_value,
                "description": p.description,
                "check_id": p.check_id,
                "control_id": p.control_id,
            }
            for p in plan.active_patches
        ]

        skipped_data = [
            {
                "check_id": s.check_id,
                "control_id": s.control_id,
                "address": s.address,
                "attribute": s.attribute,
                "op": s.op,
                "reason": s.reason,
            }
            for s in plan.skipped
        ]

        apply_result = apply_fix_plan(plan, locator, dry_run=not req.apply, backup=req.apply)
        assert isinstance(apply_result, FixApplyResult)

        diff_preview: dict[str, list[str]] = {}
        for fp, (orig, patched) in apply_result.diffs.items():
            diff_lines = render_diff(orig, patched, fp)
            if diff_lines:
                try:
                    rel = str(fp.relative_to(base))
                except ValueError:
                    rel = fp.name
                diff_preview[rel] = diff_lines

        files_modified = sorted(diff_preview.keys())

        response: dict[str, Any] = {
            "patches_count": len(plan.active_patches),
            "skipped_count": len(plan.skipped),
            "files_modified": files_modified,
            "applied": req.apply,
            "patches": patches_data,
            "skipped": skipped_data,
            "diff_preview": diff_preview,
            "warnings": apply_result.warnings,
            "delta": None,
        }

        if req.apply:
            new_state = plugin.parse(path)
            new_results = run_controls(controls, new_state, engine_name=req.iac.lower())
            apply_waivers(new_results, waivers_data)
            response["delta"] = {
                "resolved": compute_fix_delta(results, new_results).resolved,
                "still_failing": compute_fix_delta(results, new_results).still_failing,
                "regressions": compute_fix_delta(results, new_results).regressions,
            }

        return response

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/auto-fix/classify")
async def api_auto_fix_classify(req: AutoFixClassifyRequest):
    """Classify stored findings as fixable or manual without filesystem access."""
    from wafpass.fixer import FindingInput, classify_findings
    from wafpass.loader import load_controls

    controls = load_controls(CONTROLS_DIR, ids=req.control_ids)
    if not controls:
        raise HTTPException(status_code=422, detail="No controls loaded.")

    inputs = [
        FindingInput(
            control_id=f.control_id,
            check_id=f.check_id,
            resource=f.resource,
            message=f.message,
        )
        for f in req.findings
    ]

    plan = classify_findings(inputs, controls, framework=req.iac.lower())

    patches_data = [
        {
            "file": f"{p.address} resource",
            "address": p.address,
            "attribute": p.attribute_path,
            "kind": p.patch_kind.name,
            "new_value": p.hcl_value,
            "description": p.description,
            "check_id": p.check_id,
            "control_id": p.control_id,
        }
        for p in plan.active_patches
    ]

    skipped_data = [
        {
            "check_id": s.check_id,
            "control_id": s.control_id,
            "address": s.address,
            "attribute": s.attribute,
            "op": s.op,
            "reason": s.reason,
        }
        for s in plan.skipped
    ]

    return {
        "patches_count": len(plan.active_patches),
        "skipped_count": len(plan.skipped),
        "files_modified": plan.active_patches and ["Preview derived from scan findings"] or [],
        "applied": False,
        "patches": patches_data,
        "skipped": skipped_data,
        "diff_preview": {},
        "warnings": ["Local-only preview: no filesystem access, so diffs are not generated. Use the CLI command below to apply fixes locally."],
        "delta": None,
    }


@app.post("/api/auto-fix/rollback")
async def api_auto_fix_rollback(req: AutoFixRollbackRequest):
    """Restore IaC source files from their .bak backups."""
    from wafpass.fixer import restore_backup
    from wafpass.iac import registry

    path = Path(req.path)
    if not path.exists():
        raise HTTPException(status_code=400, detail=f"Path not found: {req.path}")

    plugin = registry.get(req.iac.lower())
    if plugin is None:
        raise HTTPException(status_code=422, detail=f"Unknown IaC plugin: {req.iac}")

    ext_set = set(plugin.file_extensions)
    if path.is_file():
        files = [path]
    else:
        files = sorted({
            f
            for ext in plugin.file_extensions
            for f in path.rglob(f"*{ext}")
        })

    restored: list[str] = []
    missing: list[str] = []
    for source_file in files:
        if source_file.suffix not in ext_set:
            continue
        if restore_backup(source_file):
            restored.append(str(source_file))
        else:
            missing.append(str(source_file))

    return {"restored": restored, "missing": missing}


@app.get("/api/results")
async def api_get_results():
    if not LAST_RESULTS_FILE.exists():
        return None
    with LAST_RESULTS_FILE.open() as fh:
        return json.load(fh)


@app.post("/api/scan/sandbox")
async def api_sandbox_scan(req: SandboxRequest):
    """Scan raw IaC content provided as a string (writes to a temp file, never persisted)."""
    if not req.content.strip():
        raise HTTPException(status_code=400, detail="Content cannot be empty.")
    try:
        from wafpass.engine import run_controls
        from wafpass.iac import registry
        from wafpass.loader import load_controls
        from wafpass.models import Report
        from wafpass.waivers import apply_waivers, load_waivers

        controls = load_controls(CONTROLS_DIR, pillar=req.pillar)
        if not controls:
            raise HTTPException(status_code=422, detail="No controls loaded from controls directory.")

        plugin = registry.get(req.iac.lower())
        if plugin is None:
            raise HTTPException(status_code=422, detail=f"Unknown IaC plugin: {req.iac}")

        with tempfile.TemporaryDirectory() as tmpdir:
            tf_file = Path(tmpdir) / "sandbox.tf"
            tf_file.write_text(req.content, encoding="utf-8")
            state = plugin.parse(Path(tmpdir))
            detected_regions = plugin.extract_regions(state)
            results = run_controls(controls, state)

        waivers_data = []
        if WAIVERS_FILE.exists():
            waivers_data = load_waivers(WAIVERS_FILE)
        apply_waivers(results, waivers_data)

        # Apply risk acceptances (treated as waivers with richer metadata)
        risk_acceptances_data = _load_risk_acceptances()
        for cr in results:
            ra = risk_acceptances_data.get(cr.control.id)
            if ra and cr.waived_reason is None:
                cr.waived_reason = f"[Risk Accepted by {ra.get('approver', 'N/A')}] {ra.get('reason', '')}"

        report = Report(
            path="sandbox",
            controls_loaded=len(controls),
            controls_run=len([r for r in results if r.results]),
            results=results,
            detected_regions=detected_regions,
            source_paths=["sandbox.tf"],
        )
        return _report_to_dict(report)

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/export/pdf")
async def api_export_pdf():
    """Export the last scan results as a PDF report."""
    if _last_report is None:
        raise HTTPException(status_code=400, detail="No scan results available. Run a scan first.")
    try:
        from wafpass.pdf_reporter import generate_pdf
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="PDF export requires reportlab. Install with: pip install wafpass[pdf]",
        )
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        generate_pdf(_last_report, tmp_path)
        pdf_bytes = tmp_path.read_bytes()
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="wafpass-report.pdf"'},
    )


# ── Entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("serve.app:app", host="0.0.0.0", port=8080, reload=True)
