"""Run state versioning and change tracking for WAF++ PASS.

Each run is saved as a versioned JSON snapshot under a state directory
(default: .wafpass-state/). An index.json tracks all runs for fast listing.
The schema is designed to be consumed by external dashboards (e.g. Grafana).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from wafpass import __version__

STATE_SCHEMA_VERSION = 1

_SEV_WEIGHTS: dict[str, int] = {
    "critical": 10,
    "high": 6,
    "medium": 3,
    "low": 1,
}


# ── Snapshot building ──────────────────────────────────────────────────────────

def generate_run_id() -> str:
    """Return a unique run ID: YYYYMMDD-HHMMSS-<8-char hash>."""
    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y%m%d-%H%M%S")
    suffix = hashlib.md5(now.isoformat().encode()).hexdigest()[:8]
    return f"{ts}-{suffix}"


def build_run_snapshot(report, run_id: str, iac_plugin: str, stage: str = "") -> dict:
    """Build a full JSON-serialisable run snapshot from a Report object.

    The snapshot is the unit of persistence — one file per run.
    Schema version is included so future tools can migrate older files.
    """
    total_w = fail_w = 0
    pillar_data: dict[str, dict] = {}
    control_statuses: dict[str, str] = {}
    control_details: dict[str, dict] = {}

    for cr in report.results:
        w = _SEV_WEIGHTS.get((cr.control.severity or "low").lower(), 1)
        total_w += w
        pillar = (cr.control.pillar or "unknown").lower()
        if pillar not in pillar_data:
            pillar_data[pillar] = {"total_w": 0, "fail_w": 0}
        pillar_data[pillar]["total_w"] += w
        if cr.status == "FAIL":
            fail_w += w
            pillar_data[pillar]["fail_w"] += w

        control_statuses[cr.control.id] = cr.status
        control_details[cr.control.id] = {
            "status": cr.status,
            "severity": cr.control.severity,
            "pillar": cr.control.pillar,
            "title": cr.control.title,
            "check_results": [
                {
                    "check_id": r.check_id,
                    "status": r.status,
                    "resource": r.resource,
                    "message": r.message,
                }
                for r in cr.results
            ],
        }

    score = int(fail_w / max(total_w, 1) * 100)

    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool_version": __version__,
        "iac_plugin": iac_plugin,
        "stage": stage,
        "source_paths": report.source_paths,
        "detected_regions": [
            {"region": r, "provider": p, "availability_zone": az} for r, p, az in report.detected_regions
        ],
        "score": score,
        "totals": {
            "controls_run": report.controls_run,
            "pass": report.total_pass,
            "fail": report.total_fail,
            "skip": report.total_skip,
            "waived": report.total_waived,
        },
        "pillar_scores": {
            p: int(d["fail_w"] / max(d["total_w"], 1) * 100)
            for p, d in pillar_data.items()
        },
        "control_statuses": control_statuses,
        "control_details": control_details,
    }


# ── Diff / change detection ────────────────────────────────────────────────────

def compute_diff(previous: dict, current: dict) -> dict:
    """Compute status changes between two run snapshots.

    Returns a diff dict with:
      - previous_run_id / previous_generated_at: provenance
      - score_delta: positive = worse, negative = improved
      - regressions: controls that newly entered FAIL state
      - improvements: controls that left FAIL state
      - other_changes: any other status transition
    """
    prev_statuses: dict[str, str] = previous.get("control_statuses", {})
    curr_statuses: dict[str, str] = current.get("control_statuses", {})

    regressions: list[dict] = []
    improvements: list[dict] = []
    other_changes: list[dict] = []

    all_ids = set(prev_statuses) | set(curr_statuses)
    for cid in sorted(all_ids):
        prev_s = prev_statuses.get(cid)
        curr_s = curr_statuses.get(cid)
        if prev_s == curr_s:
            continue

        detail = current.get("control_details", {}).get(cid, {})
        entry = {
            "control_id": cid,
            "from": prev_s,
            "to": curr_s,
            "title": detail.get("title", ""),
            "severity": detail.get("severity", ""),
            "pillar": detail.get("pillar", ""),
        }

        if curr_s == "FAIL":
            regressions.append(entry)
        elif prev_s == "FAIL":
            improvements.append(entry)
        else:
            other_changes.append(entry)

    score_delta = current["score"] - previous.get("score", current["score"])

    return {
        "previous_run_id": previous.get("run_id"),
        "previous_generated_at": previous.get("generated_at"),
        "score_delta": score_delta,
        "regressions": regressions,
        "improvements": improvements,
        "other_changes": other_changes,
    }


# ── Persistence ───────────────────────────────────────────────────────────────

def save_run(snapshot: dict, state_dir: Path) -> Path:
    """Persist a run snapshot and update the state index.

    Layout:
        <state_dir>/
          index.json           — lightweight index of all runs
          runs/
            run-<run_id>.json  — full snapshot for each run
    """
    runs_dir = state_dir / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    run_id = snapshot["run_id"]
    run_file = runs_dir / f"run-{run_id}.json"

    # Refuse to overwrite a validated/locked run snapshot.
    locked_file = runs_dir / f"run-{run_id}-validated.json"
    if locked_file.exists():
        raise RuntimeError(
            f"Run {run_id} has been validated and is locked. "
            "Delete the validation envelope before overwriting."
        )

    run_file.write_text(json.dumps(snapshot, indent=2, default=str), encoding="utf-8")

    # Update (or create) index
    index_file = state_dir / "index.json"
    if index_file.exists():
        try:
            index = json.loads(index_file.read_text(encoding="utf-8"))
        except Exception:
            index = {"schema_version": STATE_SCHEMA_VERSION, "runs": []}
    else:
        index = {"schema_version": STATE_SCHEMA_VERSION, "runs": []}

    index["runs"].append({
        "run_id": run_id,
        "generated_at": snapshot["generated_at"],
        "tool_version": snapshot["tool_version"],
        "iac_plugin": snapshot["iac_plugin"],
        "stage": snapshot.get("stage", ""),
        "score": snapshot["score"],
        "totals": snapshot["totals"],
        "file": run_file.name,
        "validated": False,
        "validation_id": None,
        "validation_envelope": None,
    })

    index_file.write_text(json.dumps(index, indent=2, default=str), encoding="utf-8")
    return run_file


def load_latest_run(state_dir: Path) -> dict | None:
    """Load the most recent run snapshot from the state directory, or None."""
    index_file = state_dir / "index.json"
    if not index_file.exists():
        return None
    try:
        index = json.loads(index_file.read_text(encoding="utf-8"))
    except Exception:
        return None

    runs = index.get("runs", [])
    if not runs:
        return None

    # Index entries are appended in order — last entry is most recent
    latest_entry = runs[-1]
    run_file = state_dir / "runs" / latest_entry["file"]
    if not run_file.exists():
        return None
    try:
        return json.loads(run_file.read_text(encoding="utf-8"))
    except Exception:
        return None


def load_run(run_id: str, state_dir: Path) -> dict | None:
    """Load a specific run by run_id from the state directory, or None."""
    # Prefer the locked validated snapshot if it exists.
    run_file = state_dir / "runs" / f"run-{run_id}-validated.json"
    if not run_file.exists():
        run_file = state_dir / "runs" / f"run-{run_id}.json"
    if not run_file.exists():
        return None
    try:
        return json.loads(run_file.read_text(encoding="utf-8"))
    except Exception:
        return None


def is_locked(run_id: str, state_dir: Path) -> bool:
    """Return True if the run has been validated and locked locally."""
    return (state_dir / "runs" / f"run-{run_id}-validated.json").exists()


def lock_run(
    run_id: str,
    state_dir: Path,
    validation_id: str,
    validation_envelope: Path | None = None,
) -> Path:
    """Lock a run snapshot after official validation.

    The run file is renamed to run-<run_id>-validated.json and made
    read-only. The index entry is updated to record the validation.
    """
    runs_dir = state_dir / "runs"
    original = runs_dir / f"run-{run_id}.json"
    locked = runs_dir / f"run-{run_id}-validated.json"

    if not original.exists():
        raise FileNotFoundError(f"Run file not found: {original}")

    # Move the snapshot to its immutable name.
    if locked.exists():
        raise RuntimeError(f"Run {run_id} is already locked.")
    original.rename(locked)

    # Make it read-only (best-effort on all platforms).
    import os

    try:
        os.chmod(locked, 0o444)
    except (OSError, NotImplementedError):
        pass

    # Update the index entry.
    index_file = state_dir / "index.json"
    if index_file.exists():
        try:
            index = json.loads(index_file.read_text(encoding="utf-8"))
        except Exception:
            index = {"schema_version": STATE_SCHEMA_VERSION, "runs": []}
    else:
        index = {"schema_version": STATE_SCHEMA_VERSION, "runs": []}

    for entry in index.get("runs", []):
        if entry.get("run_id") == run_id:
            entry["validated"] = True
            entry["validation_id"] = validation_id
            entry["file"] = locked.name
            if validation_envelope is not None:
                entry["validation_envelope"] = str(validation_envelope)
            break

    index_file.write_text(json.dumps(index, indent=2, default=str), encoding="utf-8")
    return locked
