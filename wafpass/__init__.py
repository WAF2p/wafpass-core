"""WAF++ PASS core library — public API.

Quick start
-----------
::

    from wafpass import run_scan, WafpassResultSchema

    result: WafpassResultSchema = run_scan(
        paths=["infra/"],
        controls_dir="controls/",
    )
    print(result.score)

Public symbols
--------------
* :func:`run_scan`             — run a compliance scan, return a result schema object
* :class:`WafpassResultSchema` — Pydantic model for the wafpass-result.json contract
* :class:`FindingSchema`       — Pydantic model for a single finding within a result
* :class:`Report`              — internal dataclass report (pre-schema, for CLI/PDF use)
* ``IaCPlugin``, ``IaCBlock``, ``IaCState`` — protocol types for IaC adapters
"""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("wafpass-core")
except PackageNotFoundError:
    __version__ = "1.1.2"

__name_full__ = "WAF++ PASS"

# ── Result schema (public contract) ───────────────────────────────────────────
from wafpass.schema import (  # noqa: E402
    FindingSchema,
    LocalAttestationSchema,
    ServerValidationSchema,
    ValidationEnvelopeSchema,
    WafpassResultSchema,
)

# ── Internal report model (used by CLI, PDF reporter, etc.) ───────────────────
from wafpass.models import Report  # noqa: E402

# ── IaC adapter protocol types ────────────────────────────────────────────────
from wafpass.iac.base import IaCBlock, IaCPlugin, IaCState  # noqa: E402


from pathlib import Path
from typing import List, Optional


def run_scan(
    paths: List[str],
    controls_dir: str = "controls/",
    *,
    severity_filter: Optional[str] = None,
    waivers_file: Optional[str] = None,
) -> "WafpassResultSchema":
    """Run a WAF++ PASS compliance scan and return a structured result.

    This is the convenience public API wrapper around
    :func:`wafpass.runner.run_scan`. For full control (project, branch, secret
    scanning, source snapshots, etc.) use :class:`wafpass.runner.ScanConfig`
    directly.
    """
    from wafpass.runner import ScanConfig, run_scan as _run_scan

    _, schema = _run_scan(ScanConfig(
        paths=[Path(p) for p in paths],
        controls_dir=Path(controls_dir),
        severity=severity_filter,
        waivers_file=Path(waivers_file) if waivers_file else None,
    ))
    return schema


__all__ = [
    "__version__",
    "__name_full__",
    "run_scan",
    "WafpassResultSchema",
    "FindingSchema",
    "LocalAttestationSchema",
    "ServerValidationSchema",
    "ValidationEnvelopeSchema",
    "Report",
    "IaCPlugin",
    "IaCBlock",
    "IaCState",
]
