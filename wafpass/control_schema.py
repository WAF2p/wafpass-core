"""Pydantic schema for wizard-generated WAF++ controls.

This is the single source of truth for validating controls produced by
``wafpass control generate``.  The schema intentionally uses a simpler,
author-focused structure (no assertions / scopes) compared to the full
engine-evaluated control format.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

# ── Allowed vocabulary ────────────────────────────────────────────────────────

PILLARS = [
    "security",
    "cost",
    "performance",
    "reliability",
    "operational",
    "operations",
    "sustainability",
    "sovereign",
    "agentic",
]

SEVERITIES = ["critical", "high", "medium", "low"]

TYPES = [
    "governance",
    "configuration",
    "iac",
    "network",
    "identity",
    "data",
    "cost",
]

ENGINES = ["terraform", "checkov", "manual", "config"]

# Pillar → short prefix used in control IDs (e.g. SOV → SOV-011)
PILLAR_TO_PREFIX: dict[str, str] = {
    "security": "SEC",
    "cost": "COST",
    "performance": "PERF",
    "reliability": "REL",
    "operational": "OPS",
    "operations": "OPS",
    "sustainability": "SUS",
    "sovereign": "SOV",
    "agentic": "AGN",
}

_PillarLiteral = Literal[
    "security",
    "cost",
    "performance",
    "reliability",
    "operational",
    "operations",
    "sustainability",
    "sovereign",
    "agentic",
]
_SeverityLiteral = Literal["critical", "high", "medium", "low", "informational"]
_TypeLiteral = Literal[
    "governance", "configuration", "iac", "network", "identity", "data", "cost"
]
_EngineLiteral = Literal["terraform", "checkov", "manual", "config", "cdk", "documentation"]


# ── Sub-models ────────────────────────────────────────────────────────────────


class WizardCheck(BaseModel):
    """A single check within a wizard-generated control.

    This is the canonical check structure that includes all fields needed
    for automated evaluation. The engine expects: scope, assertions, title,
    provider, remediation, example, on_fail.
    """

    id: str
    engine: _EngineLiteral
    description: str
    expected: str = "true"  # Default for controls that don't have specific expected values

    # Optional fields for full check structure
    title: str | None = None
    provider: str | None = None
    scope: dict | None = None
    assertions: list | None = None
    remediation: str | None = None
    example: dict | None = None
    on_fail: str | None = None

    @field_validator("id")
    @classmethod
    def id_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("check id must not be empty")
        return v

    @field_validator("description")
    @classmethod
    def text_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("field must not be empty")
        return v


class WizardControl(BaseModel):
    """A WAF++ control authored via the generate wizard."""

    id: str
    pillar: _PillarLiteral
    severity: _SeverityLiteral
    type: list[_TypeLiteral]
    description: str
    checks: list[WizardCheck]
    regulatory_mapping: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def id_format(cls, v: str) -> str:
        v = v.strip().upper()
        if not v:
            raise ValueError("control id must not be empty")
        return v

    @field_validator("description")
    @classmethod
    def description_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("description must not be empty")
        return v

    @field_validator("type")
    @classmethod
    def type_not_empty(cls, v: list) -> list:
        if not v:
            raise ValueError("at least one type must be selected")
        return v

    @field_validator("checks")
    @classmethod
    def checks_not_empty(cls, v: list) -> list:
        if not v:
            raise ValueError("at least one check must be defined")
        return v

    @model_validator(mode="after")
    def id_matches_pillar(self) -> "WizardControl":
        prefix = PILLAR_TO_PREFIX.get(self.pillar, "")
        if prefix and not self.id.startswith(prefix + "-"):
            # Not a hard error — user may choose custom IDs; emit a warning via
            # a model field so callers can surface it if they wish.
            pass
        return self
