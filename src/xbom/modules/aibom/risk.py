"""Risk scoring for AI-BOM components.

Weights and severity thresholds loaded from rules/risk.yaml.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------

_RULES_DIR = Path(__file__).parent / "rules"
_risk_config: dict[str, Any] | None = None


def _load_risk_config() -> dict[str, Any]:
    global _risk_config
    if _risk_config is None:
        with open(_RULES_DIR / "risk.yaml") as f:
            _risk_config = yaml.safe_load(f)
    return _risk_config


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class RiskAssessment:
    score: int = 0
    severity: Severity = Severity.INFO
    factors: list[str] = field(default_factory=list)

    def to_properties(self) -> list[dict[str, str]]:
        """Convert to CycloneDX property list."""
        props = [
            {"name": "xbom:ai:risk_score", "value": str(self.score)},
            {"name": "xbom:ai:risk_severity", "value": self.severity.value},
        ]
        if self.factors:
            props.append({"name": "xbom:ai:risk_factors", "value": ", ".join(self.factors)})
        return props


def score_component(flags: list[str]) -> RiskAssessment:
    """Score a component's risk based on its flags.

    Args:
        flags: List of risk flag names (e.g. ["hardcoded_api_key", "deprecated_model"]).

    Returns:
        RiskAssessment with score (0-100), severity, and contributing factors.
    """
    config = _load_risk_config()
    weights: dict[str, int] = config["weights"]
    thresholds = config["severity_thresholds"]

    total = 0
    factors = []

    for flag in flags:
        weight = weights.get(flag, 0)
        if weight > 0:
            total += weight
            factors.append(f"{flag} (+{weight})")

    total = min(total, 100)

    if total >= thresholds["critical"]:
        severity = Severity.CRITICAL
    elif total >= thresholds["high"]:
        severity = Severity.HIGH
    elif total >= thresholds["medium"]:
        severity = Severity.MEDIUM
    elif total >= thresholds["low"]:
        severity = Severity.LOW
    else:
        severity = Severity.INFO

    return RiskAssessment(score=total, severity=severity, factors=factors)


def score_bom_components(bom: dict[str, Any]) -> None:
    """Add risk scores to all AI-BOM components in-place."""
    for comp in bom.get("components", []):
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}

        flags: list[str] = []

        # Derive flags from existing properties
        scanner = props.get("xbom:ai:scanner", "")
        category = props.get("xbom:ai:category", "")

        if scanner == "api-key-scanner" or category == "api-key-reference":
            flags.append("hardcoded_api_key")

        if props.get("xbom:ai:shadow_ai") == "true":
            flags.append("shadow_ai")

        if props.get("xbom:ai:deprecated") == "true":
            flags.append("deprecated_model")

        if category == "endpoint" and "localhost" not in props.get("xbom:ai:description", ""):
            flags.append("internet_facing")

        if scanner == "config-file-scanner" and "mcp" in props.get("xbom:ai:description", "").lower():
            flags.append("mcp_unknown_server")

        if not flags:
            continue

        assessment = score_component(flags)
        for prop in assessment.to_properties():
            comp.setdefault("properties", []).append(prop)
