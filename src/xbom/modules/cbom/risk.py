"""Risk scoring for CBOM components.

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


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CryptoRiskAssessment:
    score: int = 0
    severity: Severity = Severity.INFO
    factors: list[str] = field(default_factory=list)

    def to_properties(self) -> list[dict[str, str]]:
        """Convert to CycloneDX property list."""
        props = [
            {"name": "xbom:crypto:risk_score", "value": str(self.score)},
            {"name": "xbom:crypto:risk_severity", "value": self.severity.value},
        ]
        if self.factors:
            props.append({"name": "xbom:crypto:risk_factors", "value": ", ".join(self.factors)})
        return props


def score_component(flags: list[str]) -> CryptoRiskAssessment:
    """Score a crypto component's risk based on its weakness flags.

    Args:
        flags: List of weakness names (e.g. ["weak_algorithm", "small_key_size"]).

    Returns:
        CryptoRiskAssessment with score (0-100), severity, and factors.
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

    return CryptoRiskAssessment(score=total, severity=severity, factors=factors)


def score_cbom_components(bom: dict[str, Any]) -> None:
    """Add risk scores to all CBOM components in-place."""
    for comp in bom.get("components", []):
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}

        # Already scored
        if "xbom:crypto:risk_score" in props:
            continue

        # Only score crypto components
        if props.get("xbom:crypto:detected") != "true":
            continue

        # Collect weakness flags
        weakness_str = props.get("xbom:crypto:weakness", "")
        flags = [w.strip() for w in weakness_str.split(",") if w.strip()]

        if not flags:
            continue

        assessment = score_component(flags)
        for prop in assessment.to_properties():
            comp.setdefault("properties", []).append(prop)
