"""Risk scoring for API-BOM components and services.

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
class ApiRiskAssessment:
    score: int = 0
    severity: Severity = Severity.INFO
    factors: list[str] = field(default_factory=list)

    def to_properties(self) -> list[dict[str, str]]:
        """Convert to CycloneDX property list."""
        props = [
            {"name": "xbom:api:risk_score", "value": str(self.score)},
            {"name": "xbom:api:risk_severity", "value": self.severity.value},
        ]
        if self.factors:
            props.append({"name": "xbom:api:risk_factors", "value": ", ".join(self.factors)})
        return props


def score_risk(flags: list[str]) -> ApiRiskAssessment:
    """Score an API component/service risk based on flags.

    Args:
        flags: List of risk factor names (e.g. ["no_authentication", "admin_endpoint_exposed"]).

    Returns:
        ApiRiskAssessment with score (0-100), severity, and factors.
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

    return ApiRiskAssessment(score=total, severity=severity, factors=factors)


def score_apibom(bom: dict[str, Any]) -> None:
    """Add risk scores to all API-BOM services and components in-place."""
    config = _load_risk_config()
    sensitive_keywords = config.get("sensitive_path_keywords", [])
    admin_keywords = config.get("admin_path_keywords", [])

    # Score services (internal endpoints)
    for svc in bom.get("services", []):
        flags = _assess_service_risk(svc, sensitive_keywords, admin_keywords)
        if flags:
            assessment = score_risk(flags)
            for prop in assessment.to_properties():
                svc.setdefault("properties", []).append(prop)

    # Score components (external dependencies)
    for comp in bom.get("components", []):
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        if props.get("xbom:api:category") == "external-dependency":
            flags = _assess_external_risk(comp, props)
            if flags:
                assessment = score_risk(flags)
                for prop in assessment.to_properties():
                    comp.setdefault("properties", []).append(prop)


def _assess_service_risk(
    svc: dict[str, Any],
    sensitive_keywords: list[str],
    admin_keywords: list[str],
) -> list[str]:
    """Determine risk flags for an internal API service."""
    flags: list[str] = []
    props = {p["name"]: p["value"] for p in svc.get("properties", [])}

    # Check auth coverage
    if props.get("xbom:api:auth_coverage") == "0%":
        flags.append("no_authentication")

    # Check endpoints for sensitive/admin paths
    endpoints = svc.get("endpoints", [])
    for ep in endpoints:
        ep_lower = ep.lower()
        if any(kw in ep_lower for kw in sensitive_keywords):
            flags.append("sensitive_data_exposure")
            break

    for ep in endpoints:
        ep_lower = ep.lower()
        if any(kw in ep_lower for kw in admin_keywords):
            flags.append("admin_endpoint_exposed")
            break

    return flags


def _assess_external_risk(comp: dict[str, Any], props: dict[str, str]) -> list[str]:
    """Determine risk flags for an external API dependency."""
    flags: list[str] = []

    if props.get("xbom:api:uses_tls") == "false":
        flags.append("external_api_no_tls")

    return flags
