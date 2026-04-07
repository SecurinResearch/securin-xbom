"""Post-Quantum Cryptography safety classification for CBOM components.

Classification tables loaded from rules/pqc.yaml.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import yaml

from xbom.utils.cyclonedx import add_property

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# YAML loading
# --------------------------------------------------------------------------- #

_RULES_DIR = Path(__file__).parent / "rules"
_pqc_config: dict[str, Any] | None = None


def _load_pqc_config() -> dict[str, Any]:
    global _pqc_config
    if _pqc_config is None:
        with open(_RULES_DIR / "pqc.yaml") as f:
            _pqc_config = yaml.safe_load(f)
    return _pqc_config


def _get_quantum_vulnerable() -> set[str]:
    return set(_load_pqc_config()["quantum_vulnerable"])


def _get_quantum_safe_levels() -> dict[str, tuple[int, str]]:
    raw = _load_pqc_config()["quantum_safe_levels"]
    return {k: (v["level"], v["note"]) for k, v in raw.items()}


def _get_pqc_algorithms() -> dict[str, tuple[int, str]]:
    raw = _load_pqc_config()["pqc_algorithms"]
    return {k: (v["level"], v["note"]) for k, v in raw.items()}


def _get_vuln_reasons() -> dict[str, str]:
    return _load_pqc_config()["vuln_reasons"]


def _get_alias_map() -> dict[str, str]:
    return _load_pqc_config()["aliases"]


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def annotate_pqc_safety(bom: dict[str, Any]) -> dict[str, Any]:
    """Classify all CBOM components for post-quantum safety. Modifies BOM in-place.

    Returns summary dict with counts:
        total, vulnerable, weakened, safe, pqc, unknown, readiness_pct
    """
    counts = {"total": 0, "vulnerable": 0, "weakened": 0, "safe": 0, "pqc": 0, "unknown": 0}

    for comp in bom.get("components", []):
        if _get_prop(comp, "xbom:crypto:detected") != "true":
            continue

        counts["total"] += 1
        status, level, reason = _classify_component(comp)

        add_property(comp, "xbom:crypto:quantum_safe",
                     "true" if status in ("safe", "pqc") else
                     "false" if status in ("vulnerable", "weakened") else "unknown")
        add_property(comp, "xbom:crypto:quantum_status", status)
        if reason:
            add_property(comp, "xbom:crypto:quantum_reason", reason)

        # Set nistQuantumSecurityLevel in cryptoProperties
        if level is not None:
            crypto_props = comp.setdefault("cryptoProperties", {})
            algo_props = crypto_props.setdefault("algorithmProperties", {})
            algo_props["nistQuantumSecurityLevel"] = level

        # Append quantum_vulnerable weakness for risk scoring
        if status == "vulnerable":
            _append_weakness(comp, "quantum_vulnerable")

        counts[status] = counts.get(status, 0) + 1

    # Compute readiness percentage
    total = counts["total"]
    if total > 0:
        ready = counts["safe"] + counts["pqc"]
        counts["readiness_pct"] = round(ready / total * 100)
    else:
        counts["readiness_pct"] = 100  # no crypto = nothing to migrate

    logger.info(
        "PQC analysis: %d total, %d vulnerable, %d weakened, %d safe, %d PQC, %d unknown (%d%% ready)",
        total, counts["vulnerable"], counts["weakened"], counts["safe"],
        counts["pqc"], counts["unknown"], counts["readiness_pct"],
    )

    return counts


# --------------------------------------------------------------------------- #
# Classification logic
# --------------------------------------------------------------------------- #


def _classify_component(comp: dict[str, Any]) -> tuple[str, int | None, str]:
    """Classify a single component. Returns (status, nist_level, reason)."""
    pqc_algorithms = _get_pqc_algorithms()
    quantum_vulnerable = _get_quantum_vulnerable()
    quantum_safe_levels = _get_quantum_safe_levels()
    vuln_reasons = _get_vuln_reasons()

    # Check if PQC rule detected it
    rule_id = _get_prop(comp, "xbom:crypto:rule_id") or ""
    pqc_status_meta = _get_prop(comp, "xbom:crypto:pqc_status") or ""

    if "pqc-library" in rule_id or pqc_status_meta == "migration_in_progress":
        name = comp.get("name", "PQC")
        norm = _normalize(name)
        if norm in pqc_algorithms:
            level, note = pqc_algorithms[norm]
            return "pqc", level, note
        return "pqc", 3, f"Post-quantum library detected: {name}"

    if "pqc-vulnerable" in rule_id:
        name = comp.get("name", "unknown")
        norm = _normalize(name)
        reason = vuln_reasons.get(norm, f"{name} is vulnerable to quantum attacks")
        return "vulnerable", 0, reason

    # Classify by algorithm name
    name = comp.get("name", "")
    norm = _normalize(name)

    # Check PQC algorithms first
    if norm in pqc_algorithms:
        level, note = pqc_algorithms[norm]
        return "pqc", level, note

    # Check quantum-vulnerable
    if norm in quantum_vulnerable:
        reason = vuln_reasons.get(norm, f"{name} is vulnerable to quantum attacks (Shor's algorithm)")
        return "vulnerable", 0, reason

    # Check safe/weakened symmetric and hash
    if norm in quantum_safe_levels:
        level, note = quantum_safe_levels[norm]
        if level <= 1 and norm in ("aes-128", "3des", "des"):
            return "weakened", level, note
        return "safe", level, note

    # Try to extract algorithm family from compound names
    family = _extract_family(name, comp)
    if family:
        return _classify_by_family(family, name, comp)

    # Check certificate signature algorithms
    crypto_props = comp.get("cryptoProperties", {})
    cert_props = crypto_props.get("certificateProperties", {})
    sig_algo = cert_props.get("signatureAlgorithmRef", "")
    if sig_algo:
        sig_norm = _normalize(sig_algo)
        sig_family = _extract_family(sig_algo, comp)
        if sig_family and sig_family in quantum_vulnerable:
            return "vulnerable", 0, f"Certificate signed with quantum-vulnerable {sig_algo}"
        if sig_norm in quantum_vulnerable:
            return "vulnerable", 0, f"Certificate signed with quantum-vulnerable {sig_algo}"

    return "unknown", None, ""


def _classify_by_family(family: str, orig_name: str, comp: dict[str, Any]) -> tuple[str, int | None, str]:
    """Classify based on extracted algorithm family."""
    pqc_algorithms = _get_pqc_algorithms()
    quantum_vulnerable = _get_quantum_vulnerable()
    quantum_safe_levels = _get_quantum_safe_levels()
    vuln_reasons = _get_vuln_reasons()

    if family in quantum_vulnerable:
        reason = vuln_reasons.get(family, f"{orig_name} is vulnerable to quantum attacks")
        return "vulnerable", 0, reason
    if family in pqc_algorithms:
        level, note = pqc_algorithms[family]
        return "pqc", level, note
    # Try with key size for AES
    param = comp.get("cryptoProperties", {}).get("algorithmProperties", {}).get("parameterSetIdentifier", "")
    if family == "aes" and param:
        aes_key = f"aes-{param}"
        if aes_key in quantum_safe_levels:
            level, note = quantum_safe_levels[aes_key]
            if level <= 1:
                return "weakened", level, note
            return "safe", level, note
    if family in quantum_safe_levels:
        level, note = quantum_safe_levels[family]
        if level <= 1 and family in ("aes-128", "3des", "des"):
            return "weakened", level, note
        return "safe", level, note
    return "unknown", None, ""


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

# Pattern to strip key sizes and modes from algorithm names
_STRIP_RE = re.compile(r"[-_/]?\d+[-_]?(bit|gcm|cbc|ecb|ctr|cfb|ofb|ccm|xts)?$", re.IGNORECASE)


def _normalize(name: str) -> str:
    """Normalize an algorithm name for lookup."""
    quantum_vulnerable = _get_quantum_vulnerable()
    quantum_safe_levels = _get_quantum_safe_levels()
    pqc_algorithms = _get_pqc_algorithms()
    alias_map = _get_alias_map()

    n = name.lower().strip()
    # Direct match first
    if n in quantum_vulnerable or n in quantum_safe_levels or n in pqc_algorithms:
        return n
    # Check aliases
    if n in alias_map:
        return alias_map[n]
    # Try with common separators normalized
    n2 = n.replace("_", "-").replace(" ", "-")
    if n2 in quantum_vulnerable or n2 in quantum_safe_levels or n2 in pqc_algorithms:
        return n2
    return n


def _extract_family(name: str, comp: dict[str, Any]) -> str | None:
    """Extract the base algorithm family from compound names like 'RSA-2048', 'AES-256-GCM'."""
    quantum_vulnerable = _get_quantum_vulnerable()
    quantum_safe_levels = _get_quantum_safe_levels()
    pqc_algorithms = _get_pqc_algorithms()

    n = name.lower().strip()
    # Common patterns: "SHA256withRSA", "SHA384withECDSA"
    if "with" in n:
        parts = n.split("with")
        return _normalize(parts[-1])
    # "RSA-2048", "AES-256-GCM", "ECDSA-P256"
    stripped = _STRIP_RE.sub("", n).rstrip("-_ ")
    if stripped and stripped != n:
        norm = _normalize(stripped)
        if norm in quantum_vulnerable or norm in quantum_safe_levels or norm in pqc_algorithms:
            return norm
    # First token before dash/space/underscore
    first = re.split(r"[-_ /]", n)[0]
    norm_first = _normalize(first)
    if norm_first in quantum_vulnerable or norm_first in quantum_safe_levels or norm_first in pqc_algorithms:
        return norm_first
    return None


def _get_prop(comp: dict[str, Any], name: str) -> str | None:
    """Read a property value from a component."""
    for p in comp.get("properties", []):
        if p.get("name") == name:
            return p.get("value")
    return None


def _append_weakness(comp: dict[str, Any], flag: str) -> None:
    """Append a weakness flag to the xbom:crypto:weakness property."""
    existing = _get_prop(comp, "xbom:crypto:weakness") or ""
    flags = [f.strip() for f in existing.split(",") if f.strip()]
    if flag not in flags:
        flags.append(flag)
        add_property(comp, "xbom:crypto:weakness", ",".join(flags))
