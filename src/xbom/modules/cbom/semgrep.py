"""Semgrep-based cryptographic pattern detection (Layer 1)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from xbom.models import ScanConfig
from xbom.utils.subprocess import find_tool, run

logger = logging.getLogger(__name__)

# Semgrep registry rulesets to attempt (hybrid approach).
# These supplement the custom rules in rules/ directory.
# If any fail (e.g. offline), we fall back to custom-only.
REGISTRY_RULESETS = [
    "r/python.lang.security.audit.insecure-hash-algorithms",
    "r/python.cryptography",
    "r/java.lang.security",
]

# Map Semgrep severity to a normalized level
_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


def run_semgrep_scan(project_path: Path, config: ScanConfig) -> list[dict[str, Any]]:
    """Run Semgrep with crypto rules and return CycloneDX components.

    Always runs custom rules from the rules/ directory.
    Attempts registry rulesets as supplement (hybrid approach).
    """
    semgrep_path = find_tool("semgrep")
    if not semgrep_path:
        logger.warning("semgrep not installed, skipping Layer 1")
        return []

    rules_dir = Path(__file__).parent / "rules"
    if not rules_dir.exists():
        logger.error("Custom rules directory not found: %s", rules_dir)
        return []

    # Only pass actual semgrep rule files (language-specific *-crypto.yaml and *-pqc.yaml).
    # Other YAML files in rules/ (tls.yaml, pqc.yaml, risk.yaml) are xBOM data files and
    # must not be passed to semgrep — they would cause InvalidRuleSchemaError (exit 7).
    rule_files = (
        sorted(rules_dir.glob("*-crypto.yaml"))
        + sorted(rules_dir.glob("*-crypto-inventory.yaml"))
        + sorted(rules_dir.glob("*-pqc.yaml"))
    )
    if not rule_files:
        logger.error("No semgrep rule files found in %s", rules_dir)
        return []

    # Try with registry rulesets first, fall back to custom-only
    components = _run_with_configs(
        semgrep_path, project_path, rule_files, config, use_registry=True
    )
    if components is None:
        logger.info("Registry rulesets unavailable, using custom rules only")
        components = _run_with_configs(
            semgrep_path, project_path, rule_files, config, use_registry=False
        )

    return components or []


def _run_with_configs(
    semgrep_path: str,
    project_path: Path,
    rule_files: list[Path],
    config: ScanConfig,
    *,
    use_registry: bool,
) -> list[dict[str, Any]] | None:
    """Execute semgrep with the given config sources.

    Returns None if registry configs fail (signal to retry without them).
    Returns empty list if scan succeeds but finds nothing.
    """
    cmd = [semgrep_path, "--json", "--quiet"]
    for rule_file in rule_files:
        cmd.extend(["--config", str(rule_file)])
    # Exclude dependency/build directories to avoid false positives from third-party code
    for skip in ("venv", ".venv", "node_modules", ".git", "__pycache__", "dist", "build", ".tox"):
        cmd.extend(["--exclude", skip])

    if use_registry:
        for ruleset in REGISTRY_RULESETS:
            cmd.extend(["--config", ruleset])

    cmd.append(str(project_path))

    result = run(cmd, cwd=project_path, timeout=300, verbose=config.verbose)

    # Semgrep exits 0 = no findings, 1 = findings found, other = error
    if result.returncode not in (0, 1):
        if use_registry:
            # Registry might have failed — signal caller to retry without
            logger.debug("Semgrep failed (exit %d): %s", result.returncode, result.stderr[:200])
            return None
        logger.error("Semgrep scan failed (exit %d): %s", result.returncode, result.stderr[:200])
        return []

    if not result.stdout.strip():
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        logger.error("Failed to parse Semgrep JSON output: %s", e)
        return []

    findings = data.get("results", [])
    logger.info("Semgrep found %d raw findings", len(findings))

    # Deduplicate: same file:line may be flagged by both custom and registry rules.
    # Prefer custom rules (xbom-* prefix) since they have richer metadata.
    seen: dict[str, dict[str, Any]] = {}  # key: "file:line" -> best finding
    for f in findings:
        fpath = f.get("path", "")
        line = f.get("start", {}).get("line", 0)
        key = f"{fpath}:{line}"
        check_id = f.get("check_id", "")
        is_custom = "xbom-" in check_id

        if key not in seen or (is_custom and "xbom-" not in seen[key].get("check_id", "")):
            seen[key] = f

    deduped = list(seen.values())
    logger.info("Semgrep: %d unique findings after dedup", len(deduped))

    return [_finding_to_component(f, project_path) for f in deduped]


def _finding_to_component(finding: dict[str, Any], project_path: Path) -> dict[str, Any]:
    """Convert a Semgrep finding to a CycloneDX cryptographic-asset component."""
    extra = finding.get("extra", {})
    metadata = extra.get("metadata", {})
    xbom_meta = metadata.get("xbom", {})
    check_id = finding.get("check_id", "unknown")

    asset_type = xbom_meta.get("asset_type", "algorithm")
    algo_name = xbom_meta.get("name", check_id)
    primitive = xbom_meta.get("primitive", "")
    param_set = xbom_meta.get("parameter_set", "")
    weakness = xbom_meta.get("weakness", "")
    severity = _SEVERITY_MAP.get(extra.get("severity", ""), "low")

    # Relative path from project root
    abs_path = finding.get("path", "")
    try:
        rel_path = str(Path(abs_path).relative_to(project_path))
    except ValueError:
        rel_path = abs_path

    start_line = finding.get("start", {}).get("line", 0)
    matched_code = extra.get("lines", "").strip()

    # Build CycloneDX component with cryptoProperties
    component: dict[str, Any] = {
        "type": "cryptographic-asset",
        "name": algo_name,
        "description": extra.get("message", ""),
        "cryptoProperties": _build_crypto_properties(asset_type, algo_name, primitive, param_set),
        "evidence": {
            "occurrences": [
                {
                    "location": rel_path,
                    "line": start_line,
                }
            ]
        },
        "properties": [
            {"name": "xbom:crypto:detected", "value": "true"},
            {"name": "xbom:crypto:scanner", "value": "semgrep"},
            {"name": "xbom:crypto:rule_id", "value": check_id},
            {"name": "xbom:crypto:source_file", "value": rel_path},
            {"name": "xbom:crypto:source_line", "value": str(start_line)},
            {"name": "xbom:crypto:severity", "value": severity},
        ],
    }

    if weakness:
        component["properties"].append({"name": "xbom:crypto:weakness", "value": weakness})
    if matched_code:
        # Truncate long matches
        snippet = matched_code[:200]
        component["properties"].append({"name": "xbom:crypto:evidence", "value": snippet})

    return component


def _build_crypto_properties(
    asset_type: str, name: str, primitive: str, param_set: str
) -> dict[str, Any]:
    """Build CycloneDX-compliant cryptoProperties based on asset type."""
    props: dict[str, Any] = {"assetType": asset_type}

    if asset_type == "algorithm":
        algo_props: dict[str, Any] = {}
        if primitive:
            algo_props["primitive"] = primitive
        if param_set:
            algo_props["parameterSetIdentifier"] = param_set
        if algo_props:
            props["algorithmProperties"] = algo_props

    elif asset_type == "protocol":
        proto_props: dict[str, Any] = {}
        if name:
            proto_props["type"] = name.lower()
        props["protocolProperties"] = proto_props

    elif asset_type == "related-crypto-material":
        props["relatedCryptoMaterialProperties"] = {"type": name.lower()}

    return props
