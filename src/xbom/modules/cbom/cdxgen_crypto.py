"""cdxgen --include-crypto wrapper (Layer 2)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from xbom.models import ScanConfig
from xbom.utils.subprocess import find_tool, run_json

logger = logging.getLogger(__name__)

# cdxgen --include-crypto only supports Java and Python
_SUPPORTED_EXTENSIONS = {".java", ".py"}


def run_cdxgen_crypto(project_path: Path, config: ScanConfig) -> list[dict[str, Any]]:
    """Run cdxgen with --include-crypto and extract crypto components.

    Only runs if the project contains Java or Python files, since cdxgen's
    native CBOM support is limited to those languages.

    Returns CycloneDX cryptographic-asset components.
    """
    cdxgen_path = find_tool("cdxgen")
    if not cdxgen_path:
        logger.info("cdxgen not installed, skipping Layer 2")
        return []

    if not _has_supported_files(project_path):
        logger.info("No Java/Python files found, skipping cdxgen crypto scan")
        return []

    cmd = [
        cdxgen_path,
        "--include-crypto",
        "--spec-version", "1.6",
        "-o", "-",  # stdout
        str(project_path),
    ]

    data, error = run_json(cmd, cwd=project_path, timeout=300, verbose=config.verbose)

    if error:
        logger.error("cdxgen --include-crypto failed: %s", error)
        return []

    if not data:
        return []

    # Extract crypto-related components from cdxgen output
    components = []
    for comp in data.get("components", []):
        if _is_crypto_component(comp):
            _add_xbom_properties(comp)
            components.append(comp)

    logger.info("cdxgen --include-crypto found %d crypto components", len(components))
    return components


def _has_supported_files(project_path: Path) -> bool:
    """Check if project contains Java or Python files."""
    for ext in _SUPPORTED_EXTENSIONS:
        try:
            next(project_path.rglob(f"*{ext}"))
            return True
        except StopIteration:
            continue
    return False


def _is_crypto_component(comp: dict[str, Any]) -> bool:
    """Check if a cdxgen component is crypto-related."""
    if comp.get("type") == "cryptographic-asset":
        return True
    if "cryptoProperties" in comp:
        return True
    # Check for crypto-related properties
    for prop in comp.get("properties", []):
        if "crypto" in prop.get("name", "").lower():
            return True
    return False


def _add_xbom_properties(comp: dict[str, Any]) -> None:
    """Add xbom:crypto:* properties to a cdxgen crypto component."""
    props = comp.setdefault("properties", [])

    # Don't duplicate if already tagged
    existing_names = {p["name"] for p in props}
    if "xbom:crypto:detected" in existing_names:
        return

    props.append({"name": "xbom:crypto:detected", "value": "true"})
    props.append({"name": "xbom:crypto:scanner", "value": "cdxgen"})

    # Extract asset type from cryptoProperties if present
    crypto_props = comp.get("cryptoProperties", {})
    asset_type = crypto_props.get("assetType", "")
    if asset_type:
        props.append({"name": "xbom:crypto:asset_type", "value": asset_type})
