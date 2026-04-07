"""BOM merging — combines multiple partial BOMs into a single CycloneDX 1.6 document."""

from __future__ import annotations

from typing import Any

from xbom.models import BomType
from xbom.utils.cyclonedx import add_property, find_component_by_purl, new_bom_skeleton


def merge_boms(
    results: dict[BomType, dict[str, Any]],
    source_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Merge multiple BOM results into a single composite CycloneDX 1.6 BOM.

    Strategy:
    1. SBOM is the base (most complete component + dependency data)
    2. AI-BOM: enrich existing components with xbom:ai:* properties, add new ones
    3. CBOM: cryptographic-asset components are always new additions
    4. API-BOM: services go into the services array
    5. Deduplicate by PURL
    6. Merge metadata.tools from all BOMs

    Args:
        results: Map of BomType → CycloneDX JSON dict.
        source_metadata: Optional scan metadata to include.

    Returns:
        Merged CycloneDX 1.6 JSON dict.
    """
    composite = new_bom_skeleton()

    # Start with SBOM as base if available
    sbom = results.get(BomType.SBOM)
    if sbom:
        composite["components"] = list(sbom.get("components", []))
        composite["dependencies"] = list(sbom.get("dependencies", []))
        _merge_tools(composite, sbom)

    # Merge AI-BOM
    aibom = results.get(BomType.AIBOM)
    if aibom:
        _merge_aibom(composite, aibom)
        _merge_tools(composite, aibom)

    # Merge CBOM
    cbom = results.get(BomType.CBOM)
    if cbom:
        _merge_cbom(composite, cbom)
        _merge_tools(composite, cbom)

    # Merge API-BOM
    apibom = results.get(BomType.APIBOM)
    if apibom:
        _merge_apibom(composite, apibom)
        _merge_tools(composite, apibom)

    # Add source metadata if provided
    if source_metadata:
        composite["metadata"]["component"] = source_metadata

    # Clean up empty arrays
    if not composite.get("services"):
        del composite["services"]
    if not composite.get("dependencies"):
        del composite["dependencies"]

    return composite


def _merge_aibom(composite: dict[str, Any], aibom: dict[str, Any]) -> None:
    """Merge AI-BOM components into composite.

    If a component PURL exists in composite, add xbom:ai:* properties.
    If new, add as a new component.
    """
    for comp in aibom.get("components", []):
        purl = comp.get("purl")
        if purl:
            existing = find_component_by_purl(composite, purl)
            if existing:
                # Merge AI properties into existing component
                for prop in comp.get("properties", []):
                    if prop.get("name", "").startswith("xbom:ai:"):
                        add_property(existing, prop["name"], prop["value"])
                continue
        # New component — add to composite
        composite.setdefault("components", []).append(comp)


def _merge_cbom(composite: dict[str, Any], cbom: dict[str, Any]) -> None:
    """Merge CBOM components (cryptographic-assets) into composite.

    Crypto assets are always new additions (they don't overlap with SBOM packages).
    """
    for comp in cbom.get("components", []):
        composite.setdefault("components", []).append(comp)


def _merge_apibom(composite: dict[str, Any], apibom: dict[str, Any]) -> None:
    """Merge API-BOM services and components into composite."""
    for svc in apibom.get("services", []):
        composite.setdefault("services", []).append(svc)
    for comp in apibom.get("components", []):
        composite.setdefault("components", []).append(comp)


def _merge_tools(composite: dict[str, Any], source_bom: dict[str, Any]) -> None:
    """Merge tool entries from source BOM into composite metadata."""
    source_tools = (
        source_bom.get("metadata", {}).get("tools", {}).get("components", [])
    )
    existing_tools = (
        composite.setdefault("metadata", {}).setdefault("tools", {}).setdefault("components", [])
    )
    existing_names = {t.get("name") for t in existing_tools}
    for tool in source_tools:
        if tool.get("name") not in existing_names:
            existing_tools.append(tool)
            existing_names.add(tool.get("name"))
