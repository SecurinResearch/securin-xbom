"""CycloneDX BOM construction and serialization utilities."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4


def new_bom_skeleton(*, serial_number: str | None = None) -> dict[str, Any]:
    """Create a minimal CycloneDX 1.6 BOM skeleton."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial_number or f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "xbom",
                        "version": "0.1.0",
                        "description": "Unified xBOM generator",
                    }
                ]
            },
        },
        "components": [],
        "services": [],
        "dependencies": [],
    }


def load_bom_json(path: Path) -> dict[str, Any]:
    """Load a CycloneDX JSON BOM from a file."""
    with open(path) as f:
        return json.load(f)


def write_bom_json(bom: dict[str, Any], path: Path) -> None:
    """Write a CycloneDX JSON BOM to a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(bom, f, indent=2)


def add_tool_to_metadata(bom: dict[str, Any], name: str, version: str | None = None) -> None:
    """Add a tool entry to bom.metadata.tools.components."""
    tools = bom.setdefault("metadata", {}).setdefault("tools", {}).setdefault("components", [])
    entry: dict[str, Any] = {"type": "application", "name": name}
    if version:
        entry["version"] = version
    # Avoid duplicates
    if not any(t.get("name") == name for t in tools):
        tools.append(entry)


def add_property(component: dict[str, Any], name: str, value: str) -> None:
    """Add a property to a component's properties array."""
    props = component.setdefault("properties", [])
    # Update existing if same name
    for p in props:
        if p.get("name") == name:
            p["value"] = value
            return
    props.append({"name": name, "value": value})


def find_component_by_purl(bom: dict[str, Any], purl: str) -> dict[str, Any] | None:
    """Find a component in the BOM by its PURL."""
    for comp in bom.get("components", []):
        if comp.get("purl") == purl:
            return comp
    return None


def validate_bom(bom: dict[str, Any]) -> list[str]:
    """Basic validation of a CycloneDX BOM. Returns list of issues."""
    issues = []
    if bom.get("bomFormat") != "CycloneDX":
        issues.append("bomFormat must be 'CycloneDX'")
    if bom.get("specVersion") not in ("1.4", "1.5", "1.6", "1.7"):
        issues.append(f"Unsupported specVersion: {bom.get('specVersion')}")
    if "serialNumber" not in bom:
        issues.append("Missing serialNumber")
    return issues
