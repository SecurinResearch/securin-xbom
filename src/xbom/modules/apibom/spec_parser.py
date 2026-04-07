"""OpenAPI/Swagger spec file parser — Layer 2."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

from xbom.modules.apibom.extractors.base import ApiEndpoint, _load_rules

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_spec_config: dict | None = None


def _get_spec_config() -> dict:
    global _spec_config
    if _spec_config is None:
        _spec_config = _load_rules("openapi")
    return _spec_config


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_api_specs(project_path: Path) -> tuple[list[ApiEndpoint], list[dict[str, Any]]]:
    """Find and parse OpenAPI/Swagger spec files.

    Returns:
        (endpoints, spec_components) — endpoints from specs + CycloneDX component dicts for each spec file.
    """
    config = _get_spec_config()
    spec_files = _find_spec_files(project_path, config)

    all_endpoints: list[ApiEndpoint] = []
    spec_components: list[dict[str, Any]] = []

    for spec_path in spec_files:
        rel_path = str(spec_path.relative_to(project_path))
        logger.debug("Parsing spec: %s", rel_path)

        try:
            spec = _load_spec(spec_path)
        except Exception as e:
            logger.warning("Failed to parse spec %s: %s", rel_path, e)
            continue

        if not isinstance(spec, dict):
            continue

        # Extract endpoints from paths
        endpoints = _extract_endpoints(spec, rel_path, config)
        all_endpoints.extend(endpoints)

        # Build spec component for CycloneDX
        comp = _build_spec_component(spec, rel_path, len(endpoints))
        spec_components.append(comp)

    return all_endpoints, spec_components


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _find_spec_files(project_path: Path, config: dict) -> list[Path]:
    """Find OpenAPI/Swagger spec files in the project."""
    filenames = set(config.get("spec_filenames", []))
    spec_dirs = config.get("spec_dirs", [])
    found: list[Path] = []

    # Check root-level files
    for name in filenames:
        p = project_path / name
        if p.is_file():
            found.append(p)

    # Check spec directories
    for dir_name in spec_dirs:
        d = project_path / dir_name
        if not d.is_dir():
            continue
        for name in filenames:
            p = d / name
            if p.is_file():
                found.append(p)

    return found


def _load_spec(path: Path) -> Any:
    """Load a spec file as YAML or JSON."""
    content = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix == ".json":
        return json.loads(content)
    return yaml.safe_load(content)


def _extract_endpoints(spec: dict, rel_path: str, config: dict) -> list[ApiEndpoint]:
    """Extract endpoint definitions from an OpenAPI spec."""
    endpoints: list[ApiEndpoint] = []
    http_methods = set(config.get("http_methods", ["get", "post", "put", "delete", "patch"]))

    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return endpoints

    # Check if spec has security definitions
    has_global_security = bool(
        spec.get("security") or spec.get("securityDefinitions") or spec.get("components", {}).get("securitySchemes")
    )

    for path_str, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method in http_methods:
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue

            # Check auth at operation level
            op_security = operation.get("security")
            auth_detected = has_global_security if op_security is None else bool(op_security)

            summary = operation.get("summary", "")
            description = operation.get("description", "")

            endpoints.append(
                ApiEndpoint(
                    path=path_str,
                    method=method.upper(),
                    framework="openapi-spec",
                    source_file=rel_path,
                    source_line=0,  # spec files don't have meaningful line numbers
                    category="api-spec",
                    auth_detected=auth_detected,
                    description=summary or description,
                )
            )

    return endpoints


def _build_spec_component(spec: dict, rel_path: str, endpoint_count: int) -> dict[str, Any]:
    """Build a CycloneDX component dict for a spec file."""
    info = spec.get("info", {})
    title = info.get("title", "API Spec")
    version = info.get("version", "")
    spec_version = spec.get("openapi", spec.get("swagger", ""))

    has_security = bool(
        spec.get("security") or spec.get("securityDefinitions") or spec.get("components", {}).get("securitySchemes")
    )

    return {
        "type": "data",
        "name": rel_path,
        "description": f"OpenAPI specification: {title}" + (f" v{version}" if version else ""),
        "properties": [
            {"name": "xbom:api:category", "value": "api-spec"},
            {"name": "xbom:api:spec_version", "value": spec_version},
            {"name": "xbom:api:spec_title", "value": title},
            {"name": "xbom:api:spec_api_version", "value": version},
            {"name": "xbom:api:spec_endpoint_count", "value": str(endpoint_count)},
            {"name": "xbom:api:spec_has_security", "value": str(has_security).lower()},
        ],
    }
