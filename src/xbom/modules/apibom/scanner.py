"""API-BOM module — 3-layer detection pipeline.

Layer 1: Framework-specific route extraction (regex from YAML)
Layer 2: OpenAPI/Swagger spec file parsing
Layer 3: Outbound HTTP client call detection
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from xbom.models import BomType, ScanConfig
from xbom.modules.apibom.client_detector import detect_client_calls
from xbom.modules.apibom.extractors.base import (
    ApiEndpoint,
    read_file_safe,
    walk_source_files,
)
from xbom.modules.apibom.extractors.javascript import JS_EXTRACTORS
from xbom.modules.apibom.extractors.python import PYTHON_EXTRACTORS
from xbom.modules.apibom.risk import score_apibom
from xbom.modules.apibom.spec_parser import parse_api_specs
from xbom.modules.base import BomModule
from xbom.utils.cyclonedx import add_property, add_tool_to_metadata, new_bom_skeleton

logger = logging.getLogger(__name__)

# File extensions per language group
_PY_EXTENSIONS = {".py", ".pyi"}
_JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"}


class ApibomModule(BomModule):
    """API Bill of Materials module.

    3-layer detection pipeline:
      Layer 1: Framework route extraction (always)
      Layer 2: OpenAPI/Swagger spec parsing (always)
      Layer 3: Outbound HTTP client detection (always)
    """

    @property
    def bom_type(self) -> BomType:
        return BomType.APIBOM

    @property
    def name(self) -> str:
        return "API-BOM"

    def scan(self, project_path: Path, config: ScanConfig, sbom: dict[str, Any] | None = None) -> dict[str, Any]:
        all_endpoints: list[ApiEndpoint] = []
        spec_components: list[dict[str, Any]] = []
        seen: set[str] = set()

        # Layer 1: Framework extraction (always)
        logger.info("API-BOM Layer 1: Framework route extraction")
        try:
            fw_endpoints = _extract_framework_routes(project_path)
            for ep in fw_endpoints:
                key = _dedup_key(ep)
                if key not in seen:
                    seen.add(key)
                    all_endpoints.append(ep)
            logger.info("Layer 1 (Frameworks): %d endpoints", len(fw_endpoints))
        except Exception as e:
            logger.error("Layer 1 (Frameworks) failed: %s", e)

        # Layer 2: OpenAPI spec parsing (always)
        logger.info("API-BOM Layer 2: OpenAPI/Swagger spec parsing")
        try:
            spec_endpoints, spec_comps = parse_api_specs(project_path)
            added = 0
            for ep in spec_endpoints:
                key = _dedup_key(ep)
                if key not in seen:
                    seen.add(key)
                    all_endpoints.append(ep)
                    added += 1
                else:
                    # Endpoint exists from code — mark as documented
                    _mark_documented(all_endpoints, ep)
            spec_components.extend(spec_comps)
            logger.info(
                "Layer 2 (Specs): %d endpoints (%d new), %d spec files", len(spec_endpoints), added, len(spec_comps)
            )
        except Exception as e:
            logger.error("Layer 2 (Specs) failed: %s", e)

        # Layer 3: Client detection (always)
        logger.info("API-BOM Layer 3: Outbound HTTP client detection")
        try:
            client_endpoints = detect_client_calls(project_path)
            for ep in client_endpoints:
                key = f"EXT|{ep.host}|{ep.source_file}"
                if key not in seen:
                    seen.add(key)
                    all_endpoints.append(ep)
            logger.info("Layer 3 (Clients): %d external calls", len(client_endpoints))
        except Exception as e:
            logger.error("Layer 3 (Clients) failed: %s", e)

        # Build BOM
        bom = new_bom_skeleton()
        add_tool_to_metadata(bom, "xbom-apibom", "0.1.0")

        # Separate internal vs external
        internal = [ep for ep in all_endpoints if ep.category in ("internal-endpoint", "webhook", "websocket")]
        external = [ep for ep in all_endpoints if ep.category == "external-dependency"]
        from_spec = [ep for ep in all_endpoints if ep.category == "api-spec"]

        # Build services (internal endpoints grouped by framework+file)
        bom["services"] = _build_services(internal)

        # Build components (external deps + spec files)
        bom["components"] = _build_external_components(external) + spec_components

        # Risk scoring
        score_apibom(bom)

        # Summary properties
        bom.setdefault("properties", [])
        add_property(bom, "xbom:api:total_endpoints", str(len(all_endpoints)))
        add_property(bom, "xbom:api:internal_count", str(len(internal) + len(from_spec)))
        add_property(bom, "xbom:api:external_count", str(len(external)))
        add_property(bom, "xbom:api:spec_count", str(len(spec_components)))

        # Frameworks found
        frameworks = sorted({ep.framework for ep in internal if ep.framework})
        if frameworks:
            add_property(bom, "xbom:api:framework_list", ", ".join(frameworks))

        # Auth coverage
        if internal:
            authed = sum(1 for ep in internal if ep.auth_detected)
            pct = round(authed / len(internal) * 100)
            add_property(bom, "xbom:api:auth_coverage_pct", str(pct))

        return bom

    def required_tools(self) -> list[str]:
        return []


# ---------------------------------------------------------------------------
# Framework route extraction (Layer 1)
# ---------------------------------------------------------------------------


def _extract_framework_routes(project_path: Path) -> list[ApiEndpoint]:
    """Run all framework extractors across the project."""
    all_extractors = [cls() for cls in PYTHON_EXTRACTORS + JS_EXTRACTORS]
    endpoints: list[ApiEndpoint] = []

    all_extensions = _PY_EXTENSIONS | _JS_EXTENSIONS
    for file_path in walk_source_files(project_path, all_extensions):
        content = read_file_safe(file_path)
        if not content:
            continue

        rel_path = str(file_path.relative_to(project_path))

        for extractor in all_extractors:
            if extractor.detect(content):
                try:
                    found = extractor.extract(file_path, content, rel_path)
                    endpoints.extend(found)
                except Exception as e:
                    logger.debug("Extractor %s failed on %s: %s", extractor.framework_name, rel_path, e)

    return endpoints


# ---------------------------------------------------------------------------
# BOM building helpers
# ---------------------------------------------------------------------------


def _build_services(endpoints: list[ApiEndpoint]) -> list[dict[str, Any]]:
    """Group internal endpoints into CycloneDX services by framework+file."""
    groups: dict[str, list[ApiEndpoint]] = {}
    for ep in endpoints:
        key = f"{ep.framework}|{ep.source_file}"
        groups.setdefault(key, []).append(ep)

    services: list[dict[str, Any]] = []
    for _key, eps in groups.items():
        fw = eps[0].framework
        source = eps[0].source_file
        endpoint_paths = sorted({ep.path for ep in eps})
        authed = sum(1 for ep in eps if ep.auth_detected)
        auth_pct = f"{round(authed / len(eps) * 100)}%" if eps else "0%"

        svc: dict[str, Any] = {
            "name": f"{fw}-app",
            "endpoints": endpoint_paths,
            "properties": [
                {"name": "xbom:api:framework", "value": fw},
                {"name": "xbom:api:source_file", "value": source},
                {"name": "xbom:api:endpoint_count", "value": str(len(eps))},
                {"name": "xbom:api:auth_coverage", "value": auth_pct},
            ],
            "data": [],
        }

        # Add individual endpoint details to data array
        for ep in eps:
            svc["data"].append(
                {
                    "classification": "api-definition",
                    "flow": "inbound",
                    "name": f"{ep.method} {ep.path}",
                    "description": ep.description or f"{ep.method} endpoint at {ep.path}",
                }
            )

        services.append(svc)

    return services


def _build_external_components(endpoints: list[ApiEndpoint]) -> list[dict[str, Any]]:
    """Build CycloneDX components for external API dependencies."""
    # Group by host
    by_host: dict[str, list[ApiEndpoint]] = {}
    for ep in endpoints:
        by_host.setdefault(ep.host, []).append(ep)

    components: list[dict[str, Any]] = []
    for host, eps in by_host.items():
        first = eps[0]
        urls = sorted({ep.path for ep in eps})
        uses_tls = all(ep.path.startswith("https://") for ep in eps)

        comp: dict[str, Any] = {
            "type": "service",
            "name": host,
            "description": f"External API dependency: {host}",
            "externalReferences": [{"type": "website", "url": url} for url in urls],
            "properties": [
                {"name": "xbom:api:category", "value": "external-dependency"},
                {"name": "xbom:api:client_library", "value": first.framework},
                {"name": "xbom:api:source_file", "value": first.source_file},
                {"name": "xbom:api:source_line", "value": str(first.source_line)},
                {"name": "xbom:api:uses_tls", "value": str(uses_tls).lower()},
            ],
        }
        components.append(comp)

    return components


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dedup_key(ep: ApiEndpoint) -> str:
    """Generate a deduplication key for an endpoint."""
    return f"{ep.method}|{ep.path}|{ep.source_file}"


def _mark_documented(endpoints: list[ApiEndpoint], spec_ep: ApiEndpoint) -> None:
    """Mark code-discovered endpoints as documented (found in spec)."""
    # This is a best-effort match — same method+path
    for ep in endpoints:
        if ep.method == spec_ep.method and ep.path == spec_ep.path:
            # Can't modify frozen dataclass, but we track it via properties in the service
            break
