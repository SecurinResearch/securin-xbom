"""CBOM (Cryptographic BOM) module — 3-layer detection pipeline."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from xbom.models import BomType, ScanConfig
from xbom.modules.base import BomModule, ScanError
from xbom.modules.cbom.cdxgen_crypto import run_cdxgen_crypto
from xbom.modules.cbom.pqc_annotator import annotate_pqc_safety
from xbom.modules.cbom.risk import score_cbom_components
from xbom.modules.cbom.semgrep import run_semgrep_scan
from xbom.modules.cbom.tls_scanner import run_tls_scan
from xbom.utils.cyclonedx import add_property, new_bom_skeleton

logger = logging.getLogger(__name__)


class CbomModule(BomModule):
    """Cryptographic BOM module.

    3-layer detection pipeline:
      Layer 1: Semgrep crypto rules (always)
      Layer 2: cdxgen --include-crypto (always, if available)
      Layer 3: testssl.sh (only with --live-url)
    """

    @property
    def bom_type(self) -> BomType:
        return BomType.CBOM

    @property
    def name(self) -> str:
        return "CBOM Scanner"

    def scan(
        self, project_path: Path, config: ScanConfig, sbom: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        components: list[dict[str, Any]] = []
        seen: set[str] = set()  # dedup key: "name|file|line"

        # Layer 1: Semgrep (always runs)
        logger.info("CBOM Layer 1: Semgrep crypto scanning")
        try:
            semgrep_components = run_semgrep_scan(project_path, config)
            for comp in semgrep_components:
                key = _dedup_key(comp)
                if key not in seen:
                    seen.add(key)
                    components.append(comp)
            logger.info("Layer 1 (Semgrep): %d findings", len(semgrep_components))
        except Exception as e:
            logger.error("Layer 1 (Semgrep) failed: %s", e)

        # Layer 2: cdxgen --include-crypto (always, if cdxgen available)
        logger.info("CBOM Layer 2: cdxgen --include-crypto")
        try:
            cdxgen_components = run_cdxgen_crypto(project_path, config)
            added = 0
            for comp in cdxgen_components:
                key = _dedup_key(comp)
                if key not in seen:
                    seen.add(key)
                    components.append(comp)
                    added += 1
            logger.info("Layer 2 (cdxgen): %d findings (%d new)", len(cdxgen_components), added)
        except Exception as e:
            logger.error("Layer 2 (cdxgen) failed: %s", e)

        # Layer 3: testssl.sh (only with --live-url)
        if config.live_url:
            logger.info("CBOM Layer 3: testssl.sh TLS scan (%s)", config.live_url)
            try:
                tls_components = run_tls_scan(config.live_url, config)
                components.extend(tls_components)
                logger.info("Layer 3 (testssl): %d findings", len(tls_components))
            except Exception as e:
                logger.error("Layer 3 (testssl) failed: %s", e)
        else:
            logger.debug("Layer 3 skipped (no --live-url)")

        # Build BOM
        bom = new_bom_skeleton()
        bom["components"] = components

        # PQC safety annotation (must run BEFORE risk scoring
        # so quantum_vulnerable weakness flags are present for scoring)
        pqc_summary = annotate_pqc_safety(bom)

        # Risk scoring
        score_cbom_components(bom)

        # Add summary properties
        bom.setdefault("properties", [])
        add_property(bom, "xbom:crypto:total_findings", str(len(components)))

        # Count by scanner
        scanner_counts: dict[str, int] = {}
        for comp in components:
            for prop in comp.get("properties", []):
                if prop["name"] == "xbom:crypto:scanner":
                    scanner = prop["value"]
                    scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1
        for scanner, count in scanner_counts.items():
            add_property(bom, f"xbom:crypto:scanner_{scanner}_count", str(count))

        # Count weaknesses
        weakness_count = sum(
            1 for comp in components
            for prop in comp.get("properties", [])
            if prop["name"] == "xbom:crypto:weakness" and prop["value"]
        )
        add_property(bom, "xbom:crypto:weakness_count", str(weakness_count))

        # PQC readiness summary
        add_property(bom, "xbom:crypto:pqc_vulnerable_count", str(pqc_summary.get("vulnerable", 0)))
        add_property(bom, "xbom:crypto:pqc_safe_count", str(pqc_summary.get("safe", 0)))
        add_property(bom, "xbom:crypto:pqc_adopted_count", str(pqc_summary.get("pqc", 0)))
        add_property(bom, "xbom:crypto:pqc_readiness_pct", str(pqc_summary.get("readiness_pct", 0)))

        return bom

    def required_tools(self) -> list[str]:
        return ["semgrep"]


def _dedup_key(comp: dict[str, Any]) -> str:
    """Generate a deduplication key from a component's name and location."""
    name = comp.get("name", "")
    props = {p["name"]: p["value"] for p in comp.get("properties", [])}
    source_file = props.get("xbom:crypto:source_file", "")
    source_line = props.get("xbom:crypto:source_line", "")
    return f"{name}|{source_file}|{source_line}"
