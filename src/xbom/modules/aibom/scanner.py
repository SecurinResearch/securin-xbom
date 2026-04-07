"""AI-BOM module — orchestrates pattern scanning, catalog matching, ecosyste.ms + agent classification."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from xbom.models import BomType, ScanConfig
from xbom.modules.base import BomModule, ScanError
from xbom.utils.cyclonedx import add_property, add_tool_to_metadata, new_bom_skeleton

logger = logging.getLogger(__name__)


class AibomModule(BomModule):
    """Generates AI Bill of Materials.

    Detection flow:
      Layer 1 (always): Regex pattern scanning — imports, model refs, API keys,
          Docker AI containers, MCP configs, model files, network endpoints, cloud configs.
      Layer 2 (always): SBOM cross-ref against static AI catalog — fast, no network.
      Layer 3 (with --enrich): ALL remaining SBOM packages → ecosyste.ms (get keywords
          + description) → Strands Agent classifies each as AI/ML or not.
      Layer 3 (without --enrich): ecosyste.ms keyword heuristic as weak fallback.
    """

    @property
    def bom_type(self) -> BomType:
        return BomType.AIBOM

    @property
    def name(self) -> str:
        return "AI-BOM"

    def required_tools(self) -> list[str]:
        return []

    def scan(self, project_path: Path, config: ScanConfig, sbom: dict[str, Any] | None = None) -> dict[str, Any]:
        bom = new_bom_skeleton()
        add_tool_to_metadata(bom, "xbom-aibom", "0.1.0")

        # ── Layer 1: Regex pattern scanning (always) ──
        logger.info("═══ Layer 1: Pattern scanning ═══")
        try:
            count = self._run_pattern_scan(project_path, bom)
            logger.info("  → %d unique components from patterns", count)
        except Exception as e:
            logger.warning("  ✗ Pattern scan failed: %s", e)

        # ── Layer 2: SBOM catalog cross-ref (always, if SBOM available) ──
        if sbom:
            logger.info("═══ Layer 2: SBOM catalog cross-ref (%d SBOM components) ═══", len(sbom.get("components", [])))
            try:
                count = self._run_catalog_crossref(sbom, bom)
                logger.info("  → %d AI components matched in catalog", count)
            except Exception as e:
                logger.warning("  ✗ Catalog cross-ref failed: %s", e)
        else:
            logger.info("═══ Layer 2: Skipped (no SBOM provided) ═══")

        # ── Layer 3: ecosyste.ms + agent classification ──
        if sbom:
            if config.enrich:
                logger.info("═══ Layer 3: ecosyste.ms → Strands Agent classification ═══")
                try:
                    count = self._run_agent_classification(sbom, bom)
                    logger.info("  → %d new AI components from agent", count)
                except Exception as e:
                    logger.warning("  ✗ Agent classification failed: %s", e)
            else:
                logger.info("═══ Layer 3: ecosyste.ms keyword heuristic (no --enrich) ═══")
                try:
                    count = self._run_ecosystems_heuristic(sbom, bom)
                    logger.info("  → %d potential AI components", count)
                except Exception as e:
                    logger.warning("  ✗ ecosyste.ms heuristic failed: %s", e)

        # ── Layer 4: CodeGraph analysis (--enrich + FalkorDB) ──
        if config.enrich:
            logger.info("═══ Layer 4: CodeGraph analysis ═══")
            try:
                count = self._run_codegraph_analysis(project_path, bom, config)
                logger.info("  → %d components + relationships from code graph", count)
            except ImportError as e:
                logger.info("  ⊘ Skipped: %s", e)
            except Exception as e:
                logger.warning("  ✗ CodeGraph failed: %s", e, exc_info=config.verbose)

        # ── Post-processing ──
        logger.info("═══ Post-processing: shadow AI + risk scoring ═══")
        if sbom:
            self._detect_shadow_ai(sbom, bom)
            shadow_count = sum(
                1 for c in bom.get("components", [])
                for p in c.get("properties", [])
                if p.get("name") == "xbom:ai:shadow_ai"
            )
            if shadow_count:
                logger.info("  → %d shadow AI packages flagged", shadow_count)

        from xbom.modules.aibom.risk import score_bom_components
        score_bom_components(bom)
        logger.info("  → Risk scores applied")

        return bom

    # ── Layer 1: Pattern scanning ──────────────────────────────────────

    def _run_pattern_scan(self, project_path: Path, bom: dict[str, Any]) -> int:
        """Regex pattern scanning across source files, configs, Dockerfiles, etc."""
        from xbom.modules.aibom.patterns import scan_all

        findings = scan_all(project_path)
        existing_names: set[str] = set()
        count = 0

        for finding in findings:
            if finding.name in existing_names:
                continue
            existing_names.add(finding.name)

            component: dict[str, Any] = {
                "type": _component_cdx_type(finding.category),
                "name": finding.name,
                "properties": [
                    {"name": "xbom:ai:detected", "value": "true"},
                    {"name": "xbom:ai:category", "value": finding.category},
                    {"name": "xbom:ai:scanner", "value": finding.scanner_name},
                    {"name": "xbom:ai:confidence", "value": str(finding.confidence)},
                    {"name": "xbom:ai:source_file", "value": finding.file_path},
                    {"name": "xbom:ai:description", "value": finding.description},
                ],
            }
            if finding.line_number > 0:
                add_property(component, "xbom:ai:source_line", str(finding.line_number))
            bom["components"].append(component)
            count += 1

        return count

    # ── Layer 2: Static catalog cross-reference ────────────────────────

    def _run_catalog_crossref(self, sbom: dict[str, Any], bom: dict[str, Any]) -> int:
        """Check every SBOM component against our static AI package catalog."""
        from xbom.modules.aibom.catalog import lookup_by_purl

        already_purls = _existing_purls(bom)
        already_names = _existing_names(bom)
        count = 0

        for comp in sbom.get("components", []):
            purl = comp.get("purl")
            name = comp.get("name", "")
            if not purl or purl in already_purls or name in already_names:
                continue

            entry = lookup_by_purl(purl)
            if not entry:
                continue

            ai_comp = {
                "type": _component_cdx_type(entry["category"]),
                "name": comp.get("name", ""),
                "version": comp.get("version"),
                "purl": purl,
                "properties": [
                    {"name": "xbom:ai:detected", "value": "true"},
                    {"name": "xbom:ai:category", "value": entry["category"]},
                    {"name": "xbom:ai:scanner", "value": "catalog"},
                    {"name": "xbom:ai:confidence", "value": "1.0"},
                    {"name": "xbom:ai:description", "value": entry["description"]},
                ],
            }
            bom["components"].append(ai_comp)
            already_purls.add(purl)
            already_names.add(name)
            count += 1

        return count

    # ── Layer 3a: Agent classification (--enrich) ──────────────────────

    def _run_agent_classification(self, sbom: dict[str, Any], bom: dict[str, Any]) -> int:
        """Send ALL uncatalogued SBOM packages to ecosyste.ms for metadata,
        then pass that metadata to the Strands Agent for classification.

        This is the correct flow:
          SBOM packages → ecosyste.ms (keywords + description) → Agent classifies
        """
        try:
            from xbom.modules.aibom.agent import classify_packages
        except ImportError:
            logger.warning(
                "Strands Agents SDK not installed. Install: pip install 'xbom[agent]'\n"
                "Falling back to ecosyste.ms heuristic."
            )
            return self._run_ecosystems_heuristic(sbom, bom)

        from xbom.modules.aibom.ecosystems_client import EcosystemsClient

        # Collect all SBOM packages not already identified by catalog/patterns
        already = _existing_purls(bom) | _existing_names(bom)
        logger.info("  Already identified: %d components, checking remaining SBOM packages", len(already))
        unchecked = []
        purl_to_comp: dict[str, dict] = {}

        for comp in sbom.get("components", []):
            purl = comp.get("purl")
            name = comp.get("name", "")
            if not purl or purl in already or name in already:
                continue
            unchecked.append(purl)
            purl_to_comp[purl] = comp

        if not unchecked:
            logger.info("  All SBOM packages already identified, nothing to classify")
            return 0

        logger.info("  %d unchecked SBOM packages → querying ecosyste.ms for metadata", len(unchecked))

        # Step 1: Bulk lookup ALL unchecked packages on ecosyste.ms
        client = EcosystemsClient()
        try:
            packages = asyncio.run(client.bulk_lookup(unchecked))
            logger.info("  ecosyste.ms returned metadata for %d/%d packages", len(packages), len(unchecked))
        except Exception as e:
            logger.warning("  ecosyste.ms bulk lookup failed: %s", e)
            packages = []

        # Build enriched package list for the agent
        packages_for_agent = []
        pkg_by_name: dict[str, Any] = {}
        for pkg in packages:
            pkg_by_name[pkg.name.lower()] = pkg

        for purl, comp in purl_to_comp.items():
            name = comp.get("name", "").lower()
            pkg = pkg_by_name.get(name)
            packages_for_agent.append({
                "package_name": comp.get("name", ""),
                "purl": purl,
                "version": comp.get("version", ""),
                "ecosystem": _ecosystem_from_purl(purl),
                # ecosyste.ms enrichment — this is what the agent uses to classify
                "description": pkg.description if pkg else "",
                "keywords": pkg.keywords if pkg else [],
                "repository_url": pkg.repository_url if pkg else "",
            })

        if not packages_for_agent:
            logger.info("  No packages to send to agent")
            return 0

        # Step 2: Send enriched packages to Strands Agent for classification
        logger.info("  Sending %d packages to Strands Agent for classification...", len(packages_for_agent))
        results = classify_packages(packages_for_agent)
        ai_results = [r for r in results if r.get("is_ai_ml")]
        logger.info("  Agent classified %d/%d as AI/ML", len(ai_results), len(results))

        count = 0
        for result in results:
            if not result.get("is_ai_ml"):
                continue

            purl = result.get("purl", "")
            orig = purl_to_comp.get(purl, {})

            ai_comp = {
                "type": _component_cdx_type(result.get("category", "other")),
                "name": result.get("package_name", orig.get("name", "")),
                "version": orig.get("version"),
                "purl": purl,
                "properties": [
                    {"name": "xbom:ai:detected", "value": "true"},
                    {"name": "xbom:ai:category", "value": result.get("category", "other")},
                    {"name": "xbom:ai:scanner", "value": "strands-agent"},
                    {"name": "xbom:ai:confidence", "value": str(result.get("confidence", 0.8))},
                    {"name": "xbom:ai:reasoning", "value": result.get("reasoning", "")},
                ],
            }
            bom["components"].append(ai_comp)
            count += 1

        return count

    # ── Layer 3b: ecosyste.ms heuristic (no --enrich) ─────────────────

    def _run_ecosystems_heuristic(self, sbom: dict[str, Any], bom: dict[str, Any]) -> int:
        """Weak fallback when --enrich not used: query ecosyste.ms and use keyword heuristic.

        This is deliberately conservative — it only flags packages with strong AI keyword signals.
        For accurate classification, use --enrich to let the agent decide.
        """
        from xbom.modules.aibom.ecosystems_client import EcosystemsClient, is_ai_related

        already = _existing_purls(bom) | _existing_names(bom)
        unchecked = []
        purl_to_comp: dict[str, dict] = {}

        for comp in sbom.get("components", []):
            purl = comp.get("purl")
            name = comp.get("name", "")
            if not purl or purl in already or name in already:
                continue
            unchecked.append(purl)
            purl_to_comp[purl] = comp

        if not unchecked:
            return 0

        client = EcosystemsClient()
        try:
            packages = asyncio.run(client.bulk_lookup(unchecked))
        except Exception as e:
            logger.warning("ecosyste.ms bulk lookup failed: %s", e)
            return 0

        pkg_by_name = {pkg.name.lower(): pkg for pkg in packages}
        count = 0

        for purl, comp in purl_to_comp.items():
            name = comp.get("name", "").lower()
            pkg = pkg_by_name.get(name)
            if not pkg or not is_ai_related(pkg.keywords):
                continue

            ai_comp = {
                "type": "library",
                "name": comp.get("name", ""),
                "version": comp.get("version"),
                "purl": purl,
                "properties": [
                    {"name": "xbom:ai:detected", "value": "true"},
                    {"name": "xbom:ai:category", "value": "unclassified"},
                    {"name": "xbom:ai:scanner", "value": "ecosystems-heuristic"},
                    {"name": "xbom:ai:confidence", "value": "0.5"},
                    {"name": "xbom:ai:keywords", "value": ", ".join(pkg.keywords[:10])},
                    {"name": "xbom:ai:description", "value": pkg.description or ""},
                    {"name": "xbom:ai:note", "value": "Use --enrich for agent-based classification"},
                ],
            }
            existing_names = _existing_names(bom)
            if comp.get("name", "") not in existing_names:
                bom["components"].append(ai_comp)
                count += 1

        return count


    # ── Layer 4: CodeGraph analysis ──────────────────────────────────────

    def _run_codegraph_analysis(self, project_path: Path, bom: dict[str, Any], config: ScanConfig) -> int:
        """Use FalkorDB code-graph + MCP + Strands Agent to find custom AI components
        and relationships via code graph analysis."""
        from xbom.modules.aibom.codegraph import analyze_with_codegraph, is_falkordb_available

        if not is_falkordb_available():
            logger.info("FalkorDB not available at localhost:6379, skipping CodeGraph analysis. "
                        "Start with: docker run -p 6379:6379 -it --rm falkordb/falkordb")
            return 0

        results = analyze_with_codegraph(project_path, config)
        count = 0

        # Merge components
        existing = _existing_names(bom)
        for comp in results.get("components", []):
            name = comp.get("name", "")
            if name in existing:
                continue
            existing.add(name)

            bom_comp = {
                "type": _component_cdx_type(comp.get("category", "other")),
                "name": name,
                "properties": [
                    {"name": "xbom:ai:detected", "value": "true"},
                    {"name": "xbom:ai:category", "value": comp.get("category", "other")},
                    {"name": "xbom:ai:scanner", "value": "codegraph-agent"},
                    {"name": "xbom:ai:confidence", "value": str(comp.get("confidence", 0.85))},
                    {"name": "xbom:ai:evidence", "value": comp.get("evidence", "")},
                    {"name": "xbom:ai:base_class", "value": comp.get("base_class", "")},
                    {"name": "xbom:ai:source_file", "value": comp.get("file_path", "")},
                ],
            }
            if comp.get("line_start"):
                add_property(bom_comp, "xbom:ai:source_line", str(comp["line_start"]))
            bom["components"].append(bom_comp)
            count += 1

        # Merge relationships as properties on source components
        for rel in results.get("relationships", []):
            source_name = rel.get("source", "")
            for bom_comp in bom.get("components", []):
                if bom_comp.get("name") == source_name:
                    rel_str = f"{rel.get('type', 'USES')} → {rel.get('target', '?')} ({rel.get('target_category', '')})"
                    props = bom_comp.setdefault("properties", [])
                    props.append({"name": "xbom:ai:relationship", "value": rel_str})
                    break

        # Architecture pattern
        arch = results.get("architecture", {})
        if arch.get("pattern"):
            # Add as property on the root/first component or metadata
            bom.setdefault("properties", []).append(
                {"name": "xbom:ai:architecture_pattern", "value": arch.get("pattern", "")},
            )
            if arch.get("description"):
                bom.setdefault("properties", []).append(
                    {"name": "xbom:ai:architecture_description", "value": arch["description"]},
                )

        return count

    # ── Post-processing ────────────────────────────────────────────────

    def _detect_shadow_ai(self, sbom: dict[str, Any], bom: dict[str, Any]) -> None:
        """Flag AI packages found by pattern scan but absent from SBOM (undeclared deps)."""
        sbom_names = {c.get("name", "").lower() for c in sbom.get("components", [])}
        sbom_purls = {c.get("purl", "").lower() for c in sbom.get("components", []) if c.get("purl")}

        for comp in bom.get("components", []):
            props = {p["name"]: p["value"] for p in comp.get("properties", [])}
            if props.get("xbom:ai:scanner") != "import-scanner":
                continue

            name = comp.get("name", "").lower()
            # Check if this import's package is in the SBOM
            if name not in sbom_names and not any(name in p for p in sbom_purls):
                add_property(comp, "xbom:ai:shadow_ai", "true")


# ── Helpers ────────────────────────────────────────────────────────────


def _existing_purls(bom: dict[str, Any]) -> set[str]:
    return {c.get("purl") for c in bom.get("components", []) if c.get("purl")}


def _existing_names(bom: dict[str, Any]) -> set[str]:
    return {c.get("name") for c in bom.get("components", []) if c.get("name")}


def _ecosystem_from_purl(purl: str) -> str:
    """Extract ecosystem from a PURL string."""
    try:
        from packageurl import PackageURL
        p = PackageURL.from_string(purl)
        return p.type or ""
    except Exception:
        return ""


def _component_cdx_type(category: str) -> str:
    """Map AI component category to CycloneDX component type."""
    service_types = {"model-serving", "vector-store", "graph-db", "endpoint", "gateway"}
    if category in service_types:
        return "platform"
    if category in ("ml-framework", "agent-framework"):
        return "framework"
    if category == "model-reference":
        return "machine-learning-model"
    return "library"
