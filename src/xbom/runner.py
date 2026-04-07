"""Scan runner — orchestrates BOM modules and produces unified output."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from xbom.merger import merge_boms
from xbom.models import BomType, ScanConfig, ScanResult, SourceInfo
from xbom.modules.base import BomModule, ScanError
from xbom.modules.aibom.scanner import AibomModule
from xbom.modules.apibom.scanner import ApibomModule
from xbom.modules.cbom.scanner import CbomModule
from xbom.modules.sbom.scanner import SbomModule
from xbom.utils.cyclonedx import validate_bom, write_bom_json

console = Console(stderr=True)


def get_modules(config: ScanConfig) -> list[BomModule]:
    """Get the list of BOM modules to run based on config."""
    all_modules: list[BomModule] = [
        SbomModule(),
        AibomModule(),
        CbomModule(),
        ApibomModule(),
    ]
    return [m for m in all_modules if m.bom_type in config.bom_types]


def run_scan(source_info: SourceInfo, config: ScanConfig) -> dict[str, Any]:
    """Run all configured BOM modules and produce a merged output.

    Args:
        source_info: Resolved source metadata.
        config: Scan configuration.

    Returns:
        Merged CycloneDX 1.6 JSON dict.
    """
    project_path = source_info.local_path
    modules = get_modules(config)

    if not modules:
        console.print("[yellow]No BOM modules selected. Nothing to scan.[/yellow]")
        return {}

    results: dict[BomType, dict[str, Any]] = {}
    scan_results: list[ScanResult] = []

    # Phase 1: Run SBOM first (other modules may need its output)
    sbom_module = next((m for m in modules if m.bom_type == BomType.SBOM), None)
    sbom_data: dict[str, Any] | None = None

    if sbom_module:
        console.print(f"\n[bold]Running {sbom_module.name}...[/bold]")
        start = time.time()
        try:
            sbom_data = sbom_module.scan(project_path, config)
            elapsed = time.time() - start
            results[BomType.SBOM] = sbom_data
            scan_results.append(ScanResult(
                bom_type=BomType.SBOM,
                bom_json=sbom_data,
                tool_used=config.sbom_tool.value,
                scan_time_seconds=elapsed,
            ))
            n_components = len(sbom_data.get("components", []))
            console.print(f"  [green]SBOM: {n_components} components found ({elapsed:.1f}s)[/green]")
        except ScanError as e:
            elapsed = time.time() - start
            scan_results.append(ScanResult(bom_type=BomType.SBOM, error=str(e), scan_time_seconds=elapsed))
            console.print(f"  [red]SBOM failed: {e}[/red]")

    # Phase 2: Run remaining modules (can use SBOM for cross-reference)
    other_modules = [m for m in modules if m.bom_type != BomType.SBOM]
    for module in other_modules:
        console.print(f"\n[bold]Running {module.name}...[/bold]")
        start = time.time()
        try:
            bom = module.scan(project_path, config, sbom=sbom_data)
            elapsed = time.time() - start
            results[module.bom_type] = bom
            scan_results.append(ScanResult(
                bom_type=module.bom_type,
                bom_json=bom,
                scan_time_seconds=elapsed,
            ))
            _log_module_result(module, bom, elapsed)
        except ScanError as e:
            elapsed = time.time() - start
            scan_results.append(ScanResult(bom_type=module.bom_type, error=str(e), scan_time_seconds=elapsed))
            console.print(f"  [red]{module.name} failed: {e}[/red]")

    if not results:
        console.print("\n[red]All modules failed. No output produced.[/red]")
        return {}

    # Merge all BOMs
    source_metadata = _build_source_component(source_info)
    composite = merge_boms(results, source_metadata)

    # Validate
    issues = validate_bom(composite)
    if issues:
        console.print(f"\n[yellow]BOM validation warnings: {', '.join(issues)}[/yellow]")

    # Write outputs
    _write_outputs(composite, results, config)

    # Print summary
    _print_summary(scan_results, config)

    return composite


def _log_module_result(module: BomModule, bom: dict[str, Any], elapsed: float) -> None:
    """Log a brief summary of a module's output."""
    n_components = len(bom.get("components", []))
    n_services = len(bom.get("services", []))
    parts = []
    if n_components:
        parts.append(f"{n_components} components")
    if n_services:
        parts.append(f"{n_services} services")
    summary = ", ".join(parts) if parts else "no findings"
    console.print(f"  [green]{module.name}: {summary} ({elapsed:.1f}s)[/green]")


def _build_source_component(info: SourceInfo) -> dict[str, Any]:
    """Build a CycloneDX component representing the scanned project."""
    comp: dict[str, Any] = {
        "type": "application",
        "name": info.repo or info.local_path.name,
        "properties": [],
    }
    if info.org:
        comp["group"] = info.org
    if info.commit_sha:
        comp["properties"].append({"name": "xbom:source:commit", "value": info.commit_sha})
    if info.branch:
        comp["properties"].append({"name": "xbom:source:branch", "value": info.branch})
    if info.url:
        comp["properties"].append({"name": "xbom:source:url", "value": info.url})
    comp["properties"].append({"name": "xbom:source:provider", "value": info.provider})
    return comp


def _write_outputs(
    composite: dict[str, Any],
    results: dict[BomType, dict[str, Any]],
    config: ScanConfig,
) -> None:
    """Write BOM output files."""
    output_dir = config.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    # Write composite BOM
    composite_path = output_dir / "xbom-composite.cdx.json"
    write_bom_json(composite, composite_path)
    console.print(f"\n[bold green]Composite BOM written to: {composite_path}[/bold green]")

    # Write individual BOMs
    bom_filenames = {
        BomType.SBOM: "sbom.cdx.json",
        BomType.AIBOM: "ai-bom.cdx.json",
        BomType.CBOM: "cbom.cdx.json",
        BomType.APIBOM: "api-bom.cdx.json",
    }
    for bom_type, bom in results.items():
        filename = bom_filenames.get(bom_type)
        if filename:
            path = output_dir / filename
            write_bom_json(bom, path)
            console.print(f"  {bom_type.value}: {path}")


def _print_summary(scan_results: list[ScanResult], config: ScanConfig) -> None:
    """Print a summary table of scan results."""
    table = Table(title="Scan Summary", show_header=True)
    table.add_column("Module", style="bold")
    table.add_column("Status")
    table.add_column("Findings")
    table.add_column("Time")

    for r in scan_results:
        if r.error:
            status = "[red]FAILED[/red]"
            findings = r.error[:60]
        else:
            status = "[green]OK[/green]"
            n_c = len(r.bom_json.get("components", [])) if r.bom_json else 0
            n_s = len(r.bom_json.get("services", [])) if r.bom_json else 0
            parts = []
            if n_c:
                parts.append(f"{n_c} components")
            if n_s:
                parts.append(f"{n_s} services")
            findings = ", ".join(parts) if parts else "0"
        table.add_row(r.bom_type.value.upper(), status, findings, f"{r.scan_time_seconds:.1f}s")

    console.print()
    console.print(table)
