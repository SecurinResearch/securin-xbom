"""SBOM module — orchestrates cdxgen or trivy for SBOM generation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from xbom.models import BomType, SbomTool, ScanConfig
from xbom.modules.base import BomModule, ScanError
from xbom.modules.sbom import cdxgen, trivy


class SbomModule(BomModule):
    """Generates Software Bill of Materials using cdxgen (default) or Trivy."""

    @property
    def bom_type(self) -> BomType:
        return BomType.SBOM

    @property
    def name(self) -> str:
        return "SBOM"

    def required_tools(self) -> list[str]:
        return ["cdxgen"]  # Trivy is an alternative, checked at runtime

    def scan(self, project_path: Path, config: ScanConfig, sbom: dict[str, Any] | None = None) -> dict[str, Any]:
        tool = config.sbom_tool

        if tool == SbomTool.CDXGEN:
            return self._scan_cdxgen(project_path, config)
        elif tool == SbomTool.TRIVY:
            return self._scan_trivy(project_path, config)
        else:
            raise ScanError(self.name, f"Unknown SBOM tool: {tool}")

    def _scan_cdxgen(self, project_path: Path, config: ScanConfig) -> dict[str, Any]:
        if not cdxgen.get_version():
            raise ScanError(
                self.name,
                "cdxgen not found. Install it: npm install -g @cyclonedx/cdxgen\n"
                "Or use --sbom-tool trivy as an alternative.",
            )
        try:
            return cdxgen.generate_sbom(project_path, verbose=config.verbose)
        except RuntimeError as e:
            raise ScanError(self.name, str(e)) from e

    def _scan_trivy(self, project_path: Path, config: ScanConfig) -> dict[str, Any]:
        if not trivy.get_version():
            raise ScanError(
                self.name,
                "trivy not found. Install it: brew install trivy\n"
                "Or use the default --sbom-tool cdxgen.",
            )
        try:
            return trivy.generate_sbom(project_path, verbose=config.verbose)
        except RuntimeError as e:
            raise ScanError(self.name, str(e)) from e
