"""Abstract base class for all BOM modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from xbom.models import BomType, ScanConfig


class BomModule(ABC):
    """Base interface that all BOM modules implement."""

    @property
    @abstractmethod
    def bom_type(self) -> BomType:
        """The BOM type this module produces."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of this module."""

    @abstractmethod
    def scan(self, project_path: Path, config: ScanConfig, sbom: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run the scan and return a CycloneDX 1.6 BOM dict.

        Args:
            project_path: Path to the project to scan.
            config: Scan configuration.
            sbom: The SBOM output (if available), for cross-referencing.
                  AI-BOM and CBOM modules use this to identify AI/crypto packages.

        Returns:
            CycloneDX 1.6 JSON as a dict.

        Raises:
            ScanError: If the scan fails.
        """

    def detect(self, project_path: Path) -> bool:
        """Check if this module is applicable to the given project.

        Override to skip scanning when not relevant (e.g., no Java files for
        Spring Boot API-BOM extractor).

        Returns True by default (always run).
        """
        return True

    @abstractmethod
    def required_tools(self) -> list[str]:
        """List external tool commands this module depends on."""


class ScanError(Exception):
    """Raised when a BOM module scan fails."""

    def __init__(self, module_name: str, message: str):
        self.module_name = module_name
        super().__init__(f"[{module_name}] {message}")
