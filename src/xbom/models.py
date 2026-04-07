"""Shared data models for xBOM."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class BomType(str, Enum):
    SBOM = "sbom"
    AIBOM = "aibom"
    CBOM = "cbom"
    APIBOM = "apibom"


class SbomTool(str, Enum):
    CDXGEN = "cdxgen"
    TRIVY = "trivy"


@dataclass
class ScanConfig:
    """Configuration for a single xBOM scan run."""

    target: str
    output_dir: Path = Path("./xbom-output")
    bom_types: list[BomType] = field(default_factory=lambda: list(BomType))
    sbom_tool: SbomTool = SbomTool.CDXGEN
    enrich: bool = False
    live_url: str | None = None
    branch: str | None = None
    token: str | None = None
    provider: str | None = None
    verbose: bool = False
    config_path: Path | None = None


@dataclass
class SourceInfo:
    """Metadata about the resolved source."""

    local_path: Path
    provider: str  # local, github, gitlab, bitbucket
    org: str | None = None
    repo: str | None = None
    branch: str | None = None
    commit_sha: str | None = None
    url: str | None = None
    is_temp: bool = False  # True if we cloned to a temp dir


@dataclass
class ToolInfo:
    """Info about an external tool dependency."""

    name: str
    command: str
    version: str | None = None
    installed: bool = False
    required: bool = True
    purpose: str = ""


@dataclass
class ScanResult:
    """Result from a single BOM module scan."""

    bom_type: BomType
    bom_json: dict[str, Any] | None = None
    error: str | None = None
    tool_used: str | None = None
    scan_time_seconds: float = 0.0
