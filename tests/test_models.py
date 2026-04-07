"""Tests for data models."""

from pathlib import Path

from xbom.models import BomType, SbomTool, ScanConfig


def test_bom_types():
    assert BomType.SBOM.value == "sbom"
    assert BomType.AIBOM.value == "aibom"
    assert BomType.CBOM.value == "cbom"
    assert BomType.APIBOM.value == "apibom"


def test_scan_config_defaults():
    config = ScanConfig(target="/tmp/test")
    assert config.output_dir == Path("./xbom-output")
    assert len(config.bom_types) == 4
    assert config.sbom_tool == SbomTool.CDXGEN
    assert config.enrich is False
    assert config.verbose is False


def test_sbom_tool_enum():
    assert SbomTool.CDXGEN.value == "cdxgen"
    assert SbomTool.TRIVY.value == "trivy"
