"""Tests for BOM merging."""

from xbom.merger import merge_boms
from xbom.models import BomType


def _make_sbom():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {"name": "langchain", "purl": "pkg:pypi/langchain@0.1.0", "type": "library"},
            {"name": "requests", "purl": "pkg:pypi/requests@2.31.0", "type": "library"},
        ],
        "dependencies": [],
        "metadata": {"tools": {"components": [{"type": "application", "name": "cdxgen", "version": "10.0"}]}},
    }


def _make_aibom():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "name": "langchain",
                "purl": "pkg:pypi/langchain@0.1.0",
                "type": "library",
                "properties": [
                    {"name": "xbom:ai:category", "value": "agent-framework"},
                    {"name": "xbom:ai:detected", "value": "true"},
                ],
            },
            {
                "name": "gpt-4o",
                "type": "machine-learning-model",
                "properties": [
                    {"name": "xbom:ai:category", "value": "model"},
                ],
            },
        ],
        "metadata": {"tools": {"components": []}},
    }


def _make_cbom():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "name": "AES-256-GCM",
                "type": "cryptographic-asset",
                "cryptoProperties": {"assetType": "algorithm"},
            },
        ],
        "metadata": {"tools": {"components": [{"type": "application", "name": "semgrep"}]}},
    }


def _make_apibom():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "services": [
            {
                "name": "users-api",
                "endpoints": ["/api/users", "/api/users/{id}"],
                "properties": [{"name": "xbom:api:framework", "value": "fastapi"}],
            },
        ],
        "metadata": {"tools": {"components": []}},
    }


def test_merge_sbom_only():
    results = {BomType.SBOM: _make_sbom()}
    merged = merge_boms(results)
    assert len(merged["components"]) == 2
    assert merged["bomFormat"] == "CycloneDX"


def test_merge_sbom_and_aibom():
    results = {BomType.SBOM: _make_sbom(), BomType.AIBOM: _make_aibom()}
    merged = merge_boms(results)

    # langchain should be in components once (from SBOM) with AI properties merged
    langchains = [c for c in merged["components"] if c["name"] == "langchain"]
    assert len(langchains) == 1
    props = {p["name"]: p["value"] for p in langchains[0].get("properties", [])}
    assert props.get("xbom:ai:category") == "agent-framework"

    # gpt-4o should be added as new
    models = [c for c in merged["components"] if c["name"] == "gpt-4o"]
    assert len(models) == 1


def test_merge_all_four():
    results = {
        BomType.SBOM: _make_sbom(),
        BomType.AIBOM: _make_aibom(),
        BomType.CBOM: _make_cbom(),
        BomType.APIBOM: _make_apibom(),
    }
    merged = merge_boms(results)

    # Components: 2 from SBOM + 1 new from AIBOM + 1 from CBOM
    assert len(merged["components"]) == 4

    # Services from API-BOM
    assert len(merged["services"]) == 1
    assert merged["services"][0]["name"] == "users-api"

    # Tools should include both cdxgen and semgrep
    tool_names = {t["name"] for t in merged["metadata"]["tools"]["components"]}
    assert "xbom" in tool_names
    assert "cdxgen" in tool_names
    assert "semgrep" in tool_names


def test_merge_with_source_metadata():
    results = {BomType.SBOM: _make_sbom()}
    metadata = {"type": "application", "name": "my-app", "group": "org"}
    merged = merge_boms(results, source_metadata=metadata)
    assert merged["metadata"]["component"]["name"] == "my-app"
