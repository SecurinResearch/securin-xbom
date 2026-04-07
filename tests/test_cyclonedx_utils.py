"""Tests for CycloneDX utility functions."""

from xbom.utils.cyclonedx import (
    add_property,
    add_tool_to_metadata,
    find_component_by_purl,
    new_bom_skeleton,
    validate_bom,
)


def test_new_bom_skeleton():
    bom = new_bom_skeleton()
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert "serialNumber" in bom
    assert bom["components"] == []


def test_add_tool_to_metadata():
    bom = new_bom_skeleton()
    add_tool_to_metadata(bom, "cdxgen", "10.5.0")
    tools = bom["metadata"]["tools"]["components"]
    assert any(t["name"] == "cdxgen" for t in tools)

    # Should not add duplicates
    add_tool_to_metadata(bom, "cdxgen", "10.5.0")
    assert sum(1 for t in tools if t["name"] == "cdxgen") == 1


def test_add_property():
    comp = {"name": "test"}
    add_property(comp, "xbom:ai:detected", "true")
    assert comp["properties"] == [{"name": "xbom:ai:detected", "value": "true"}]

    # Update existing
    add_property(comp, "xbom:ai:detected", "false")
    assert len(comp["properties"]) == 1
    assert comp["properties"][0]["value"] == "false"


def test_find_component_by_purl():
    bom = new_bom_skeleton()
    bom["components"] = [
        {"name": "foo", "purl": "pkg:pypi/foo@1.0"},
        {"name": "bar", "purl": "pkg:npm/bar@2.0"},
    ]
    assert find_component_by_purl(bom, "pkg:pypi/foo@1.0")["name"] == "foo"
    assert find_component_by_purl(bom, "pkg:npm/baz@1.0") is None


def test_validate_bom():
    bom = new_bom_skeleton()
    assert validate_bom(bom) == []

    bad_bom = {"bomFormat": "wrong", "specVersion": "0.1"}
    issues = validate_bom(bad_bom)
    assert len(issues) >= 2


def test_validate_bom_missing_serial():
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6"}
    issues = validate_bom(bom)
    assert any("serialNumber" in i for i in issues)
