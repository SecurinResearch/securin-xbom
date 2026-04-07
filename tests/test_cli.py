"""Tests for xBOM CLI commands."""

from typer.testing import CliRunner

from xbom.cli import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    # rich Console(stderr=True) writes to stderr, but CliRunner merges output
    assert "xbom" in result.output


def test_doctor_runs():
    """Doctor command should run without crashing (some tools may be missing)."""
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code in (0, 1)
    assert "xBOM" in result.output


def test_scan_missing_target():
    result = runner.invoke(app, ["scan", "/nonexistent/path/abc123"])
    assert result.exit_code == 1


def test_scan_bad_bom_type():
    result = runner.invoke(app, ["scan", ".", "--bom-types", "invalid"])
    assert result.exit_code != 0
