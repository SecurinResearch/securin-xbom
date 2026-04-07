"""Trivy subprocess wrapper for SBOM generation."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from xbom.config import get_tool_path
from xbom.utils.cyclonedx import add_tool_to_metadata, load_bom_json
from xbom.utils.subprocess import check_tool_version, run


def get_version() -> str | None:
    """Get installed Trivy version."""
    return check_tool_version(get_tool_path("trivy"), "--version")


def generate_sbom(
    project_path: Path,
    *,
    verbose: bool = False,
) -> dict[str, Any]:
    """Run Trivy to generate a CycloneDX SBOM.

    Args:
        project_path: Path to the project.
        verbose: Enable verbose logging.

    Returns:
        CycloneDX 1.6 JSON dict.
    """
    trivy = get_tool_path("trivy")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        output_path = Path(tmp.name)

    cmd = [
        trivy,
        "fs",
        "--format", "cyclonedx",
        "--output", str(output_path),
        "--scanners", "vuln",
        "--list-all-pkgs",
        str(project_path),
    ]

    result = run(cmd, timeout=300, verbose=verbose)

    if not result.success:
        output_path.unlink(missing_ok=True)
        raise RuntimeError(f"trivy failed (exit {result.returncode}): {result.stderr}")

    if not output_path.exists() or output_path.stat().st_size == 0:
        output_path.unlink(missing_ok=True)
        raise RuntimeError("trivy produced no output file")

    try:
        bom = load_bom_json(output_path)
    finally:
        output_path.unlink(missing_ok=True)

    # Tag that trivy was the tool used
    version = get_version()
    add_tool_to_metadata(bom, "trivy", version)

    return bom
