"""cdxgen subprocess wrapper for SBOM and CBOM generation."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from xbom.config import get_tool_path
from xbom.utils.cyclonedx import add_tool_to_metadata, load_bom_json
from xbom.utils.subprocess import check_tool_version, run


def get_version() -> str | None:
    """Get installed cdxgen version."""
    return check_tool_version(get_tool_path("cdxgen"), "--version")


def generate_sbom(
    project_path: Path,
    *,
    project_type: str | None = None,
    include_crypto: bool = False,
    verbose: bool = False,
) -> dict[str, Any]:
    """Run cdxgen to generate a CycloneDX SBOM.

    Args:
        project_path: Path to the project.
        project_type: Force a project type (e.g., "python", "java"). Auto-detected if None.
        include_crypto: If True, include crypto BOM data (Java/Python only).
        verbose: Enable verbose logging.

    Returns:
        CycloneDX 1.6 JSON dict.
    """
    cdxgen = get_tool_path("cdxgen")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        output_path = Path(tmp.name)

    cmd = [
        cdxgen,
        "--spec-version", "1.6",
        "--output", str(output_path),
    ]

    if project_type:
        cmd.extend(["--type", project_type])

    if include_crypto:
        cmd.append("--include-crypto")

    cmd.append(str(project_path))

    result = run(cmd, timeout=300, verbose=verbose)

    if not result.success:
        output_path.unlink(missing_ok=True)
        raise RuntimeError(f"cdxgen failed (exit {result.returncode}): {result.stderr}")

    if not output_path.exists() or output_path.stat().st_size == 0:
        output_path.unlink(missing_ok=True)
        raise RuntimeError("cdxgen produced no output file")

    try:
        bom = load_bom_json(output_path)
    finally:
        output_path.unlink(missing_ok=True)

    # Tag that cdxgen was the tool used
    version = get_version()
    add_tool_to_metadata(bom, "cdxgen", version)

    return bom
