"""Outbound HTTP client call detection — Layer 3."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from urllib.parse import urlparse

from xbom.modules.apibom.extractors.base import (
    ApiEndpoint,
    _load_rules,
    read_file_safe,
    walk_source_files,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_PY_EXTENSIONS = {".py", ".pyi"}
_JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"}
_JAVA_EXTENSIONS = {".java", ".kt", ".scala"}
_GO_EXTENSIONS = {".go"}

_ALL_EXTENSIONS = _PY_EXTENSIONS | _JS_EXTENSIONS | _JAVA_EXTENSIONS | _GO_EXTENSIONS

_client_config: dict | None = None


def _get_client_config() -> dict:
    global _client_config
    if _client_config is None:
        _client_config = _load_rules("clients")
    return _client_config


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_client_calls(project_path: Path) -> list[ApiEndpoint]:
    """Detect outbound HTTP client calls in the project.

    Returns:
        List of ApiEndpoint with category="external-dependency".
    """
    config = _get_client_config()
    endpoints: list[ApiEndpoint] = []
    seen: set[str] = set()

    for file_path in walk_source_files(project_path, _ALL_EXTENSIONS):
        content = read_file_safe(file_path)
        if not content:
            continue

        rel_path = str(file_path.relative_to(project_path))
        lang = _detect_language(file_path)
        if not lang:
            continue

        lang_config = config.get(lang, [])
        if not lang_config:
            continue

        lines = content.splitlines()

        for lib_cfg in lang_config:
            detect_pat = lib_cfg.get("detect")
            library = lib_cfg.get("library", "unknown")

            # If detect pattern exists, check if library is used in this file
            if detect_pat and not re.search(detect_pat, content):
                continue

            for pat_str in lib_cfg.get("patterns", []):
                pattern = re.compile(pat_str)
                for i, line in enumerate(lines, 1):
                    m = pattern.search(line)
                    if not m:
                        continue

                    # Extract URL — last group is usually the URL
                    url = _extract_url(m)
                    if not url:
                        continue

                    host = _extract_host(url)
                    if not host:
                        continue

                    # Dedup by host + file
                    key = f"{host}|{rel_path}"
                    if key in seen:
                        continue
                    seen.add(key)

                    # Try to extract method
                    method = _extract_method(m)

                    endpoints.append(
                        ApiEndpoint(
                            path=url,
                            method=method,
                            framework=library,
                            source_file=rel_path,
                            source_line=i,
                            category="external-dependency",
                            host=host,
                            description=f"Outbound {method} call via {library} to {host}",
                            auth_detected=False,  # can't reliably detect for outbound
                        )
                    )

    return endpoints


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _detect_language(file_path: Path) -> str | None:
    """Map file extension to language key in clients.yaml."""
    ext = file_path.suffix
    if ext in _PY_EXTENSIONS:
        return "python"
    if ext in _JS_EXTENSIONS:
        return "javascript"
    if ext in _JAVA_EXTENSIONS:
        return "java"
    if ext in _GO_EXTENSIONS:
        return "go"
    return None


def _extract_url(match: re.Match[str]) -> str:
    """Extract the URL from a regex match (usually the last group containing http)."""
    for i in range(match.lastindex or 0, 0, -1):
        grp = match.group(i)
        if grp and grp.startswith("http"):
            return grp
    return ""


def _extract_host(url: str) -> str:
    """Extract hostname from a URL."""
    try:
        parsed = urlparse(url)
        return parsed.hostname or ""
    except Exception:
        return ""


def _extract_method(match: re.Match[str]) -> str:
    """Try to extract HTTP method from a regex match."""
    for i in range(1, (match.lastindex or 0) + 1):
        grp = match.group(i)
        if grp and grp.upper() in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
            return grp.upper()
    return "*"
