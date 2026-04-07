"""JavaScript framework extractors — Express."""

from __future__ import annotations

import re
from pathlib import Path

from xbom.modules.apibom.extractors.base import (
    ApiEndpoint,
    FrameworkExtractor,
    _load_rules,
)

# ---------------------------------------------------------------------------
# Cached compiled patterns
# ---------------------------------------------------------------------------

_fw_config: dict | None = None


def _get_fw_config() -> dict:
    global _fw_config
    if _fw_config is None:
        _fw_config = _load_rules("frameworks")["javascript"]
    return _fw_config


def _compile_detect(fw: str) -> list[re.Pattern[str]]:
    return [re.compile(p) for p in _get_fw_config()[fw]["detect"]]


def _compile_auth(fw: str) -> list[re.Pattern[str]]:
    return [re.compile(p) for p in _get_fw_config()[fw].get("auth_indicators", [])]


# ---------------------------------------------------------------------------
# Express extractor
# ---------------------------------------------------------------------------


class ExpressExtractor(FrameworkExtractor):
    """Extract routes from Express.js applications."""

    @property
    def framework_name(self) -> str:
        return "express"

    def detect(self, content: str) -> bool:
        return any(p.search(content) for p in _compile_detect("express"))

    def extract(self, file_path: Path, content: str, rel_path: str) -> list[ApiEndpoint]:
        cfg = _get_fw_config()["express"]
        endpoints: list[ApiEndpoint] = []
        lines = content.splitlines()

        # Detect router prefix (app.use('/api', router))
        prefix = ""
        for pat_str in cfg.get("router_prefix", []):
            m = re.search(pat_str, content)
            if m:
                prefix = m.group(1).rstrip("/")
                break

        auth_patterns = _compile_auth("express")
        file_has_auth = any(p.search(content) for p in auth_patterns)

        for route_cfg in cfg["routes"]:
            pattern = re.compile(route_cfg["pattern"])
            for i, line in enumerate(lines, 1):
                m = pattern.search(line)
                if not m:
                    continue

                method_grp = route_cfg.get("method_group")
                path_grp = route_cfg.get("path_group")

                method = m.group(method_grp).upper() if method_grp else "*"
                path = m.group(path_grp) if path_grp else ""

                if not path:
                    continue

                full_path = prefix + path if prefix else path

                # Check for auth middleware in the route args
                endpoint_auth = file_has_auth or _check_line_auth(line, auth_patterns)

                endpoints.append(
                    ApiEndpoint(
                        path=full_path,
                        method=method,
                        framework="express",
                        source_file=rel_path,
                        source_line=i,
                        category="internal-endpoint",
                        auth_detected=endpoint_auth,
                    )
                )

        # Websocket endpoints
        for ws_pat_str in cfg.get("websocket", []):
            ws_pattern = re.compile(ws_pat_str)
            for i, line in enumerate(lines, 1):
                m = ws_pattern.search(line)
                if m:
                    ws_path = prefix + m.group(1) if prefix else m.group(1)
                    endpoints.append(
                        ApiEndpoint(
                            path=ws_path,
                            method="WS",
                            framework="express",
                            source_file=rel_path,
                            source_line=i,
                            category="websocket",
                        )
                    )

        return endpoints


def _check_line_auth(line: str, auth_patterns: list[re.Pattern[str]]) -> bool:
    """Check if auth middleware appears in the route handler arguments."""
    return any(p.search(line) for p in auth_patterns)


JS_EXTRACTORS: list[type[FrameworkExtractor]] = [
    ExpressExtractor,
]
