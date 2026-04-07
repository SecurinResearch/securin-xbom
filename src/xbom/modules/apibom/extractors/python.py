"""Python framework extractors — FastAPI, Flask, Django."""

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
        _fw_config = _load_rules("frameworks")["python"]
    return _fw_config


def _compile_detect(fw: str) -> list[re.Pattern[str]]:
    return [re.compile(p) for p in _get_fw_config()[fw]["detect"]]


def _compile_auth(fw: str) -> list[re.Pattern[str]]:
    return [re.compile(p) for p in _get_fw_config()[fw].get("auth_indicators", [])]


# ---------------------------------------------------------------------------
# FastAPI extractor
# ---------------------------------------------------------------------------


class FastAPIExtractor(FrameworkExtractor):
    """Extract routes from FastAPI applications."""

    @property
    def framework_name(self) -> str:
        return "fastapi"

    def detect(self, content: str) -> bool:
        return any(p.search(content) for p in _compile_detect("fastapi"))

    def extract(self, file_path: Path, content: str, rel_path: str) -> list[ApiEndpoint]:
        cfg = _get_fw_config()["fastapi"]
        endpoints: list[ApiEndpoint] = []
        lines = content.splitlines()

        # Detect router prefix in file
        prefix = ""
        for pat_str in cfg.get("router_prefix", []):
            m = re.search(pat_str, content)
            if m:
                prefix = m.group(1).rstrip("/")
                break

        # Check for auth in file (file-level)
        auth_patterns = _compile_auth("fastapi")
        file_has_auth = any(p.search(content) for p in auth_patterns)

        # Extract routes
        for route_cfg in cfg["routes"]:
            pattern = re.compile(route_cfg["pattern"])
            for i, line in enumerate(lines, 1):
                m = pattern.search(line)
                if not m:
                    continue

                method_grp = route_cfg.get("method_group")
                path_grp = route_cfg.get("path_group")

                method = m.group(method_grp).upper() if method_grp and m.group(method_grp) else "*"
                path = m.group(path_grp) if path_grp and m.group(path_grp) else ""

                if not path:
                    continue

                full_path = prefix + path if prefix else path

                # Check for auth on this specific endpoint (look at surrounding lines)
                endpoint_auth = file_has_auth or _check_nearby_auth(lines, i - 1, auth_patterns)

                endpoints.append(
                    ApiEndpoint(
                        path=full_path,
                        method=method,
                        framework="fastapi",
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
                            framework="fastapi",
                            source_file=rel_path,
                            source_line=i,
                            category="websocket",
                        )
                    )

        return endpoints


# ---------------------------------------------------------------------------
# Flask extractor
# ---------------------------------------------------------------------------


class FlaskExtractor(FrameworkExtractor):
    """Extract routes from Flask applications."""

    @property
    def framework_name(self) -> str:
        return "flask"

    def detect(self, content: str) -> bool:
        return any(p.search(content) for p in _compile_detect("flask"))

    def extract(self, file_path: Path, content: str, rel_path: str) -> list[ApiEndpoint]:
        cfg = _get_fw_config()["flask"]
        endpoints: list[ApiEndpoint] = []
        lines = content.splitlines()

        # Detect Blueprint prefix
        prefix = ""
        for pat_str in cfg.get("router_prefix", []):
            m = re.search(pat_str, content)
            if m and m.group(1):
                prefix = m.group(1).rstrip("/")
                break

        auth_patterns = _compile_auth("flask")
        file_has_auth = any(p.search(content) for p in auth_patterns)

        for route_cfg in cfg["routes"]:
            pattern = re.compile(route_cfg["pattern"])
            for i, line in enumerate(lines, 1):
                m = pattern.search(line)
                if not m:
                    continue

                path_grp = route_cfg.get("path_group")
                method_grp = route_cfg.get("method_group")
                default_method = route_cfg.get("default_method", "*")

                path = m.group(path_grp) if path_grp and m.group(path_grp) else ""
                if not path:
                    continue

                full_path = prefix + path if prefix else path

                # Parse methods from group (e.g. '"GET", "POST"') or use default
                if method_grp:
                    raw = m.group(method_grp) if m.lastindex and m.lastindex >= method_grp else None
                    methods = _parse_method_list(raw) if raw else [default_method]
                else:
                    methods = [default_method]

                endpoint_auth = file_has_auth or _check_nearby_auth(lines, i - 1, auth_patterns)

                for method in methods:
                    endpoints.append(
                        ApiEndpoint(
                            path=full_path,
                            method=method.upper(),
                            framework="flask",
                            source_file=rel_path,
                            source_line=i,
                            category="internal-endpoint",
                            auth_detected=endpoint_auth,
                        )
                    )

        return endpoints


# ---------------------------------------------------------------------------
# Django extractor
# ---------------------------------------------------------------------------


class DjangoExtractor(FrameworkExtractor):
    """Extract routes from Django/DRF applications."""

    @property
    def framework_name(self) -> str:
        return "django"

    def detect(self, content: str) -> bool:
        return any(p.search(content) for p in _compile_detect("django"))

    def extract(self, file_path: Path, content: str, rel_path: str) -> list[ApiEndpoint]:
        cfg = _get_fw_config()["django"]
        endpoints: list[ApiEndpoint] = []
        lines = content.splitlines()

        auth_patterns = _compile_auth("django")
        file_has_auth = any(p.search(content) for p in auth_patterns)

        for route_cfg in cfg["routes"]:
            pattern = re.compile(route_cfg["pattern"])
            for i, line in enumerate(lines, 1):
                m = pattern.search(line)
                if not m:
                    continue

                path_grp = route_cfg.get("path_group")
                method_grp = route_cfg.get("method_group")
                default_method = route_cfg.get("default_method", "*")

                path = ""
                if path_grp and m.lastindex and m.lastindex >= path_grp:
                    path = m.group(path_grp) or ""

                methods = [default_method]
                if method_grp and m.lastindex and m.lastindex >= method_grp:
                    raw = m.group(method_grp)
                    if raw:
                        methods = _parse_method_list(raw)

                # Django paths: ensure leading slash
                if path and not path.startswith("/"):
                    path = "/" + path

                for method in methods:
                    endpoints.append(
                        ApiEndpoint(
                            path=path or "/",
                            method=method.upper(),
                            framework="django",
                            source_file=rel_path,
                            source_line=i,
                            category="internal-endpoint",
                            auth_detected=file_has_auth,
                        )
                    )

        return endpoints


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_method_list(raw: str) -> list[str]:
    """Parse methods from a string like '"GET", "POST"' or 'GET|POST'."""
    # Strip quotes and split by comma or pipe
    cleaned = raw.replace("'", "").replace('"', "").strip()
    if "|" in cleaned:
        return [m.strip() for m in cleaned.split("|") if m.strip()]
    return [m.strip() for m in cleaned.split(",") if m.strip()]


def _check_nearby_auth(lines: list[str], line_idx: int, auth_patterns: list[re.Pattern[str]]) -> bool:
    """Check for auth decorators/middleware in lines immediately above the route."""
    start = max(0, line_idx - 5)
    for i in range(start, line_idx):
        for p in auth_patterns:
            if p.search(lines[i]):
                return True
    return False


# All Python extractors
PYTHON_EXTRACTORS: list[type[FrameworkExtractor]] = [
    FastAPIExtractor,
    FlaskExtractor,
    DjangoExtractor,
]
