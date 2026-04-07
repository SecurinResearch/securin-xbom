"""Base interface for API endpoint extractors and shared data model."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# YAML rules loading (cached at module level)
# ---------------------------------------------------------------------------

_RULES_DIR = Path(__file__).parent.parent / "rules"
_rules_cache: dict[str, Any] = {}


def _load_rules(name: str) -> Any:
    """Load and cache a rules YAML file."""
    if name not in _rules_cache:
        with open(_RULES_DIR / f"{name}.yaml") as f:
            _rules_cache[name] = yaml.safe_load(f)
    return _rules_cache[name]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ApiEndpoint:
    """A single detected API endpoint."""

    path: str  # /api/users/{id}
    method: str  # GET, POST, PUT, DELETE, PATCH, *
    framework: str  # fastapi, flask, express
    source_file: str  # relative path
    source_line: int  # line number
    category: str  # internal-endpoint, external-dependency, api-spec, webhook
    auth_detected: bool = False
    description: str = ""
    host: str = ""  # for external dependencies


# ---------------------------------------------------------------------------
# Abstract extractor
# ---------------------------------------------------------------------------


class FrameworkExtractor(ABC):
    """Abstract base for framework-specific route extractors."""

    @property
    @abstractmethod
    def framework_name(self) -> str:
        """Framework identifier (e.g. 'fastapi', 'flask', 'express')."""

    @abstractmethod
    def extract(self, file_path: Path, content: str, rel_path: str) -> list[ApiEndpoint]:
        """Extract API endpoints from a source file.

        Args:
            file_path: Absolute path to the file.
            content: File contents.
            rel_path: Relative path from project root.

        Returns:
            List of detected API endpoints.
        """

    @abstractmethod
    def detect(self, content: str) -> bool:
        """Quick check: does this file use this framework?"""


# ---------------------------------------------------------------------------
# File iteration helpers
# ---------------------------------------------------------------------------

_SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".env",
    "vendor",
    "target",
    "build",
    "dist",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "site-packages",
    ".next",
}


def walk_source_files(project_path: Path, extensions: set[str]) -> Iterator[Path]:
    """Yield source files matching given extensions, skipping common non-project dirs."""
    for item in project_path.iterdir():
        try:
            if item.is_dir():
                if item.name in _SKIP_DIRS:
                    continue
                yield from walk_source_files(item, extensions)
            elif item.is_file() and item.suffix in extensions:
                yield item
        except PermissionError:
            continue


def read_file_safe(path: Path) -> str | None:
    """Read a file, returning None on failure."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return None


def compile_patterns(raw: list[str]) -> list[re.Pattern[str]]:
    """Compile a list of regex strings into pattern objects."""
    return [re.compile(p) for p in raw]
