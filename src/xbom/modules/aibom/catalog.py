"""AI/ML package catalog -- static registry of known AI/ML packages.

Maps (ecosystem, package_name_lowercase) to category and description.
Used to classify SBOM components as AI-related.

All data loaded from rules/catalog.yaml and rules/models.yaml.
"""

from __future__ import annotations

from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------

_RULES_DIR = Path(__file__).parent / "rules"

CatalogEntry = dict[str, str]  # {"category": ..., "description": ...}

_CATALOG: dict[tuple[str, str], CatalogEntry] | None = None
_DEPRECATED_MODELS: set[str] | None = None


def _ensure_loaded() -> None:
    """Load catalog and deprecated models from YAML on first access."""
    global _CATALOG, _DEPRECATED_MODELS

    if _CATALOG is None:
        with open(_RULES_DIR / "catalog.yaml") as f:
            data = yaml.safe_load(f)

        _CATALOG = {}
        for entry in data["packages"]:
            key = (entry["ecosystem"].lower(), entry["name"].lower())
            _CATALOG[key] = {
                "category": entry["category"],
                "description": entry["description"],
            }

    if _DEPRECATED_MODELS is None:
        with open(_RULES_DIR / "models.yaml") as f:
            data = yaml.safe_load(f)
        _DEPRECATED_MODELS = set(data["deprecated"])


def _get_catalog() -> dict[tuple[str, str], CatalogEntry]:
    _ensure_loaded()
    assert _CATALOG is not None
    return _CATALOG


def _get_deprecated_models() -> set[str]:
    _ensure_loaded()
    assert _DEPRECATED_MODELS is not None
    return _DEPRECATED_MODELS


# ---------------------------------------------------------------------------
# Deprecated models
# ---------------------------------------------------------------------------


def is_deprecated_model(model_name: str) -> bool:
    """Check if a model name is known-deprecated."""
    deprecated = _get_deprecated_models()
    name = model_name.lower().strip()
    return any(name.startswith(d) or name == d for d in deprecated)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def lookup(ecosystem: str, name: str) -> CatalogEntry | None:
    """Look up a package in the AI catalog.

    Args:
        ecosystem: Package ecosystem (pypi, npm, maven, go).
        name: Package name (case-insensitive for matching).

    Returns:
        Catalog entry dict with ``category`` and ``description``, or *None*.
    """
    return _get_catalog().get((ecosystem.lower(), name.lower()))


def lookup_by_purl(purl: str) -> CatalogEntry | None:
    """Look up a package by its Package URL (PURL).

    Supports the following PURL schemes::

        pkg:pypi/openai@1.30.0
        pkg:npm/%40anthropic-ai/sdk@0.24.0
        pkg:maven/org.tensorflow/tensorflow-core-platform@0.5.0
        pkg:golang/github.com/sashabaranov/go-openai@1.24.1

    Args:
        purl: A Package URL string (RFC compliant).

    Returns:
        Catalog entry dict, or *None*.
    """
    if not purl.startswith("pkg:"):
        return None

    # Strip "pkg:" prefix
    rest = purl[4:]

    # Split ecosystem from the remainder
    slash_idx = rest.find("/")
    if slash_idx == -1:
        return None

    ecosystem_raw = rest[:slash_idx]
    remainder = rest[slash_idx + 1:]

    # Map PURL type to our ecosystem key
    ecosystem_map: dict[str, str] = {
        "pypi": "pypi",
        "npm": "npm",
        "maven": "maven",
        "golang": "go",
    }
    ecosystem = ecosystem_map.get(ecosystem_raw.lower())
    if ecosystem is None:
        return None

    # Strip version (@...) and qualifiers (?...) / subpath (#...)
    for sep in ("@", "?", "#"):
        idx = remainder.find(sep)
        if idx != -1:
            remainder = remainder[:idx]

    # URL-decode (e.g. %40 -> @, %2F -> /)
    try:
        from urllib.parse import unquote

        name = unquote(remainder)
    except Exception:
        name = remainder

    # Maven PURLs use "group/artifact" -- we store them as "group:artifact"
    if ecosystem == "maven" and "/" in name:
        name = name.replace("/", ":")

    return lookup(ecosystem, name)
