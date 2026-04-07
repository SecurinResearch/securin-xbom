"""Async HTTP client for the ecosyste.ms Packages API.

Provides bulk and single-package lookups with automatic retry logic,
and a keyword-based check for AI/ML relevance.

API docs: https://packages.ecosyste.ms/api/v1/
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

import httpx
import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration: AI keyword set loaded from agent_config.yaml
# ---------------------------------------------------------------------------

_CONFIG_PATH = Path(__file__).parent / "agent_config.yaml"


def _load_ai_keywords() -> set[str]:
    """Load the canonical AI keyword set from agent_config.yaml."""
    try:
        with open(_CONFIG_PATH) as f:
            cfg = yaml.safe_load(f)
        return {kw.lower() for kw in cfg.get("ai_keywords", [])}
    except Exception:
        logger.debug("Could not load ai_keywords from %s, using built-in fallback", _CONFIG_PATH)
        return {
            "machine-learning", "deep-learning", "llm", "ai", "artificial-intelligence",
            "neural-network", "nlp", "natural-language-processing", "computer-vision",
            "transformer", "gpt", "embedding", "vector-database", "rag", "langchain",
            "openai", "anthropic", "huggingface", "tensorflow", "pytorch", "scikit-learn",
            "ml", "generative-ai", "large-language-model", "chatbot", "text-generation",
            "inference", "model-serving", "reinforcement-learning", "data-science",
        }


AI_KEYWORDS: set[str] = _load_ai_keywords()

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class PackageInfo(BaseModel):
    """Normalized metadata returned by ecosyste.ms."""

    name: str
    ecosystem: str = ""
    description: str = ""
    keywords: list[str] = Field(default_factory=list)
    homepage: str = ""
    repository_url: str = ""
    latest_version: str = ""


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def is_ai_related(keywords: list[str]) -> bool:
    """Return True if *any* keyword overlaps with the AI/ML term set."""
    return bool(AI_KEYWORDS & {kw.lower() for kw in keywords})


# ---------------------------------------------------------------------------
# PURL parsing helper
# ---------------------------------------------------------------------------


def _parse_purl(purl: str) -> tuple[str, str] | None:
    """Extract (ecosystem, name) from a Package URL.

    Uses packageurl-python (already a dependency via cyclonedx-python-lib).
    Returns None on parse failure.
    """
    try:
        from packageurl import PackageURL

        parsed = PackageURL.from_string(purl)
        ecosystem = parsed.type  # e.g. "pypi", "npm", "maven"
        name = parsed.name
        if parsed.namespace:
            name = f"{parsed.namespace}/{name}"
        return ecosystem, name
    except Exception:
        logger.debug("Failed to parse PURL: %s", purl)
        return None


# ---------------------------------------------------------------------------
# Ecosystems client
# ---------------------------------------------------------------------------

# Maps PURL types to ecosyste.ms ecosystem identifiers
_PURL_TYPE_TO_ECOSYSTEM = {
    "pypi": "pypi",
    "npm": "npm",
    "maven": "maven",
    "cargo": "crates.io",
    "gem": "rubygems.org",
    "nuget": "nuget.org",
    "golang": "go",
    "composer": "packagist.org",
    "pub": "pub.dev",
    "hex": "hex.pm",
    "cocoapods": "cocoapods.org",
    "conda": "conda-forge",
    "swift": "swiftpm",
}

_MAX_RETRIES = 3
_BATCH_SIZE = 100


class EcosystemsClient:
    """Async HTTP client for the ecosyste.ms Packages API."""

    def __init__(
        self,
        base_url: str = "https://packages.ecosyste.ms/api/v1",
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    # -- internal helpers ---------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Issue an HTTP request with simple retry on 429 / 5xx."""
        url = f"{self.base_url}{path}"
        backoff = 1.0

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for attempt in range(1, _MAX_RETRIES + 1):
                try:
                    resp = await client.request(method, url, json=json, params=params)
                    if resp.status_code == 429 or resp.status_code >= 500:
                        if attempt < _MAX_RETRIES:
                            retry_after = float(resp.headers.get("Retry-After", backoff))
                            logger.debug(
                                "ecosyste.ms %s %s returned %s, retrying in %.1fs (attempt %d/%d)",
                                method, path, resp.status_code, retry_after, attempt, _MAX_RETRIES,
                            )
                            await asyncio.sleep(retry_after)
                            backoff *= 2
                            continue
                    resp.raise_for_status()
                    return resp
                except httpx.HTTPStatusError:
                    raise
                except httpx.HTTPError as exc:
                    if attempt < _MAX_RETRIES:
                        logger.debug(
                            "ecosyste.ms request error: %s, retrying in %.1fs (attempt %d/%d)",
                            exc, backoff, attempt, _MAX_RETRIES,
                        )
                        await asyncio.sleep(backoff)
                        backoff *= 2
                        continue
                    raise

        # Should not reach here, but satisfy the type checker.
        msg = f"Failed after {_MAX_RETRIES} retries"
        raise httpx.HTTPError(msg)

    @staticmethod
    def _response_to_package(data: dict[str, Any]) -> PackageInfo:
        """Convert a raw ecosyste.ms JSON response to a PackageInfo model."""
        return PackageInfo(
            name=data.get("name", ""),
            ecosystem=data.get("ecosystem", ""),
            description=data.get("description", ""),
            keywords=data.get("keywords") or [],
            homepage=data.get("homepage") or "",
            repository_url=data.get("repository_url") or "",
            latest_version=(data.get("latest_release_number") or data.get("latest_version") or ""),
        )

    # -- public API ---------------------------------------------------------

    async def get_package(self, ecosystem: str, name: str) -> PackageInfo | None:
        """Look up a single package by ecosystem and name.

        GET /packages/lookup?ecosystem={eco}&name={name}

        Returns None if the package is not found (404).
        """
        try:
            resp = await self._request(
                "GET",
                "/packages/lookup",
                params={"ecosystem": ecosystem, "name": name},
            )
            return self._response_to_package(resp.json())
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return None
            raise

    async def bulk_lookup(self, purls: list[str]) -> list[PackageInfo]:
        """Look up multiple packages by PURL via the bulk endpoint.

        POST /packages/bulk_lookup

        PURLs are sent in batches of 100 to stay within API limits.
        """
        results: list[PackageInfo] = []

        for start in range(0, len(purls), _BATCH_SIZE):
            batch = purls[start : start + _BATCH_SIZE]
            try:
                resp = await self._request(
                    "POST",
                    "/packages/bulk_lookup",
                    json=batch,
                )
                data = resp.json()
                # The bulk endpoint returns a list of package objects
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and item.get("name"):
                            results.append(self._response_to_package(item))
                elif isinstance(data, dict):
                    # Some API versions return {purl: package_data, ...}
                    for _purl, item in data.items():
                        if isinstance(item, dict) and item.get("name"):
                            results.append(self._response_to_package(item))
            except httpx.HTTPError as exc:
                logger.warning("Bulk lookup failed for batch starting at %d: %s", start, exc)
                continue

        return results
