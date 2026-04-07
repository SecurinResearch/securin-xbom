"""Strands Agent integration for AI/ML package classification.

All prompts and model settings are loaded from agent_config.yaml.
The agent is created lazily and supports 8 model providers via a factory.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

_CONFIG_PATH = Path(__file__).parent / "agent_config.yaml"
_config: dict[str, Any] | None = None


def _load_config() -> dict[str, Any]:
    """Load and cache the agent configuration from YAML."""
    global _config
    if _config is None:
        with open(_CONFIG_PATH) as f:
            _config = yaml.safe_load(f)
    return _config


# ---------------------------------------------------------------------------
# Strands availability check
# ---------------------------------------------------------------------------


def _ensure_strands_installed() -> None:
    """Raise a clear error if strands-agents is not installed."""
    try:
        import strands  # noqa: F401
    except ImportError:
        raise ImportError(
            "Strands Agents SDK is required for --enrich but is not installed.\n"
            "Install it with: pip install 'xbom[agent]'"
        ) from None


# ---------------------------------------------------------------------------
# Model provider factory
# ---------------------------------------------------------------------------

# Environment variable names for API keys per provider (checked in order)
_ENV_KEYS: dict[str, list[str]] = {
    "openai": ["OPENAI_API_KEY"],
    "openai_like": ["OPENAI_API_KEY", "LITELLM_V_KEY", "LITELLM_API_KEY"],
    "anthropic": ["ANTHROPIC_API_KEY"],
    "gemini": ["GOOGLE_API_KEY"],
    "litellm_proxy": ["LITELLM_API_KEY", "LITELLM_V_KEY"],
    "bedrock": [],  # Uses AWS env (AWS_ACCESS_KEY_ID, etc.)
    "azure_ai_foundry": ["AZURE_API_KEY"],
    "vertex_ai": [],  # Uses Google ADC
}

_ENV_BASE_URLS: dict[str, list[str]] = {
    "openai_like": ["OPENAI_API_BASE", "LITELLM_API_BASE"],
    "litellm_proxy": ["LITELLM_API_BASE"],
    "azure_ai_foundry": ["AZURE_API_BASE"],
}


def _build_model(provider_name: str, provider_cfg: dict[str, Any]) -> Any:
    """Instantiate a Strands model object for the given provider.

    Returns a model instance compatible with ``strands.Agent(model=...)``.
    """
    model_id = provider_cfg.get("model_id")
    params = provider_cfg.get("params", {})
    max_tokens = provider_cfg.get("max_tokens")

    # Resolve API key from environment (try multiple env var names)
    api_key = ""
    for env_name in _ENV_KEYS.get(provider_name, []):
        api_key = os.environ.get(env_name, "")
        if api_key:
            break

    # Resolve base URL from config then environment
    base_url = provider_cfg.get("base_url")
    if not base_url:
        for env_name in _ENV_BASE_URLS.get(provider_name, []):
            base_url = os.environ.get(env_name)
            if base_url:
                break

    # Allow LITELLM_MODEL env var to override model_id
    env_model = os.environ.get("LITELLM_MODEL")
    if env_model and provider_name in ("openai_like", "litellm_proxy"):
        model_id = env_model

    if provider_name == "openai":
        from strands.models.openai import OpenAIModel

        return OpenAIModel(
            client_args={"api_key": api_key},
            model_id=model_id,
            params=params,
        )

    if provider_name == "openai_like":
        from strands.models.openai import OpenAIModel

        client_args: dict[str, Any] = {"api_key": api_key}
        if base_url:
            client_args["base_url"] = base_url
        return OpenAIModel(
            client_args=client_args,
            model_id=model_id,
            params=params,
        )

    if provider_name == "anthropic":
        from strands.models.anthropic import AnthropicModel

        kwargs: dict[str, Any] = {
            "client_args": {"api_key": api_key},
            "model_id": model_id,
            "params": params,
        }
        if max_tokens:
            kwargs["max_tokens"] = max_tokens
        return AnthropicModel(**kwargs)

    if provider_name == "gemini":
        from strands.models.gemini import GeminiModel

        return GeminiModel(
            client_args={"api_key": api_key},
            model_id=model_id,
            params=params,
        )

    if provider_name == "litellm_proxy":
        from strands.models.litellm import LiteLLMModel

        return LiteLLMModel(
            client_args={
                "api_key": api_key,
                "api_base": base_url,
                "use_litellm_proxy": True,
            },
            model_id=model_id,
            params=params,
        )

    if provider_name == "bedrock":
        from strands.models.bedrock import BedrockModel

        return BedrockModel(model_id=model_id)

    if provider_name == "azure_ai_foundry":
        from strands.models.litellm import LiteLLMModel

        azure_model_id = f"azure/{model_id}" if model_id and not model_id.startswith("azure/") else model_id
        return LiteLLMModel(
            client_args={
                "api_key": api_key,
                "api_base": base_url,
            },
            model_id=azure_model_id,
            params=params,
        )

    if provider_name == "vertex_ai":
        from strands.models.litellm import LiteLLMModel

        vertex_model_id = f"vertex_ai/{model_id}" if model_id and not model_id.startswith("vertex_ai/") else model_id
        return LiteLLMModel(
            model_id=vertex_model_id,
            params=params,
        )

    raise ValueError(f"Unknown enrichment provider: {provider_name!r}")


# ---------------------------------------------------------------------------
# Tool for the agent: ecosyste.ms package lookup
# ---------------------------------------------------------------------------


def _make_lookup_tool() -> Any:
    """Create the @tool-decorated lookup_package function.

    Deferred to avoid import errors when strands is not installed.
    """
    from strands import tool

    from xbom.modules.aibom.ecosystems_client import EcosystemsClient

    @tool
    def lookup_package(ecosystem: str, name: str) -> str:
        """Look up a software package on ecosyste.ms to retrieve its metadata.

        Args:
            ecosystem: The package ecosystem (e.g. pypi, npm, maven).
            name: The package name to look up.
        """
        client = EcosystemsClient()
        try:
            result = asyncio.run(client.get_package(ecosystem, name))
        except Exception as exc:
            return json.dumps({"error": str(exc)})

        if result is None:
            return json.dumps({"error": f"Package {name} not found in {ecosystem}"})

        return result.model_dump_json()

    return lookup_package


# ---------------------------------------------------------------------------
# Agent lifecycle
# ---------------------------------------------------------------------------

_agent_instance: Any = None
_agent_provider: str | None = None


def get_agent(provider_override: str | None = None) -> Any:
    """Lazily create and return the Strands classification agent.

    The agent is cached so subsequent calls reuse the same instance,
    unless the provider changes.
    """
    global _agent_instance, _agent_provider

    _ensure_strands_installed()
    from strands import Agent

    cfg = _load_config()
    agent_cfg = cfg.get("agent", {})
    model_cfg = cfg.get("model", {})

    # Determine which provider to use
    provider_name = (
        provider_override
        or os.environ.get("XBOM_ENRICHMENT_PROVIDER")
        or model_cfg.get("default_provider", "anthropic")
    )

    # Return cached agent if same provider
    if _agent_instance is not None and _agent_provider == provider_name:
        return _agent_instance

    # Build the model
    providers = model_cfg.get("providers", {})
    if provider_name not in providers:
        raise ValueError(
            f"Unknown provider {provider_name!r}. "
            f"Available: {', '.join(providers.keys())}"
        )
    model = _build_model(provider_name, providers[provider_name])

    # Build the tool
    lookup_tool = _make_lookup_tool()

    # Create the agent
    system_prompt = agent_cfg.get("system_prompt", "")
    _agent_instance = Agent(
        model=model,
        tools=[lookup_tool],
        system_prompt=system_prompt,
        callback_handler=None,  # Suppress streaming output
    )
    _agent_provider = provider_name

    logger.info("Strands Agent created with provider=%s", provider_name)
    return _agent_instance


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def classify_packages(
    packages: list[dict[str, Any]],
    provider_override: str | None = None,
) -> list[dict[str, Any]]:
    """Classify packages as AI/ML related using the Strands Agent.

    Each package should include ecosyste.ms metadata:
      {package_name, purl, version, ecosystem, description, keywords, repository_url}

    The agent receives the FULL metadata and makes the classification decision.
    This is NOT a hardcoded keyword match — the agent uses reasoning over the
    description, keywords, and name to determine if a package is AI/ML related
    and what specific category it falls into.

    Args:
        packages: List of dicts with ecosyste.ms-enriched metadata.
        provider_override: Override the default model provider.

    Returns:
        List of classification result dicts with keys: package_name, purl,
        is_ai_ml, confidence, category, reasoning.
    """
    _ensure_strands_installed()

    if not packages:
        return []

    cfg = _load_config()
    agent_cfg = cfg.get("agent", {})
    model_cfg = cfg.get("model", {})
    batch_size = model_cfg.get("batch_size", 20)
    agent = get_agent(provider_override)

    all_results: list[dict[str, Any]] = []

    total_batches = (len(packages) + batch_size - 1) // batch_size
    logger.info("  Processing %d packages in %d batch(es) of %d", len(packages), total_batches, batch_size)

    # Process in batches to avoid token limits
    for i in range(0, len(packages), batch_size):
        batch = packages[i : i + batch_size]
        batch_num = i // batch_size + 1
        logger.info("  Batch %d/%d: %d packages", batch_num, total_batches, len(batch))

        if len(batch) == 1:
            pkg = batch[0]
            prompt_template = agent_cfg.get("single_classification_prompt", "")
            prompt = prompt_template.format(
                package_name=pkg.get("package_name", ""),
                purl=pkg.get("purl", ""),
                ecosystem=pkg.get("ecosystem", ""),
                description=pkg.get("description", ""),
                keywords=", ".join(pkg.get("keywords", [])),
                repository_url=pkg.get("repository_url", ""),
            )
        else:
            prompt_template = agent_cfg.get("batch_classification_prompt", "")
            prompt = prompt_template.format(
                packages_json=json.dumps(batch, indent=2, default=str),
            )

        try:
            logger.info("  Sending to LLM (prompt length: %d chars)...", len(prompt))
            result = agent(prompt)
            response_text = str(result)
            logger.info("  LLM response: %d chars", len(response_text))
            batch_results = _parse_classification_response(response_text, batch)
            all_results.extend(batch_results)
        except Exception as exc:
            logger.warning("Agent classification failed for batch %d: %s", i // batch_size, exc)
            all_results.extend(_fallback_results(batch, f"Agent error: {exc}"))

    return all_results


def _parse_classification_response(
    response_text: str,
    packages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Parse the agent's JSON response into classification results.

    Handles both single-object and array responses, with fallback on
    parse failure.
    """
    # Strip markdown code fences if present
    text = response_text.strip()
    if text.startswith("```"):
        # Remove opening fence (```json or ```)
        first_newline = text.index("\n")
        text = text[first_newline + 1 :]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        # Try to extract JSON from the response
        start = text.find("[")
        end = text.rfind("]")
        if start != -1 and end != -1:
            try:
                parsed = json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass
            else:
                return _normalize_results(parsed, packages)

        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1:
            try:
                parsed = json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass
            else:
                return _normalize_results([parsed], packages)

        logger.warning("Could not parse agent response as JSON: %.200s", text)
        return _fallback_results(packages, "Unparseable agent response")

    return _normalize_results(parsed if isinstance(parsed, list) else [parsed], packages)


def _normalize_results(
    parsed: list[dict[str, Any]],
    packages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Ensure each result dict has all required keys."""
    results = []
    for item in parsed:
        results.append({
            "package_name": item.get("package_name", ""),
            "purl": item.get("purl", ""),
            "ecosystem": item.get("ecosystem", ""),
            "is_ai_ml": bool(item.get("is_ai_ml", False)),
            "confidence": float(item.get("confidence", 0.0)),
            "category": item.get("category", "none"),
            "reasoning": item.get("reasoning", ""),
        })
    return results


def _fallback_results(
    packages: list[dict[str, Any]],
    reason: str,
) -> list[dict[str, Any]]:
    """Return default non-AI classifications when parsing fails."""
    return [
        {
            "package_name": pkg.get("package_name", ""),
            "purl": pkg.get("purl", ""),
            "ecosystem": pkg.get("ecosystem", ""),
            "is_ai_ml": False,
            "confidence": 0.0,
            "category": "none",
            "reasoning": reason,
        }
        for pkg in packages
    ]
