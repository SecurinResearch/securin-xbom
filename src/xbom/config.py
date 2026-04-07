"""Configuration loading from .xbom.yaml and environment variables."""

from __future__ import annotations

import os
from pathlib import Path

from xbom.models import SbomTool


# Environment variable mappings
ENV_VARS = {
    "XBOM_GITHUB_TOKEN": "GitHub auth token",
    "XBOM_GITLAB_TOKEN": "GitLab auth token",
    "XBOM_BITBUCKET_TOKEN": "Bitbucket auth token (app password)",
    "XBOM_ANTHROPIC_API_KEY": "Claude API key for --enrich",
    "XBOM_OUTPUT_DIR": "Default output directory",
    "XBOM_SEMGREP_PATH": "Custom Semgrep binary path",
    "XBOM_TRIVY_PATH": "Custom Trivy binary path",
    "XBOM_CDXGEN_PATH": "Custom cdxgen binary path",
}

# Default tool paths (resolved from PATH or env vars)
DEFAULT_TOOLS = {
    "cdxgen": os.environ.get("XBOM_CDXGEN_PATH", "cdxgen"),
    "trivy": os.environ.get("XBOM_TRIVY_PATH", "trivy"),
    "semgrep": os.environ.get("XBOM_SEMGREP_PATH", "semgrep"),
    "gitleaks": "gitleaks",
    "testssl": "testssl.sh",
    "git": "git",
}


def get_tool_path(tool_name: str) -> str:
    """Get the configured path for an external tool."""
    return DEFAULT_TOOLS.get(tool_name, tool_name)


def get_token_for_provider(provider: str, explicit_token: str | None = None) -> str | None:
    """Resolve auth token for a git provider, checking explicit flag then env vars."""
    if explicit_token:
        return explicit_token

    env_map = {
        "github": "XBOM_GITHUB_TOKEN",
        "gitlab": "XBOM_GITLAB_TOKEN",
        "bitbucket": "XBOM_BITBUCKET_TOKEN",
    }
    env_var = env_map.get(provider)
    if env_var:
        return os.environ.get(env_var)
    return None


def get_default_output_dir() -> Path:
    """Get default output directory from env or fallback."""
    return Path(os.environ.get("XBOM_OUTPUT_DIR", "./xbom-output"))


def get_default_sbom_tool() -> SbomTool:
    """Get default SBOM tool."""
    return SbomTool.CDXGEN
