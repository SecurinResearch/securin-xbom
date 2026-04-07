"""CodeGraph analysis — indexes project with FalkorDB code-graph,
then uses a Strands Agent with the official FalkorDB MCP Server
(@falkordb/mcpserver) to autonomously discover AI components via graph exploration."""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
from pathlib import Path
from typing import Any

import yaml

from xbom.models import ScanConfig

logger = logging.getLogger(__name__)

_PROMPTS_PATH = Path(__file__).parent / "codegraph_prompts.yaml"
_prompts: dict[str, Any] | None = None


def _load_prompts() -> dict[str, Any]:
    global _prompts
    if _prompts is None:
        with open(_PROMPTS_PATH) as f:
            _prompts = yaml.safe_load(f)
    return _prompts


# ── FalkorDB availability ─────────────────────────────────────────────


def is_falkordb_available(
    host: str | None = None,
    port: int | None = None,
) -> bool:
    """Check if FalkorDB is reachable."""
    host = host or os.environ.get("FALKORDB_HOST", "localhost")
    port = port or int(os.environ.get("FALKORDB_PORT", "6379"))
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except (OSError, ConnectionRefusedError):
        return False


# ── Project indexing ───────────────────────────────────────────────────


def index_project(project_path: Path) -> str:
    """Index a project with FalkorDB code-graph.

    Returns the graph name.
    """
    try:
        from api.analyzers.source_analyzer import SourceAnalyzer
        from api.graph import Graph
    except ImportError:
        raise ImportError(
            "falkordb-code-graph is required for CodeGraph analysis.\n"
            "Install with: pip install falkordb-code-graph"
        ) from None

    graph_name = f"xbom_{project_path.name}"
    graph = Graph(graph_name)
    analyzer = SourceAnalyzer()

    logger.info("Indexing project %s into graph %s...", project_path, graph_name)
    analyzer.analyze_local_folder(
        str(project_path),
        graph,
        ignore=[".git", "node_modules", "__pycache__", ".venv", "venv", "build", "dist", "tests", ".tox"],
    )

    # Log stats
    try:
        from falkordb import FalkorDB
        host = os.environ.get("FALKORDB_HOST", "localhost")
        port = int(os.environ.get("FALKORDB_PORT", "6379"))
        db = FalkorDB(host=host, port=port)
        g = db.select_graph(graph_name)
        result = g.query("MATCH (n) RETURN count(n) AS c")
        node_count = result.result_set[0][0] if result.result_set else 0
        result = g.query("MATCH ()-[e]->() RETURN count(e) AS c")
        edge_count = result.result_set[0][0] if result.result_set else 0
        logger.info("Graph %s: %d nodes, %d edges", graph_name, node_count, edge_count)
    except Exception as e:
        logger.debug("Could not get graph stats: %s", e)

    return graph_name


# ── Agent with FalkorDB MCP Server ────────────────────────────────────


def analyze_with_codegraph(project_path: Path, config: ScanConfig) -> dict[str, Any]:
    """Full CodeGraph analysis:
    1. Index project → FalkorDB graph
    2. Connect Strands Agent to official FalkorDB MCP Server (@falkordb/mcpserver)
    3. Agent runs Cypher discovery queries via MCP tools
    4. Parse structured JSON output
    5. Cleanup graph
    """
    graph_name = index_project(project_path)

    try:
        result = _run_codegraph_agent(graph_name, config)
    finally:
        try:
            cleanup(graph_name)
        except Exception as e:
            logger.debug("Graph cleanup failed: %s", e)

    return result


def _run_codegraph_agent(graph_name: str, config: ScanConfig) -> dict[str, Any]:
    """Create Strands Agent with FalkorDB MCP Server tools and run discovery."""
    try:
        from strands import Agent
        from strands.tools.mcp import MCPClient
    except ImportError:
        raise ImportError(
            "Strands Agents SDK is required for CodeGraph analysis.\n"
            "Install with: pip install 'xbom[agent]'"
        ) from None

    try:
        from mcp import stdio_client, StdioServerParameters
    except ImportError:
        raise ImportError(
            "mcp package is required for MCP integration.\n"
            "Install with: pip install mcp"
        ) from None

    prompts = _load_prompts()

    # Build model from existing provider factory
    from xbom.modules.aibom.agent import _build_model, _load_config as _load_agent_config

    agent_cfg = _load_agent_config()
    model_cfg = agent_cfg.get("model", {})
    provider_name = (
        os.environ.get("XBOM_ENRICHMENT_PROVIDER")
        or model_cfg.get("default_provider", "anthropic")
    )
    providers = model_cfg.get("providers", {})
    logger.info("  Building model: provider=%s", provider_name)
    model = _build_model(provider_name, providers.get(provider_name, {}))

    # Official FalkorDB MCP Server: @falkordb/mcpserver via npx (stdio transport)
    falkordb_host = os.environ.get("FALKORDB_HOST", "localhost")
    falkordb_port = os.environ.get("FALKORDB_PORT", "6379")

    # Find npx for MCP server
    npx_path = _find_npx()
    logger.info("  npx path: %s", npx_path)
    if not npx_path:
        raise RuntimeError(
            "npx not found. Install Node.js to use CodeGraph analysis.\n"
            "The FalkorDB MCP Server (@falkordb/mcpserver) requires npx."
        )

    mcp_client = MCPClient(
        lambda: stdio_client(StdioServerParameters(
            command=npx_path,
            args=["-y", "@falkordb/mcpserver@latest"],
            env={
                **os.environ,
                "FALKORDB_HOST": falkordb_host,
                "FALKORDB_PORT": falkordb_port,
            },
        ))
    )

    system_prompt = prompts.get("system_prompt", "")

    logger.info("  Starting FalkorDB MCP Server (@falkordb/mcpserver) via npx...")
    logger.info("  FalkorDB connection: %s:%s", falkordb_host, falkordb_port)
    logger.info("  Running agent on graph: %s", graph_name)

    # Pass mcp_client directly to Agent — Strands manages the lifecycle
    agent = Agent(
        model=model,
        tools=[mcp_client],
        system_prompt=system_prompt,
        callback_handler=None,  # Suppress streaming output
    )

    discovery_prompt = prompts.get("discovery_prompt", "").format(graph_name=graph_name)
    logger.info("  Agent exploring graph autonomously...")

    timeout = int(os.environ.get("XBOM_CODEGRAPH_TIMEOUT", "120"))
    watchdog = threading.Thread(target=_timeout_watchdog, args=(agent, timeout), daemon=True)
    watchdog.start()

    response = agent(discovery_prompt)
    response_text = str(response)
    logger.info("  Agent response length: %d chars", len(response_text))

    return _parse_codegraph_response(response_text)


def _timeout_watchdog(agent: Any, timeout: int) -> None:
    """Cancel the agent after a timeout period to prevent runaway exploration."""
    import time

    time.sleep(timeout)
    logger.warning("CodeGraph agent timed out after %ds, cancelling...", timeout)
    try:
        agent.cancel()
    except Exception as e:
        logger.debug("Failed to cancel agent: %s", e)


def _find_npx() -> str | None:
    """Find the npx binary."""
    import shutil
    npx = shutil.which("npx")
    if npx:
        return npx
    # Common locations
    for path in ["/opt/homebrew/bin/npx", "/usr/local/bin/npx"]:
        if os.path.isfile(path):
            return path
    return None


# ── Response parsing ───────────────────────────────────────────────────


def _parse_codegraph_response(response_text: str) -> dict[str, Any]:
    """Parse the agent's structured JSON response."""
    text = response_text.strip()

    # Strip markdown fences
    if text.startswith("```"):
        first_nl = text.index("\n")
        text = text[first_nl + 1:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()

    try:
        result = json.loads(text)
        return _validate_result(result)
    except json.JSONDecodeError:
        pass

    # Try extracting JSON object
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1:
        try:
            result = json.loads(text[start:end + 1])
            return _validate_result(result)
        except json.JSONDecodeError:
            pass

    logger.warning("Could not parse CodeGraph agent response as JSON")
    return _empty_result("Agent response unparseable")


def _validate_result(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "components": data.get("components", []),
        "relationships": data.get("relationships", []),
        "architecture": data.get("architecture", {"pattern": "unknown", "description": "", "entry_points": []}),
    }


def _empty_result(description: str = "") -> dict[str, Any]:
    return {
        "components": [],
        "relationships": [],
        "architecture": {"pattern": "unknown", "description": description, "entry_points": []},
    }


# ── Cleanup ────────────────────────────────────────────────────────────


def cleanup(graph_name: str) -> None:
    """Delete the graph from FalkorDB."""
    try:
        from falkordb import FalkorDB
        host = os.environ.get("FALKORDB_HOST", "localhost")
        port = int(os.environ.get("FALKORDB_PORT", "6379"))
        db = FalkorDB(host=host, port=port)
        g = db.select_graph(graph_name)
        g.delete()
        logger.info("Cleaned up graph %s", graph_name)
    except Exception as e:
        logger.debug("Failed to cleanup graph %s: %s", graph_name, e)
