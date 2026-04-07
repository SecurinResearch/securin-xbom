"""Tests for AI-BOM module components."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest


class TestAICatalog:
    """Tests for the static AI package catalog."""

    def test_lookup_known_python_package(self):
        from xbom.modules.aibom.catalog import lookup

        result = lookup("pypi", "openai")
        assert result is not None
        assert result["category"] == "llm-provider"

    def test_lookup_known_npm_package(self):
        from xbom.modules.aibom.catalog import lookup

        result = lookup("npm", "openai")
        assert result is not None

    def test_lookup_unknown_package(self):
        from xbom.modules.aibom.catalog import lookup

        result = lookup("pypi", "requests")
        assert result is None

    def test_lookup_case_insensitive(self):
        from xbom.modules.aibom.catalog import lookup

        result = lookup("pypi", "OpenAI")
        assert result is not None

    def test_lookup_by_purl(self):
        from xbom.modules.aibom.catalog import lookup_by_purl

        result = lookup_by_purl("pkg:pypi/langchain@0.1.0")
        assert result is not None
        assert result["category"] == "agent-framework"

    def test_lookup_by_purl_unknown(self):
        from xbom.modules.aibom.catalog import lookup_by_purl

        result = lookup_by_purl("pkg:pypi/flask@3.0")
        assert result is None

    def test_catalog_has_minimum_entries(self):
        from xbom.modules.aibom.catalog import _get_catalog

        catalog = _get_catalog()
        assert len(catalog) >= 100, f"Catalog has only {len(catalog)} entries"

    def test_catalog_covers_multiple_ecosystems(self):
        from xbom.modules.aibom.catalog import _get_catalog

        catalog = _get_catalog()
        ecosystems = {key[0] for key in catalog}
        assert "pypi" in ecosystems
        assert "npm" in ecosystems

    def test_catalog_covers_new_categories(self):
        from xbom.modules.aibom.catalog import lookup

        assert lookup("pypi", "neo4j") is not None  # graph-db
        assert lookup("pypi", "unstructured") is not None  # rag-component
        assert lookup("pypi", "ragas") is not None  # evaluation
        assert lookup("pypi", "mcp") is not None  # mcp
        assert lookup("pypi", "tavily-python") is not None  # agent-tool
        assert lookup("pypi", "instructor") is not None  # prompt-engineering


class TestDeprecatedModels:
    """Tests for deprecated model detection."""

    def test_deprecated_openai_models(self):
        from xbom.modules.aibom.catalog import is_deprecated_model

        assert is_deprecated_model("gpt-3.5-turbo-0301")
        assert is_deprecated_model("text-davinci-003")
        assert is_deprecated_model("text-embedding-ada-002")

    def test_deprecated_anthropic_models(self):
        from xbom.modules.aibom.catalog import is_deprecated_model

        assert is_deprecated_model("claude-instant-1")
        assert is_deprecated_model("claude-2.0")

    def test_current_models_not_deprecated(self):
        from xbom.modules.aibom.catalog import is_deprecated_model

        assert not is_deprecated_model("gpt-4o")
        assert not is_deprecated_model("claude-sonnet-4-20250514")
        assert not is_deprecated_model("gemini-2.5-flash")


class TestPatternScanner:
    """Tests for the regex pattern scanner."""

    def test_import_scanner_python(self):
        from xbom.modules.aibom.patterns import ImportScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            py_file = Path(tmpdir) / "app.py"
            py_file.write_text("import openai\nfrom langchain import ChatOpenAI\n")

            scanner = ImportScanner()
            findings = scanner.scan(Path(tmpdir))

            assert len(findings) >= 1
            names = {f.name for f in findings}
            assert "openai" in names

    def test_model_reference_scanner(self):
        from xbom.modules.aibom.patterns import ModelReferenceScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            py_file = Path(tmpdir) / "config.py"
            py_file.write_text('MODEL = "gpt-4o"\nBACKUP = "claude-3-sonnet"\n')

            scanner = ModelReferenceScanner()
            findings = scanner.scan(Path(tmpdir))

            assert len(findings) >= 1

    def test_api_key_scanner(self):
        from xbom.modules.aibom.patterns import APIKeyScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            py_file = Path(tmpdir) / "config.py"
            py_file.write_text('key = os.environ.get("OPENAI_API_KEY")\n')

            scanner = APIKeyScanner()
            findings = scanner.scan(Path(tmpdir))

            assert len(findings) >= 1

    def test_model_file_scanner(self):
        from xbom.modules.aibom.patterns import ModelFileScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "model.onnx").touch()
            (Path(tmpdir) / "weights.safetensors").touch()

            scanner = ModelFileScanner()
            findings = scanner.scan(Path(tmpdir))

            assert len(findings) == 2

    def test_config_file_scanner(self):
        from xbom.modules.aibom.patterns import ConfigFileScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            mcp_config = Path(tmpdir) / "mcp.json"
            mcp_config.write_text(json.dumps({"mcpServers": {"filesystem": {}}}))

            scanner = ConfigFileScanner()
            findings = scanner.scan(Path(tmpdir))

            assert len(findings) >= 1

    def test_docker_scanner(self):
        from xbom.modules.aibom.patterns import DockerScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            dc = Path(tmpdir) / "docker-compose.yml"
            dc.write_text("services:\n  llm:\n    image: ollama/ollama\n  db:\n    image: chromadb/chroma\n")

            scanner = DockerScanner()
            findings = scanner.scan(Path(tmpdir))

            names = {f.name for f in findings}
            assert "ollama" in names
            assert "chromadb" in names

    def test_network_endpoint_scanner(self):
        from xbom.modules.aibom.patterns import NetworkEndpointScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = Path(tmpdir) / "config.yaml"
            cfg.write_text("openai_url: https://api.openai.com/v1/chat\n")

            scanner = NetworkEndpointScanner()
            findings = scanner.scan(Path(tmpdir))

            assert len(findings) >= 1
            assert any(f.name == "openai" for f in findings)

    def test_github_actions_scanner(self):
        from xbom.modules.aibom.patterns import GitHubActionsScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            wf_dir = Path(tmpdir) / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            wf = wf_dir / "ci.yml"
            wf.write_text("env:\n  OPENAI_API_KEY: ${{ secrets.OPENAI_KEY }}\n")

            scanner = GitHubActionsScanner()
            findings = scanner.scan(Path(tmpdir))

            assert len(findings) >= 1

    def test_scan_all(self):
        from xbom.modules.aibom.patterns import scan_all

        with tempfile.TemporaryDirectory() as tmpdir:
            py_file = Path(tmpdir) / "main.py"
            py_file.write_text('import openai\nmodel = "gpt-4o"\n')

            findings = scan_all(Path(tmpdir))
            assert len(findings) >= 1

    def test_skips_excluded_dirs(self):
        from xbom.modules.aibom.patterns import ImportScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            nm_dir = Path(tmpdir) / "node_modules" / "some-pkg"
            nm_dir.mkdir(parents=True)
            (nm_dir / "index.js").write_text('const openai = require("openai");')

            scanner = ImportScanner()
            findings = scanner.scan(Path(tmpdir))
            assert len(findings) == 0


class TestRiskScoring:
    """Tests for risk scoring engine."""

    def test_score_critical(self):
        from xbom.modules.aibom.risk import Severity, score_component

        result = score_component(["hardcoded_api_key", "shadow_ai"])
        assert result.score >= 50
        assert result.severity in (Severity.HIGH, Severity.CRITICAL)

    def test_score_medium(self):
        from xbom.modules.aibom.risk import Severity, score_component

        result = score_component(["deprecated_model", "no_rate_limit"])
        assert result.severity in (Severity.LOW, Severity.MEDIUM)

    def test_score_none(self):
        from xbom.modules.aibom.risk import Severity, score_component

        result = score_component([])
        assert result.score == 0
        assert result.severity == Severity.INFO

    def test_score_capped_at_100(self):
        from xbom.modules.aibom.risk import score_component

        result = score_component(["hardcoded_api_key", "hardcoded_credentials", "shadow_ai", "mcp_unknown_server"])
        assert result.score <= 100

    def test_score_bom_components(self):
        from xbom.modules.aibom.risk import score_bom_components

        bom = {
            "components": [
                {
                    "name": "leaked-key",
                    "properties": [
                        {"name": "xbom:ai:scanner", "value": "api-key-scanner"},
                        {"name": "xbom:ai:category", "value": "api-key-reference"},
                    ],
                },
                {
                    "name": "safe-lib",
                    "properties": [
                        {"name": "xbom:ai:scanner", "value": "catalog"},
                        {"name": "xbom:ai:category", "value": "llm-provider"},
                    ],
                },
            ]
        }
        score_bom_components(bom)

        # The api-key finding should have risk props
        leaked = bom["components"][0]
        prop_names = {p["name"] for p in leaked["properties"]}
        assert "xbom:ai:risk_score" in prop_names
        assert "xbom:ai:risk_severity" in prop_names


class TestEcosystemsClient:
    """Tests for ecosyste.ms keyword matching (no network calls)."""

    def test_is_ai_related_true(self):
        from xbom.modules.aibom.ecosystems_client import is_ai_related

        assert is_ai_related(["machine-learning", "data", "python"])
        assert is_ai_related(["llm", "openai"])
        assert is_ai_related(["deep-learning", "neural-network"])

    def test_is_ai_related_false(self):
        from xbom.modules.aibom.ecosystems_client import is_ai_related

        assert not is_ai_related(["web", "http", "server"])
        assert not is_ai_related(["database", "sql", "orm"])
        assert not is_ai_related([])


class TestAgentConfig:
    """Tests for agent configuration loading."""

    def test_config_file_exists(self):
        config_path = Path(__file__).parent.parent / "src" / "xbom" / "modules" / "aibom" / "agent_config.yaml"
        assert config_path.exists()

    def test_config_has_required_keys(self):
        import yaml

        config_path = Path(__file__).parent.parent / "src" / "xbom" / "modules" / "aibom" / "agent_config.yaml"
        with open(config_path) as f:
            config = yaml.safe_load(f)

        assert "agent" in config
        assert "system_prompt" in config["agent"]
        assert "single_classification_prompt" in config["agent"]
        assert "batch_classification_prompt" in config["agent"]
        assert "model" in config
        assert "providers" in config["model"]

    def test_config_has_all_providers(self):
        import yaml

        config_path = Path(__file__).parent.parent / "src" / "xbom" / "modules" / "aibom" / "agent_config.yaml"
        with open(config_path) as f:
            config = yaml.safe_load(f)

        providers = config["model"]["providers"]
        expected = ["openai", "openai_like", "anthropic", "gemini", "litellm_proxy", "bedrock", "azure_ai_foundry", "vertex_ai"]
        for p in expected:
            assert p in providers, f"Missing provider: {p}"


class TestCodeGraphPrompts:
    """Tests for CodeGraph prompts configuration."""

    def test_codegraph_prompts_file_exists(self):
        config_path = Path(__file__).parent.parent / "src" / "xbom" / "modules" / "aibom" / "codegraph_prompts.yaml"
        assert config_path.exists()

    def test_codegraph_prompts_has_required_keys(self):
        import yaml

        config_path = Path(__file__).parent.parent / "src" / "xbom" / "modules" / "aibom" / "codegraph_prompts.yaml"
        with open(config_path) as f:
            config = yaml.safe_load(f)

        assert "system_prompt" in config
        assert "discovery_prompt" in config
        # System prompt should contain graph schema
        assert "EXTENDS" in config["system_prompt"]
        assert "CALLS" in config["system_prompt"]
        assert "BaseTool" in config["system_prompt"]
        # Should contain output schema
        assert "components" in config["system_prompt"]
        assert "relationships" in config["system_prompt"]
        assert "architecture" in config["system_prompt"]

    def test_codegraph_prompts_has_cypher_queries(self):
        import yaml

        config_path = Path(__file__).parent.parent / "src" / "xbom" / "modules" / "aibom" / "codegraph_prompts.yaml"
        with open(config_path) as f:
            config = yaml.safe_load(f)

        prompt = config["system_prompt"]
        assert "MATCH" in prompt  # Has Cypher query patterns
        assert "Reference Query Patterns" in prompt
        assert "Exploration Strategy" in prompt

    def test_discovery_prompt_has_placeholder(self):
        import yaml

        config_path = Path(__file__).parent.parent / "src" / "xbom" / "modules" / "aibom" / "codegraph_prompts.yaml"
        with open(config_path) as f:
            config = yaml.safe_load(f)

        assert "{graph_name}" in config["discovery_prompt"]


class TestCodeGraphModule:
    """Tests for CodeGraph module (no FalkorDB required)."""

    def test_falkordb_availability_check(self):
        from xbom.modules.aibom.codegraph import is_falkordb_available

        # Should not crash — returns True/False based on whether FalkorDB is running
        result = is_falkordb_available(host="localhost", port=6379)
        assert isinstance(result, bool)

    def test_parse_codegraph_response_valid(self):
        from xbom.modules.aibom.codegraph import _parse_codegraph_response

        response = json.dumps({
            "components": [
                {"name": "SearchTool", "category": "agent-tool", "base_class": "BaseTool",
                 "file_path": "tools.py", "line_start": 10, "confidence": 0.9, "evidence": "extends BaseTool"}
            ],
            "relationships": [
                {"source": "Agent", "source_category": "agent", "type": "USES_TOOL",
                 "target": "SearchTool", "target_category": "agent-tool",
                 "file_path": "agent.py", "evidence": "calls SearchTool"}
            ],
            "architecture": {"pattern": "tool-using-agent", "description": "Agent with tools",
                           "entry_points": ["main.py:run"]}
        })

        result = _parse_codegraph_response(response)
        assert len(result["components"]) == 1
        assert result["components"][0]["name"] == "SearchTool"
        assert len(result["relationships"]) == 1
        assert result["architecture"]["pattern"] == "tool-using-agent"

    def test_parse_codegraph_response_empty(self):
        from xbom.modules.aibom.codegraph import _parse_codegraph_response

        response = json.dumps({
            "components": [],
            "relationships": [],
            "architecture": {"pattern": "none", "description": "No AI found", "entry_points": []}
        })

        result = _parse_codegraph_response(response)
        assert result["components"] == []
        assert result["architecture"]["pattern"] == "none"

    def test_parse_codegraph_response_with_markdown_fences(self):
        from xbom.modules.aibom.codegraph import _parse_codegraph_response

        response = '```json\n{"components": [], "relationships": [], "architecture": {"pattern": "none"}}\n```'
        result = _parse_codegraph_response(response)
        assert result["components"] == []

    def test_parse_codegraph_response_garbage(self):
        from xbom.modules.aibom.codegraph import _parse_codegraph_response

        result = _parse_codegraph_response("this is not json at all")
        assert result["components"] == []
        assert result["architecture"]["pattern"] == "unknown"
