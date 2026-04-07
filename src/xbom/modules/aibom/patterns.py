"""Regex-based AI/ML component scanner.

Scans source files for patterns indicating AI/ML usage -- import statements,
model name references, API key environment variables, config files, and model
file artifacts.  All scanners use regex (no AST parsing) for speed and
cross-language support.

All pattern data is loaded from rules/*.yaml files.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# YAML rules loading (cached at module level)
# ---------------------------------------------------------------------------

_RULES_DIR = Path(__file__).parent / "rules"
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
class Finding:
    """A single AI/ML pattern detection result."""

    scanner_name: str
    category: str
    name: str
    description: str
    file_path: str
    line_number: int
    confidence: float  # 0.0 .. 1.0


# ---------------------------------------------------------------------------
# Helpers (file iteration)
# ---------------------------------------------------------------------------

_skip_dirs: set[str] | None = None
_source_extensions: set[str] | None = None
_config_names: set[str] | None = None


def _get_skip_dirs() -> set[str]:
    global _skip_dirs
    if _skip_dirs is None:
        _skip_dirs = set(_load_rules("files")["skip_dirs"])
    return _skip_dirs


def _get_source_extensions() -> set[str]:
    global _source_extensions
    if _source_extensions is None:
        _source_extensions = set(_load_rules("files")["source_extensions"])
    return _source_extensions


def _get_config_names() -> set[str]:
    global _config_names
    if _config_names is None:
        _config_names = set(_load_rules("files")["config_names"])
    return _config_names


def _iter_source_files(project_path: Path) -> Iterator[Path]:
    """Yield source code files, skipping common non-project directories."""
    exts = _get_source_extensions()
    for child in _walk_filtered(project_path):
        if child.suffix in exts:
            yield child


def _walk_filtered(project_path: Path) -> Iterator[Path]:
    """Recursively yield files, pruning skip dirs."""
    skip = _get_skip_dirs()
    for item in project_path.iterdir():
        try:
            if item.is_dir():
                if item.name in skip:
                    continue
                yield from _walk_filtered(item)
            else:
                yield item
        except PermissionError:
            continue


def _read_lines(path: Path) -> list[str]:
    """Read file lines, returning an empty list on any I/O or decode error."""
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, UnicodeDecodeError):
        return []


def _in_skip_dir(filepath: Path, root: Path) -> bool:
    """Check if filepath is inside any directory we should skip."""
    skip = _get_skip_dirs()
    try:
        rel = filepath.relative_to(root)
    except ValueError:
        return False
    return any(part in skip for part in rel.parts)


# ---------------------------------------------------------------------------
# Compiled pattern caches
# ---------------------------------------------------------------------------

_import_patterns: list[tuple[re.Pattern[str], str, str, str]] | None = None
_model_patterns: list[tuple[re.Pattern[str], str, str]] | None = None
_api_key_patterns: list[tuple[re.Pattern[str], str, str]] | None = None
_env_ai_keys_re: re.Pattern[str] | None = None


def _get_import_patterns() -> list[tuple[re.Pattern[str], str, str, str]]:
    global _import_patterns
    if _import_patterns is None:
        rules = _load_rules("imports")
        _import_patterns = []
        for lang_key in ("python", "javascript", "java", "go"):
            for entry in rules.get(lang_key, []):
                _import_patterns.append((
                    re.compile(entry[0]),
                    entry[1],  # category
                    entry[2],  # name
                    entry[3],  # description
                ))
    return _import_patterns


def _get_model_patterns() -> list[tuple[re.Pattern[str], str, str]]:
    global _model_patterns
    if _model_patterns is None:
        rules = _load_rules("models")
        _model_patterns = []
        for entry in rules["patterns"]:
            if isinstance(entry, list):
                _model_patterns.append((re.compile(entry[0]), entry[1], entry[2]))
            else:
                # Dict form with optional flags
                flags = getattr(re, entry.get("flags", ""), 0)
                _model_patterns.append((
                    re.compile(entry["pattern"], flags),
                    entry["model_id"],
                    entry["description"],
                ))
    return _model_patterns


def _get_api_key_patterns() -> list[tuple[re.Pattern[str], str, str]]:
    global _api_key_patterns
    if _api_key_patterns is None:
        rules = _load_rules("api_keys")
        _api_key_patterns = [
            (re.compile(entry[0]), entry[1], entry[2])
            for entry in rules["patterns"]
        ]
    return _api_key_patterns


def _get_env_ai_keys_re() -> re.Pattern[str]:
    global _env_ai_keys_re
    if _env_ai_keys_re is None:
        rules = _load_rules("api_keys")
        keys = rules["env_file_keys"]
        pattern = r"^(?:" + "|".join(re.escape(k) for k in keys) + r")\s*="
        _env_ai_keys_re = re.compile(pattern, re.MULTILINE)
    return _env_ai_keys_re


# ---------------------------------------------------------------------------
# 1. ImportScanner
# ---------------------------------------------------------------------------


class ImportScanner:
    """Detects AI/ML import statements across Python, JS/TS, Java, and Go."""

    name = "import-scanner"

    def scan(self, project_path: Path) -> list[Finding]:
        patterns = _get_import_patterns()
        findings: list[Finding] = []
        for source_file in _iter_source_files(project_path):
            lines = _read_lines(source_file)
            for line_num, line in enumerate(lines, start=1):
                for pattern, category, pkg_name, description in patterns:
                    if pattern.search(line):
                        findings.append(Finding(
                            scanner_name=self.name,
                            category=category,
                            name=pkg_name,
                            description=description,
                            file_path=str(source_file),
                            line_number=line_num,
                            confidence=0.95,
                        ))
        return findings


# ---------------------------------------------------------------------------
# 2. ModelReferenceScanner
# ---------------------------------------------------------------------------


class ModelReferenceScanner:
    """Finds model name strings in source files."""

    name = "model-reference-scanner"

    def scan(self, project_path: Path) -> list[Finding]:
        patterns = _get_model_patterns()
        findings: list[Finding] = []
        for source_file in _iter_source_files(project_path):
            lines = _read_lines(source_file)
            for line_num, line in enumerate(lines, start=1):
                for pattern, model_id, description in patterns:
                    if pattern.search(line):
                        findings.append(Finding(
                            scanner_name=self.name,
                            category="model-reference",
                            name=model_id,
                            description=description,
                            file_path=str(source_file),
                            line_number=line_num,
                            confidence=0.85,
                        ))
        return findings


# ---------------------------------------------------------------------------
# 3. APIKeyScanner
# ---------------------------------------------------------------------------


class APIKeyScanner:
    """Detects AI service API key / env var references in source code."""

    name = "api-key-scanner"

    def scan(self, project_path: Path) -> list[Finding]:
        patterns = _get_api_key_patterns()
        findings: list[Finding] = []
        for source_file in _iter_source_files(project_path):
            lines = _read_lines(source_file)
            for line_num, line in enumerate(lines, start=1):
                for pattern, provider, description in patterns:
                    if pattern.search(line):
                        findings.append(Finding(
                            scanner_name=self.name,
                            category="api-key-reference",
                            name=provider,
                            description=description,
                            file_path=str(source_file),
                            line_number=line_num,
                            confidence=0.80,
                        ))
        return findings


# ---------------------------------------------------------------------------
# 4. ConfigFileScanner
# ---------------------------------------------------------------------------


class ConfigFileScanner:
    """Finds AI-related configuration files (MCP configs, Docker AI services, .env keys)."""

    name = "config-file-scanner"

    def scan(self, project_path: Path) -> list[Finding]:
        config_names = _get_config_names()
        docker_rules = _load_rules("docker")
        compose_patterns = [
            (re.compile(entry[0]), entry[1], entry[2])
            for entry in docker_rules["compose_images"]
        ]
        env_keys_re = _get_env_ai_keys_re()
        findings: list[Finding] = []

        for config_file in _walk_filtered(project_path):
            if config_file.name not in config_names:
                continue

            lines = _read_lines(config_file)
            file_str = str(config_file)

            # --- MCP config files ---
            if config_file.name in ("mcp.json", ".mcp.json", "mcp-config.json"):
                findings.append(Finding(
                    scanner_name=self.name,
                    category="config",
                    name="mcp-config",
                    description=f"MCP (Model Context Protocol) configuration: {config_file.name}",
                    file_path=file_str,
                    line_number=1,
                    confidence=0.95,
                ))
                continue

            # --- Docker Compose ---
            if config_file.name in (
                "docker-compose.yml", "docker-compose.yaml",
                "compose.yml", "compose.yaml",
            ):
                for line_num, line in enumerate(lines, start=1):
                    for pattern, svc_name, description in compose_patterns:
                        if pattern.search(line):
                            findings.append(Finding(
                                scanner_name=self.name,
                                category="config",
                                name=svc_name,
                                description=description,
                                file_path=file_str,
                                line_number=line_num,
                                confidence=0.90,
                            ))
                continue

            # --- .env files ---
            if config_file.name.startswith(".env"):
                for line_num, line in enumerate(lines, start=1):
                    if env_keys_re.match(line.strip()):
                        key_name = line.strip().split("=", 1)[0]
                        findings.append(Finding(
                            scanner_name=self.name,
                            category="config",
                            name=key_name.lower(),
                            description=f"AI-related environment variable: {key_name}",
                            file_path=file_str,
                            line_number=line_num,
                            confidence=0.85,
                        ))

        return findings


# ---------------------------------------------------------------------------
# 5. ModelFileScanner
# ---------------------------------------------------------------------------


class ModelFileScanner:
    """Detects AI model files by extension (.gguf, .safetensors, .onnx, .pt, etc.)."""

    name = "model-file-scanner"

    def scan(self, project_path: Path) -> list[Finding]:
        file_rules = _load_rules("files")
        model_exts: dict[str, list[str]] = file_rules["model_file_extensions"]
        bin_pattern = re.compile(file_rules["model_bin_pattern"], re.IGNORECASE)
        findings: list[Finding] = []

        for filepath in _walk_filtered(project_path):
            ext = filepath.suffix.lower()

            # Special handling for .bin -- only flag ML-looking filenames
            if ext == ".bin":
                if bin_pattern.search(filepath.name):
                    findings.append(Finding(
                        scanner_name=self.name,
                        category="model-file",
                        name="model-binary",
                        description=f"Model binary (potential HF model weights): {filepath.name}",
                        file_path=str(filepath),
                        line_number=0,
                        confidence=0.75,
                    ))
                continue

            if ext not in model_exts:
                continue

            name_tag, description = model_exts[ext]
            findings.append(Finding(
                scanner_name=self.name,
                category="model-file",
                name=name_tag,
                description=f"{description}: {filepath.name}",
                file_path=str(filepath),
                line_number=0,
                confidence=0.90,
            ))

        return findings


# ---------------------------------------------------------------------------
# 6. DockerScanner
# ---------------------------------------------------------------------------


class DockerScanner:
    """Detect AI containers in Dockerfiles and docker-compose files."""

    name = "docker-scanner"

    def scan(self, project_path: Path) -> list[Finding]:
        docker_rules = _load_rules("docker")
        ai_images = [(re.compile(e[0], re.IGNORECASE), e[1], e[2]) for e in docker_rules["images"]]
        ai_env_patterns = docker_rules["env_patterns"]
        findings: list[Finding] = []

        docker_files = (
            list(project_path.rglob("Dockerfile*"))
            + list(project_path.rglob("*.dockerfile"))
            + list(project_path.rglob("docker-compose*.yml"))
            + list(project_path.rglob("docker-compose*.yaml"))
            + list(project_path.rglob("compose*.yml"))
            + list(project_path.rglob("compose*.yaml"))
        )
        for fp in docker_files:
            if _in_skip_dir(fp, project_path):
                continue
            try:
                content = fp.read_text(errors="ignore")
            except OSError:
                continue

            # Check FROM statements and image references
            for pattern, name, desc in ai_images:
                for m in pattern.finditer(content):
                    line_num = content[:m.start()].count("\n") + 1
                    findings.append(Finding(
                        scanner_name=self.name,
                        category="container",
                        name=name,
                        description=f"AI container image: {desc}",
                        file_path=str(fp),
                        line_number=line_num,
                        confidence=0.95,
                    ))

            # Check for GPU device mappings
            if re.search(r"nvidia|gpu|cuda|runtime:\s*nvidia", content, re.IGNORECASE):
                findings.append(Finding(
                    scanner_name=self.name,
                    category="infrastructure",
                    name="gpu-runtime",
                    description="GPU/CUDA runtime detected in Docker config",
                    file_path=str(fp),
                    line_number=0,
                    confidence=0.9,
                ))

            # Check AI env vars in compose files
            for env_pat in ai_env_patterns:
                for m in re.finditer(rf"\b{env_pat}\w*", content):
                    line_num = content[:m.start()].count("\n") + 1
                    findings.append(Finding(
                        scanner_name=self.name,
                        category="api-key-reference",
                        name=env_pat.lower().rstrip("_"),
                        description=f"AI env var in Docker config: {m.group(0)}",
                        file_path=str(fp),
                        line_number=line_num,
                        confidence=0.8,
                    ))

        return findings


# ---------------------------------------------------------------------------
# 7. NetworkEndpointScanner
# ---------------------------------------------------------------------------


class NetworkEndpointScanner:
    """Detect AI service endpoints in config and env files."""

    name = "network-scanner"

    def scan(self, project_path: Path) -> list[Finding]:
        file_rules = _load_rules("files")
        net_exts = set(file_rules["network_file_extensions"])
        endpoint_rules = _load_rules("endpoints")
        patterns = [(re.compile(e[0]), e[1], e[2]) for e in endpoint_rules["patterns"]]
        findings: list[Finding] = []

        for filepath in _walk_filtered(project_path):
            if filepath.suffix not in net_exts:
                continue
            try:
                content = filepath.read_text(errors="ignore")
            except OSError:
                continue

            for pattern, name, desc in patterns:
                for m in pattern.finditer(content):
                    line_num = content[:m.start()].count("\n") + 1
                    findings.append(Finding(
                        scanner_name=self.name,
                        category="endpoint",
                        name=name,
                        description=f"AI endpoint: {desc} ({m.group(0)})",
                        file_path=str(filepath),
                        line_number=line_num,
                        confidence=0.9,
                    ))

        return findings


# ---------------------------------------------------------------------------
# 8. JupyterScanner
# ---------------------------------------------------------------------------


class JupyterScanner:
    """Detect AI usage in Jupyter notebooks (.ipynb files)."""

    name = "jupyter-scanner"

    def scan(self, project_path: Path) -> list[Finding]:
        import json as _json

        rules = _load_rules("imports")
        ai_import_re = re.compile(rules["jupyter_pattern"], re.IGNORECASE)
        findings: list[Finding] = []

        for fp in project_path.rglob("*.ipynb"):
            if _in_skip_dir(fp, project_path):
                continue
            try:
                nb = _json.loads(fp.read_text(errors="ignore"))
            except (OSError, _json.JSONDecodeError):
                continue

            cells = nb.get("cells", [])
            for cell_idx, cell in enumerate(cells):
                if cell.get("cell_type") != "code":
                    continue
                source = "".join(cell.get("source", []))
                for m in ai_import_re.finditer(source):
                    findings.append(Finding(
                        scanner_name=self.name,
                        category="llm-provider",
                        name=m.group(0).split()[-1].split(".")[0],
                        description=f"AI import in notebook cell {cell_idx}",
                        file_path=str(fp),
                        line_number=cell_idx,
                        confidence=0.9,
                    ))

        return findings


# ---------------------------------------------------------------------------
# 9. CloudAIScanner
# ---------------------------------------------------------------------------


class CloudAIScanner:
    """Detect AI resources in Terraform and CloudFormation configs."""

    name = "cloud-scanner"

    def scan(self, project_path: Path) -> list[Finding]:
        cloud_rules = _load_rules("cloud")
        resources = [(re.compile(e[0]), e[1], e[2]) for e in cloud_rules["resources"]]
        findings: list[Finding] = []

        cloud_files = (
            list(project_path.rglob("*.tf"))
            + list(project_path.rglob("*.yaml"))
            + list(project_path.rglob("*.yml"))
            + list(project_path.rglob("*.json"))
        )

        for fp in cloud_files:
            if _in_skip_dir(fp, project_path):
                continue
            try:
                content = fp.read_text(errors="ignore")
            except OSError:
                continue

            for pattern, name, desc in resources:
                for m in pattern.finditer(content):
                    line_num = content[:m.start()].count("\n") + 1
                    findings.append(Finding(
                        scanner_name=self.name,
                        category="cloud-ai",
                        name=name,
                        description=desc,
                        file_path=str(fp),
                        line_number=line_num,
                        confidence=0.95,
                    ))

            # GPU instance detection
            gpu_match = re.search(r"ml\.(g|p|inf|trn)\d+\.\w+", content)
            if gpu_match:
                findings.append(Finding(
                    scanner_name=self.name,
                    category="infrastructure",
                    name="gpu-instance",
                    description=f"GPU instance type: {gpu_match.group(0)}",
                    file_path=str(fp),
                    line_number=content[:gpu_match.start()].count("\n") + 1,
                    confidence=0.9,
                ))

        return findings


# ---------------------------------------------------------------------------
# 10. GitHubActionsScanner
# ---------------------------------------------------------------------------


class GitHubActionsScanner:
    """Detect AI usage in GitHub Actions workflow files."""

    name = "github-actions-scanner"

    def scan(self, project_path: Path) -> list[Finding]:
        gh_rules = _load_rules("github_actions")
        ai_actions: list[str] = gh_rules["actions"]
        ai_env_vars: list[str] = gh_rules["env_vars"]
        findings: list[Finding] = []

        workflows_dir = project_path / ".github" / "workflows"
        if not workflows_dir.is_dir():
            return findings

        for fp in workflows_dir.glob("*.y*ml"):
            try:
                content = fp.read_text(errors="ignore")
            except OSError:
                continue

            # Check for AI actions
            for action in ai_actions:
                if action in content.lower():
                    findings.append(Finding(
                        scanner_name=self.name,
                        category="workflow",
                        name=f"gh-action-{action}",
                        description=f"AI-related GitHub Action: {action}",
                        file_path=str(fp),
                        line_number=0,
                        confidence=0.85,
                    ))

            # Check for AI env vars
            for env_var in ai_env_vars:
                if env_var in content:
                    line_num = content[:content.index(env_var)].count("\n") + 1
                    findings.append(Finding(
                        scanner_name=self.name,
                        category="api-key-reference",
                        name=env_var.lower().replace("_api_key", "").replace("_token", "").replace("_key", ""),
                        description=f"AI API key in GitHub Actions: {env_var}",
                        file_path=str(fp),
                        line_number=line_num,
                        confidence=0.8,
                    ))

        return findings


# ---------------------------------------------------------------------------
# Aggregate scanner
# ---------------------------------------------------------------------------

_ALL_SCANNERS = [
    ImportScanner,
    ModelReferenceScanner,
    APIKeyScanner,
    ConfigFileScanner,
    ModelFileScanner,
    DockerScanner,
    NetworkEndpointScanner,
    JupyterScanner,
    CloudAIScanner,
    GitHubActionsScanner,
]


def scan_all(project_path: Path) -> list[Finding]:
    """Run every scanner and return the combined findings."""
    results: list[Finding] = []
    for scanner_cls in _ALL_SCANNERS:
        scanner = scanner_cls()
        results.extend(scanner.scan(project_path))
    return results
