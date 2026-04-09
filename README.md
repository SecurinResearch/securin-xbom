# xBOM

Generate unified **SBOM**, **AI-BOM**, **CBOM**, and **API-BOM** in a single CycloneDX 1.6 JSON output.

xBOM scans a codebase and produces four Bills of Materials covering software packages, AI/ML components, cryptographic assets, and API endpoints — then merges them into one composite BOM.

## Features

- **SBOM** — Software Bill of Materials via [cdxgen](https://github.com/CycloneDX/cdxgen) or [Trivy](https://github.com/aquasecurity/trivy)
- **AI-BOM** — AI/ML supply chain inventory with 4-layer detection: regex patterns, 200+ package catalog, ecosyste.ms + LLM agent classification, and FalkorDB code graph analysis
- **CBOM** — Cryptographic asset inventory via Semgrep rules across 5 languages, post-quantum safety classification, and live TLS scanning
- **API-BOM** — API endpoint discovery for FastAPI, Flask, Django, and Express, plus OpenAPI spec parsing and outbound HTTP client detection
- **Composite BOM** — All four BOMs merged by PURL deduplication into a single CycloneDX 1.6 JSON
- **Risk scoring** — Each module scores components for security risk (shadow AI, weak crypto, unauthenticated endpoints, etc.)
- **Rules-driven** — All detection patterns live in YAML files; add new patterns without changing Python code
- **Git provider support** — Scan local paths, GitHub, GitLab, or Bitbucket repos directly

## Supported Languages & Ecosystems

| Capability | Python | JavaScript/TypeScript | Java | Go | C/C++ |
|-----------|--------|----------------------|------|-----|-------|
| **SBOM** (cdxgen/trivy) | ✅ | ✅ | ✅ | ✅ | ✅ |
| **AI-BOM** import detection | ✅ | ✅ | ✅ | ✅ | — |
| **AI-BOM** package catalog | pypi | npm | maven | go modules | — |
| **CBOM** crypto scanning (Semgrep) | ✅ | ✅ | ✅ | ✅ | ✅ |
| **CBOM** PQC annotation | ✅ | ✅ | ✅ | ✅ | ✅ |
| **API-BOM** framework extraction | FastAPI, Flask, Django | Express | — | — | — |
| **API-BOM** client detection | requests, httpx, aiohttp, urllib | axios, fetch, node-fetch | — | — | — |
| **API-BOM** OpenAPI spec parsing | ✅ (language-agnostic) | ✅ | ✅ | ✅ | ✅ |

**Also scans:** Dockerfiles, docker-compose, `.env` files, Jupyter notebooks, GitHub Actions workflows, Terraform/CloudFormation configs, MCP config files, model files (`.onnx`, `.safetensors`, `.gguf`, `.pt`), and live TLS endpoints via testssl.sh.

## Quick Start

```bash
pip install -e "."
xbom scan /path/to/project
xbom doctor                   # check what's installed
```

## Setup

### Prerequisites

| Dependency | Required? | Purpose | Install |
|-----------|-----------|---------|---------|
| **Python >= 3.11** | Yes | Runtime | [python.org](https://python.org) |
| **Node.js >= 18** | Yes | cdxgen + MCP servers | `brew install node` / [nodejs.org](https://nodejs.org) |
| **git** | Yes | Remote repo scanning | Pre-installed on most systems |

### Step 1: Python Environment

```bash
git clone https://github.com/SecurinResearch/securin-xbom.git
cd xbom
python3 -m venv .venv
source .venv/bin/activate

# Core only (SBOM + AI-BOM patterns + API-BOM regex)
pip install -e "."

# Everything (agent enrichment, codegraph, dev tools)
pip install -e ".[all]"
```

**Optional extras:**

| Extra | Install | What it enables |
|-------|---------|-----------------|
| `agent` | `pip install -e ".[agent]"` | AI-BOM LLM enrichment via Strands Agents (`--enrich`) |
| `codegraph` | `pip install -e ".[codegraph]"` | AI-BOM code graph analysis via FalkorDB (`--enrich`) |
| `apibom` | `pip install -e ".[apibom]"` | API-BOM tree-sitter AST extraction (optional enhancement) |
| `dev` | `pip install -e ".[dev]"` | pytest, ruff, coverage |
| `all` | `pip install -e ".[all]"` | Everything above |

### Step 2: External CLI Tools

```bash
# cdxgen — SBOM generation (required)
npm install -g @cyclonedx/cdxgen

# semgrep — CBOM crypto scanning (required for CBOM)
pip install semgrep
# or: brew install semgrep

# trivy — alternative SBOM generator (optional)
# brew install trivy

# testssl.sh — live TLS scanning (optional, --live-url only)
# brew install testssl
```

### Step 3: FalkorDB for CodeGraph (Optional)

The AI-BOM CodeGraph layer discovers custom agents, tools, and MCP wrappers by indexing your project into a graph database and exploring it with an autonomous agent. This requires Docker + Node.js.

```bash
# Start FalkorDB (must map port 6379 to host!)
docker run -d --name falkordb -p 6379:6379 falkordb/falkordb

# Verify it's running
docker ps | grep falkordb

# npx must be on PATH (comes with Node.js)
which npx
```

The MCP server (`@falkordb/mcpserver`) is fetched automatically via `npx -y` at scan time — no manual npm install needed.

### Step 4: LLM API Key for Enrichment (Optional)

The `--enrich` flag activates the Strands Agent for classifying unknown packages. Configure one of 8 supported providers:

```bash
# Option A: OpenAI directly
export OPENAI_API_KEY=sk-...
export XBOM_ENRICHMENT_PROVIDER=openai

# Option B: Anthropic directly
export ANTHROPIC_API_KEY=sk-ant-...
export XBOM_ENRICHMENT_PROVIDER=anthropic

# Option C: LiteLLM proxy (used in development)
export LITELLM_V_KEY="your-key"
export LITELLM_MODEL="azure/sonnet-4.6"
export XBOM_ENRICHMENT_PROVIDER=openai_like

# Option D: AWS Bedrock (uses AWS credentials from env/profile)
export XBOM_ENRICHMENT_PROVIDER=bedrock

# Other providers: gemini, litellm_proxy, azure_ai_foundry, vertex_ai
# See src/xbom/modules/aibom/agent_config.yaml for all provider configs
```

### Step 5: Verify

```bash
xbom doctor
```

This checks three categories:
- **CLI Tools** — cdxgen, semgrep, git, npx, node, trivy, testssl.sh
- **Python Extras** — strands-agents, falkordb, tree-sitter
- **Services** — FalkorDB connectivity (localhost:6379)

## Usage

### Basic Scan

```bash
# Scan a local project (all 4 BOM types)
xbom scan /path/to/project

# With verbose logging
xbom scan /path/to/project -v

# Custom output directory
xbom scan /path/to/project -o /tmp/xbom-output
```

### Selective Scanning

```bash
# Only AI-BOM and API-BOM
xbom scan /path/to/project --bom-types aibom,apibom

# Skip SBOM
xbom scan /path/to/project --skip sbom

# Use Trivy instead of cdxgen
xbom scan /path/to/project --sbom-tool trivy
```

### Enriched Scan (LLM Agent + CodeGraph)

Requires: `pip install -e ".[agent,codegraph]"` + API key + Docker with FalkorDB running.

```bash
export XBOM_ENRICHMENT_PROVIDER=openai
xbom scan /path/to/project --enrich -v
```

This activates:
- **AI-BOM Layer 3**: Strands Agent classifies unknown packages via ecosyste.ms metadata
- **AI-BOM Layer 4**: CodeGraph indexes the project into FalkorDB, then an agent explores the graph via MCP to discover custom agents, tools, and architectural patterns

### Remote Repos

```bash
# GitHub
xbom scan https://github.com/org/repo

# With auth and branch
xbom scan https://github.com/org/repo --token ghp_xxx --branch main

# GitLab / Bitbucket
xbom scan https://gitlab.com/org/repo --token glpat-xxx
```

### Live TLS Scanning

```bash
# Requires testssl.sh on PATH
xbom scan /path/to/project --live-url https://api.example.com
```

### Sample Project

A bundled sample project exercises all four modules:

```bash
# Basic scan (AI-BOM patterns + API-BOM + CBOM)
xbom scan sample/ --skip sbom -v -o /tmp/xbom-sample

# Full enriched scan (+ LLM agent + CodeGraph)
xbom scan sample/ --enrich -v -o /tmp/xbom-sample-full
```

The sample project is a FastAPI AI chat service with OpenAI, LangChain, Strands Agents, MCP tools, JWT/bcrypt/Fernet crypto, and outbound HTTP calls to Slack/Stripe/Sentry.

## Output

xBOM writes individual and composite BOMs to the output directory:

```
xbom-output/
  xbom-composite.cdx.json   # Merged BOM (all modules combined)
  sbom.cdx.json              # Software BOM
  ai-bom.cdx.json            # AI/ML BOM
  cbom.cdx.json              # Cryptographic BOM
  api-bom.cdx.json           # API BOM
```

All output follows the [CycloneDX 1.6](https://cyclonedx.org/specification/overview/) specification. Each module adds custom properties under its own namespace:

| Module | Property Namespace | Examples |
|--------|-------------------|----------|
| AI-BOM | `xbom:ai:*` | `xbom:ai:category`, `xbom:ai:shadow_ai`, `xbom:ai:risk_score` |
| CBOM | `xbom:crypto:*` | `xbom:crypto:quantum_safe`, `xbom:crypto:weakness`, `xbom:crypto:risk_severity` |
| API-BOM | `xbom:api:*` | `xbom:api:framework`, `xbom:api:auth_coverage`, `xbom:api:risk_score` |

## Architecture

```
CLI (Typer) -> Runner (orchestrator) -> BOM Modules -> Merger -> CycloneDX JSON
                                          |
                    +---------------------+--------------------+
                    |           |           |                   |
                  SBOM       AI-BOM       CBOM              API-BOM
                (cdxgen/    (4 layers)   (3 layers)         (3 layers)
                 trivy)
```

### SBOM Module

Generates a standard Software BOM using cdxgen (default) or Trivy. Runs first — other modules cross-reference its output.

**Requires:** Node.js + cdxgen (`npm install -g @cyclonedx/cdxgen`)

### AI-BOM Module

Detects AI/ML components through a 4-layer pipeline:

| Layer | Requires | What it does |
|-------|----------|--------------|
| 1. Pattern scanning | nothing | 10 regex scanners (imports, model names, API keys, Docker images, etc.) across Python/JS/Java/Go |
| 2. Catalog cross-ref | SBOM output | Matches SBOM packages against 200+ known AI/ML package catalog |
| 3. ecosyste.ms + Agent | `--enrich` + API key + `pip install xbom[agent]` | Bulk metadata lookup + LLM classification of unknown packages |
| 4. CodeGraph | `--enrich` + Docker + FalkorDB + npx + `pip install xbom[codegraph]` | Autonomous graph exploration to discover custom agents, tools, MCP wrappers |

Post-processing: shadow AI detection (imports not in SBOM) and risk scoring.

### CBOM Module

Detects cryptographic assets through a 3-layer pipeline:

| Layer | Requires | What it does |
|-------|----------|--------------|
| 1. Semgrep | semgrep | Custom crypto rules for Python, Java, JS/TS, Go, C/C++ |
| 2. cdxgen crypto | cdxgen | cdxgen `--include-crypto` for Java and Python |
| 3. testssl.sh | `--live-url` + testssl.sh | Live TLS endpoint scanning (cipher suites, certs, protocols) |

Post-processing: post-quantum safety classification and crypto risk scoring.

### API-BOM Module

Discovers API endpoints through a 3-layer pipeline:

| Layer | Requires | What it does |
|-------|----------|--------------|
| 1. Framework extraction | nothing | Route patterns for FastAPI, Flask, Django, Express (regex from YAML) |
| 2. OpenAPI spec parsing | nothing | Parses openapi.yaml/swagger.json for endpoint definitions |
| 3. Client detection | nothing | Detects outbound HTTP calls (requests, httpx, axios, fetch, etc.) |

Post-processing: auth coverage analysis and API risk scoring.

## Configuration

### Environment Variables

**Core:**
| Variable | Purpose |
|----------|---------|
| `XBOM_OUTPUT_DIR` | Default output directory |
| `XBOM_CDXGEN_PATH` | Custom cdxgen binary path |
| `XBOM_SEMGREP_PATH` | Custom semgrep binary path |
| `XBOM_TRIVY_PATH` | Custom trivy binary path |

**Git providers:**
| Variable | Purpose |
|----------|---------|
| `XBOM_GITHUB_TOKEN` | GitHub auth token for private repos |
| `XBOM_GITLAB_TOKEN` | GitLab auth token |
| `XBOM_BITBUCKET_TOKEN` | Bitbucket app password |

**AI-BOM enrichment (`--enrich`):**
| Variable | Purpose |
|----------|---------|
| `XBOM_ENRICHMENT_PROVIDER` | Provider: `openai`, `openai_like`, `anthropic`, `gemini`, `litellm_proxy`, `bedrock`, `azure_ai_foundry`, `vertex_ai` |
| `OPENAI_API_KEY` | OpenAI API key |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `GOOGLE_API_KEY` | Google Gemini API key |
| `LITELLM_V_KEY` / `LITELLM_API_KEY` | LiteLLM proxy API key |
| `LITELLM_MODEL` | Override model ID for openai_like/litellm_proxy |
| `LITELLM_API_BASE` | LiteLLM proxy base URL |
| `AZURE_API_KEY` / `AZURE_API_BASE` | Azure AI Foundry credentials |
| `FALKORDB_HOST` / `FALKORDB_PORT` | FalkorDB connection (default: localhost:6379) |
| `XBOM_CODEGRAPH_TIMEOUT` | CodeGraph agent timeout in seconds (default: 120) |

### Extending Detection Rules

All detection patterns are in YAML files under each module's `rules/` directory. To add a new pattern:

```bash
# Add a new AI import pattern
vim src/xbom/modules/aibom/rules/imports.yaml

# Add a new crypto Semgrep rule
vim src/xbom/modules/cbom/rules/python-crypto.yaml

# Add a new API framework pattern
vim src/xbom/modules/apibom/rules/frameworks.yaml

# Add a new AI package to the catalog
vim src/xbom/modules/aibom/rules/catalog.yaml
```

No Python code changes required.

## Development

```bash
source .venv/bin/activate
pip install -e ".[all]"

# Run tests
pytest                                      # 81 tests
pytest tests/test_apibom.py -v              # Single module

# Lint
ruff check src/ tests/
ruff format src/ tests/
```

### Project Structure

```
src/xbom/
  cli.py                     # Typer CLI (scan, doctor, validate, version)
  runner.py                  # Scan orchestration
  merger.py                  # BOM merging
  models.py                  # Data models (BomType, ScanConfig, etc.)
  config.py                  # Env vars and tool paths
  source/provider.py         # Git provider abstraction
  utils/
    cyclonedx.py             # CycloneDX helpers
    subprocess.py            # Safe subprocess execution
  modules/
    base.py                  # Abstract BomModule
    sbom/                    # SBOM module (cdxgen/trivy wrappers)
    aibom/                   # AI-BOM module (4-layer pipeline + 12 YAML rule files)
    cbom/                    # CBOM module (3-layer pipeline + 13 YAML rule files)
    apibom/                  # API-BOM module (3-layer pipeline + 4 YAML rule files)
sample/                      # Sample project for testing all 4 modules
```

## License

Apache-2.0
