# DocQ&A — Sample Project for xBOM

A small AI-powered document Q&A service designed to exercise all four xBOM modules.

## What's inside

| File | AI/Security surface |
|------|---------------------|
| `app/main.py` | FastAPI app with CORS wildcard, 2 public routes (no auth) |
| `app/chat.py` | RAG pipeline: OpenAI + ChromaDB + tiktoken + LangChain |
| `app/agent.py` | Strands Agent orchestrator with 4 tools + 2 MCP servers |
| `app/rag_pipeline.py` | LangChain RAG chain with OpenAI embeddings |
| `app/auth.py` | JWT (HS256), bcrypt, Fernet (AES-128), SHA-256, HMAC-SHA256 |
| `app/admin.py` | Admin routes including `/debug/config` with no auth, `/password/reset` |
| `app/external.py` | 5 outbound HTTP calls — Slack, Sentry, Stripe, PagerDuty, weather (no TLS!) |
| `app/guardrails.py` | guardrails-ai PII detection + OpenAI content moderation |
| `app/observability.py` | structlog + boto3 S3 metrics archival |
| `mcp.json` | 3 MCP server configs (knowledge-base, browser-tools, database-query) |
| `docs/openapi.yaml` | OpenAPI 3.0 spec with 6 endpoints + JWT security scheme |
| `.env` | OPENAI_API_KEY, JWT secrets, encryption keys |
| `requirements.txt` | 24 Python packages |

## Scan it

```bash
# From the xbom repo root
xbom scan sample/ -v -o /tmp/xbom-sample

# With LLM enrichment (needs API key configured)
xbom scan sample/ --enrich -v -o /tmp/xbom-sample-full
```

## Expected results

### AI-BOM (13 components)

| Scanner | Findings |
|---------|----------|
| import-scanner | chromadb, tiktoken, langchain, openai, guardrails-ai, strands-agents, mcp-sdk, anthropic |
| model-reference-scanner | gpt-4o, text-embedding-3-small, claude-sonnet |
| config-file-scanner | OPENAI_API_KEY (.env), mcp.json (3 MCP servers) |

### CBOM

Crypto usage in `app/auth.py`: JWT HS256, bcrypt, Fernet AES-128-CBC, SHA-256, HMAC-SHA256. Requires semgrep installed for detection.

### API-BOM (3 services, 5 components)

| Source | Endpoints | Auth | Risk |
|--------|-----------|------|------|
| `app/chat.py` | /chat, /documents | 100% | info |
| `app/admin.py` | /dashboard, /debug/config, /password/reset, /users/{id} | 100% | medium (45) — sensitive_data_exposure + admin_endpoint_exposed |
| `app/main.py` | /health, /api/v1/models | 0% | medium (30) — no_authentication |

| External Dep | TLS | Risk |
|-------------|-----|------|
| hooks.slack.com | yes | info |
| sentry.io | yes | info |
| events.pagerduty.com | yes | info |
| api.weatherapi.com | **no** | low (25) — external_api_no_tls |

OpenAPI spec: `docs/openapi.yaml` (6 endpoints, JWT security)
