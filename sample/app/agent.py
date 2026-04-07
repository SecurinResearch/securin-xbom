"""AI Agent — multi-tool orchestrator using Strands Agents."""

import os

from strands import Agent
from strands.tools import tool
from strands.tools.mcp import MCPClient
from mcp import stdio_client, StdioServerParameters

from app.embeddings import get_embedding


# --- Tools ---

@tool
def search_documents(query: str) -> str:
    """Search the document store for relevant information."""
    embedding = get_embedding(query)
    # In production, this would query ChromaDB
    return f"Found 3 documents matching: {query}"


@tool
def fetch_web_page(url: str) -> str:
    """Fetch and summarize a web page."""
    import httpx
    resp = httpx.get(url)
    return resp.text[:2000]


@tool
def run_sql_query(query: str) -> str:
    """Execute a read-only SQL query against the analytics database."""
    # Safety check
    if any(kw in query.upper() for kw in ["DROP", "DELETE", "INSERT", "UPDATE"]):
        return "Error: Only SELECT queries are allowed."
    return f"Query executed: {query} → 42 rows returned"


@tool
def send_notification(channel: str, message: str) -> str:
    """Send a notification to a Slack channel."""
    import requests
    requests.post(
        "https://hooks.slack.com/services/T00/B00/agent-webhook",
        json={"channel": channel, "text": message},
    )
    return f"Notification sent to #{channel}"


# --- MCP Tool Servers ---

def _build_mcp_client(server_name: str, port: int) -> MCPClient:
    """Build an MCP client for a local tool server."""
    return MCPClient(
        lambda: stdio_client(StdioServerParameters(
            command="npx",
            args=["-y", f"@example/{server_name}@latest"],
            env={**os.environ, "PORT": str(port)},
        ))
    )


# --- Agent Factory ---

SYSTEM_PROMPT = """You are a helpful document Q&A assistant with access to tools.
You can search documents, fetch web pages, run analytics queries, and send notifications.
Always cite your sources when answering questions.
Use the MCP tools when you need to access external knowledge bases."""


def create_qa_agent(model: str = "gpt-4o") -> Agent:
    """Create a Q&A agent with tools and MCP connections."""
    from openai import OpenAI

    tools = [search_documents, fetch_web_page, run_sql_query, send_notification]

    agent = Agent(
        model=model,
        tools=tools,
        system_prompt=SYSTEM_PROMPT,
    )

    return agent


def create_research_agent() -> Agent:
    """Create a research agent that uses MCP tool servers."""
    from anthropic import Anthropic

    mcp_knowledge = _build_mcp_client("knowledge-base-server", 8100)
    mcp_browser = _build_mcp_client("browser-tools", 8101)

    agent = Agent(
        model="claude-sonnet-4-20250514",
        tools=[mcp_knowledge, mcp_browser, search_documents],
        system_prompt="You are a research assistant. Use MCP tools to gather comprehensive information.",
    )

    return agent


# --- Orchestrator ---

class AgentOrchestrator:
    """Routes user requests to the appropriate specialized agent."""

    def __init__(self):
        self.qa_agent = create_qa_agent()
        self.research_agent = create_research_agent()
        self.model = "gpt-4o"

    def route(self, query: str, mode: str = "qa") -> str:
        """Route a query to the appropriate agent."""
        if mode == "research":
            return str(self.research_agent(query))
        return str(self.qa_agent(query))
