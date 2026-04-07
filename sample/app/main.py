"""AI-powered document Q&A service — sample project for xBOM scanning."""

import os

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.auth import get_current_user
from app.chat import router as chat_router
from app.admin import router as admin_router
from app.models import HealthResponse

app = FastAPI(title="DocQ&A", version="1.0.0", description="AI-powered document Q&A service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(chat_router, prefix="/api/v1")
app.include_router(admin_router, prefix="/admin")


@app.get("/health", response_model=HealthResponse)
def health():
    return HealthResponse(status="ok", version="1.0.0")


@app.get("/api/v1/models")
def list_models():
    return {
        "models": [
            {"id": "gpt-4o", "provider": "openai"},
            {"id": "claude-sonnet-4-20250514", "provider": "anthropic"},
        ]
    }
