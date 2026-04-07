"""Pydantic models for request/response schemas."""

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    version: str


class ChatRequest(BaseModel):
    question: str
    model: str = "gpt-4o"
    temperature: float = 0.7
    max_tokens: int = 1024


class ChatResponse(BaseModel):
    answer: str
    sources: list[str]
    model: str
    tokens_used: int


class DocumentUpload(BaseModel):
    filename: str
    content: str


class UserProfile(BaseModel):
    user_id: str
    email: str
    role: str = "user"
