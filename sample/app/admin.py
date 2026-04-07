"""Admin endpoints — system management and monitoring."""

import os

from fastapi import APIRouter, Depends

from app.auth import get_current_user

router = APIRouter(tags=["admin"])


@router.get("/dashboard")
def admin_dashboard(user=Depends(get_current_user)):
    """Admin overview with system stats."""
    return {"status": "ok", "user": user}


@router.get("/debug/config")
def debug_config():
    """Debug endpoint showing runtime config (NO AUTH!)."""
    return {
        "model": os.environ.get("OPENAI_MODEL", "gpt-4o"),
        "chroma_host": os.environ.get("CHROMA_HOST", "localhost"),
        "redis_url": os.environ.get("REDIS_URL", "redis://localhost:6379"),
    }


@router.delete("/users/{user_id}")
def delete_user(user_id: str, user=Depends(get_current_user)):
    """Delete a user account."""
    return {"deleted": user_id}


@router.post("/password/reset")
def reset_password(email: str, user=Depends(get_current_user)):
    """Trigger password reset flow."""
    return {"status": "reset_sent", "email": email}
