"""Guardrails — input/output validation for AI responses."""

import re

from guardrails import Guard
from openai import OpenAI


# PII detection patterns
PII_PATTERNS = [
    (r"\b\d{3}-\d{2}-\d{4}\b", "SSN"),
    (r"\b\d{16}\b", "credit card"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "email"),
]


def check_pii_leakage(text: str) -> list[str]:
    """Check if AI output contains PII that should be redacted."""
    violations = []
    for pattern, pii_type in PII_PATTERNS:
        if re.search(pattern, text):
            violations.append(f"Potential {pii_type} detected in output")
    return violations


def validate_response(response: str, max_tokens: int = 4096) -> dict:
    """Validate an AI response before returning to user."""
    issues = check_pii_leakage(response)

    if len(response.split()) > max_tokens:
        issues.append("Response exceeds maximum token limit")

    return {
        "valid": len(issues) == 0,
        "issues": issues,
        "response": response if not issues else "[REDACTED — validation failed]",
    }


class ContentFilter:
    """Filter harmful or off-topic content from AI interactions."""

    BLOCKED_TOPICS = ["violence", "illegal", "hate speech"]

    def __init__(self, model: str = "gpt-4o-mini"):
        self.client = OpenAI()
        self.model = model

    def is_safe(self, text: str) -> bool:
        """Check if input text is safe for processing."""
        response = self.client.moderations.create(input=text)
        return not response.results[0].flagged
