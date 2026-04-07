"""Embedding generation via OpenAI."""

import os

from openai import OpenAI

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

EMBEDDING_MODEL = "text-embedding-3-small"


def get_embedding(text: str) -> list[float]:
    """Generate embedding vector for a text string."""
    response = client.embeddings.create(input=[text], model=EMBEDDING_MODEL)
    return response.data[0].embedding
