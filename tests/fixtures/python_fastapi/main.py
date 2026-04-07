"""Sample FastAPI app with AI components — for testing."""

import os

from fastapi import FastAPI
from openai import OpenAI

app = FastAPI()

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
MODEL = "gpt-4o"


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/chat")
def chat(message: str):
    response = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": message}],
    )
    return {"reply": response.choices[0].message.content}


@app.get("/api/users/{user_id}")
def get_user(user_id: int):
    return {"user_id": user_id, "name": "Test User"}
