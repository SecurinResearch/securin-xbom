"""Sample file with outbound HTTP client calls — for testing."""

import requests
import httpx

# requests calls
response = requests.get("https://api.example.com/v1/data")
result = requests.post("https://api.openai.com/v1/chat/completions", json={"model": "gpt-4"})

# httpx calls
client = httpx.Client(base_url="https://api.stripe.com/v1")
resp = httpx.get("http://insecure-api.example.com/data")  # No TLS!
