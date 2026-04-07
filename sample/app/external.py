"""External API integrations — outbound HTTP calls."""

import httpx
import requests


def send_to_slack(webhook_url: str, message: str) -> dict:
    """Post a notification to Slack."""
    resp = requests.post("https://hooks.slack.com/services/T00/B00/xxx", json={"text": message})
    return resp.json()


def log_to_sentry(event: dict) -> None:
    """Send error event to Sentry."""
    requests.post("https://sentry.io/api/0/store/", json=event)


def fetch_weather(city: str) -> dict:
    """Fetch weather data from a public API (no TLS!)."""
    resp = httpx.get(f"http://api.weatherapi.com/v1/current.json?q={city}")
    return resp.json()


def call_stripe(payment_intent_id: str) -> dict:
    """Retrieve a payment intent from Stripe."""
    resp = httpx.get(
        f"https://api.stripe.com/v1/payment_intents/{payment_intent_id}",
        headers={"Authorization": "Bearer sk_test_xxx"},
    )
    return resp.json()


def notify_pagerduty(incident: dict) -> dict:
    """Trigger a PagerDuty incident."""
    resp = requests.post("https://events.pagerduty.com/v2/enqueue", json=incident)
    return resp.json()
