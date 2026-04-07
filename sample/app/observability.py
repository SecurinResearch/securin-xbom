"""Observability — logging, metrics, and tracing for AI operations."""

import time
import structlog
from collections import defaultdict

import boto3


logger = structlog.get_logger(__name__)

# S3 client for log archival
s3_client = boto3.client("s3", region_name="us-east-1")
METRICS_BUCKET = "docqa-metrics"


class TokenTracker:
    """Track token usage across models and users."""

    def __init__(self):
        self.usage = defaultdict(lambda: {"prompt": 0, "completion": 0, "total": 0})

    def record(self, user_id: str, model: str, prompt_tokens: int, completion_tokens: int):
        key = f"{user_id}:{model}"
        self.usage[key]["prompt"] += prompt_tokens
        self.usage[key]["completion"] += completion_tokens
        self.usage[key]["total"] += prompt_tokens + completion_tokens

        logger.info(
            "token_usage",
            user_id=user_id,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )

    def get_usage(self, user_id: str) -> dict:
        return {k: v for k, v in self.usage.items() if k.startswith(user_id)}


class LatencyTracker:
    """Track LLM call latency for SLA monitoring."""

    def __init__(self):
        self.latencies = []

    def __enter__(self):
        self._start = time.monotonic()
        return self

    def __exit__(self, *args):
        elapsed = time.monotonic() - self._start
        self.latencies.append(elapsed)
        logger.info("llm_latency", duration_ms=round(elapsed * 1000, 2))

    @property
    def p99(self) -> float:
        if not self.latencies:
            return 0.0
        sorted_l = sorted(self.latencies)
        idx = int(len(sorted_l) * 0.99)
        return sorted_l[min(idx, len(sorted_l) - 1)]


def archive_metrics(date: str, data: dict) -> None:
    """Archive daily metrics to S3."""
    import json
    s3_client.put_object(
        Bucket=METRICS_BUCKET,
        Key=f"metrics/{date}.json",
        Body=json.dumps(data),
    )
    logger.info("metrics_archived", date=date, bucket=METRICS_BUCKET)
