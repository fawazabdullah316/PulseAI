"""
PULSEAI — Celery worker + task definitions

Start workers:
    celery -A celery_worker worker --loglevel=info --concurrency=4

Requires:
    REDIS_URL env var pointing to your Redis instance
    ANTHROPIC_API_KEY + other pipeline env vars
"""

import os
import logging
from celery import Celery

log = logging.getLogger("PULSEAI.celery")

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# ---------------------------------------------------------------------------
# Celery app
# ---------------------------------------------------------------------------

celery_app = Celery(
    "pulseai",
    broker=REDIS_URL,
    backend=REDIS_URL,
)

celery_app.conf.update(
    # Serialisation
    task_serializer   = "json",
    accept_content    = ["json"],
    result_serializer = "json",

    # Time zone
    timezone          = "UTC",
    enable_utc        = True,

    # Task behaviour
    task_track_started      = True,
    task_time_limit         = 120,         # Hard kill after 2 min
    task_soft_time_limit    = 90,          # Raise SoftTimeLimitExceeded at 90s
    worker_prefetch_multiplier = 1,        # One task at a time per worker — fair distribution
    task_acks_late          = True,        # Re-queue if worker crashes mid-task
    task_reject_on_worker_lost = True,     # Don't lose tasks on worker SIGKILL

    # Result expiry — keep results for 1 hour then auto-delete from Redis
    result_expires     = 3600,

    # Retry policy
    task_default_retry_delay = 5,          # Wait 5s before retry
    task_max_retries         = 2,          # Max 2 retries (3 total attempts)
)

# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------

@celery_app.task(
    bind=True,
    name="pulseai.run_pipeline",
    max_retries=2,
    default_retry_delay=5,
)
def run_pipeline_task(self, alert_name: str, service: str, triggered_at: str | None = None):
    """
    Async wrapper around run_pipeline().
    Dispatched by POST /analyse/async and PagerDuty webhook (when Celery is configured).
    Result is stored in Redis and retrievable via GET /result/{job_id}.
    """
    from dataclasses import asdict
    from pipeline import run_pipeline

    log.info(
        "Celery task started [id=%s] alert='%s' service='%s'",
        self.request.id, alert_name, service,
    )
    try:
        rca = run_pipeline(
            alert_name   = alert_name,
            service      = service,
            triggered_at = triggered_at,
        )
        log.info(
            "Celery task complete [id=%s] incident_id=%s confidence=%d",
            self.request.id, rca.incident_id, rca.confidence,
        )
        return asdict(rca)
    except Exception as exc:
        log.error("Celery task failed [id=%s]: %s", self.request.id, exc)
        raise self.retry(exc=exc) from exc


# ---------------------------------------------------------------------------
# CLI — run a task synchronously for quick testing
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import json
    alert   = sys.argv[1] if len(sys.argv) > 1 else "High error rate on /api/checkout"
    service = sys.argv[2] if len(sys.argv) > 2 else "checkout-service"
    print(f"Running task synchronously for alert='{alert}' service='{service}'")
    result = run_pipeline_task(alert_name=alert, service=service)
    print(json.dumps(result, indent=2))
