"""
PULSEAI — FastAPI server  (v4 — production-grade)

Upgrades from v3:
  [Monitor]    /metrics endpoint — Prometheus scrape target for Grafana/Datadog
  [Async]      POST /analyse/async — returns job_id instantly; Celery processes in background
  [Async]      GET  /result/{job_id} — poll Celery result (queued/processing/complete/failed)
  [Health]     /health now includes DB + Redis + Celery status
  [Rate limit] slowapi — 10/min on /analyse, 30/min on /analyse/async, 100/min on /result
  [Ops]        Celery import is conditional — server still works without Celery configured
  (All v3 features retained)

Run (single worker, dev):
    uvicorn server:app --host 0.0.0.0 --port 8000

Run (production, multiple Gunicorn workers):
    gunicorn server:app --worker-class uvicorn.workers.UvicornWorker --config gunicorn_conf.py
"""

import os
import uuid
import logging
from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Header, Request, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from pipeline import (
    run_pipeline, startup, get_recent_analyses, check_db_health,
    verify_pagerduty_signature, RootCauseAnalysis,
    PULSEAI_API_KEY, PULSEAI_API_KEYS, REDIS_URL,
)

log = logging.getLogger("PULSEAI.server")

# ---------------------------------------------------------------------------
# Prometheus multiprocess setup (must happen before workers fork)
# Note: pipeline.py already creates this directory the moment it's imported
# below (it has to, for the reason explained in its own comments) — this is
# kept here too as a harmless, idempotent safety net for any code path that
# might import this module differently in the future.
# ---------------------------------------------------------------------------
import tempfile as _tempfile
_PROM_MULTIPROC_DIR = os.environ.get(
    "PROMETHEUS_MULTIPROC_DIR",
    os.path.join(_tempfile.gettempdir(), "pulseai_prom"),
)
os.makedirs(_PROM_MULTIPROC_DIR, exist_ok=True)
os.environ.setdefault("PROMETHEUS_MULTIPROC_DIR", _PROM_MULTIPROC_DIR)

try:
    from prometheus_client import (
        CollectorRegistry, multiprocess,
        generate_latest, CONTENT_TYPE_LATEST,
    )
    _PROM_OK = True
except ImportError:
    _PROM_OK = False
    log.warning("prometheus_client not installed — /metrics disabled")

# ---------------------------------------------------------------------------
# Celery (optional — async endpoint disabled if not configured)
# ---------------------------------------------------------------------------
_CELERY_OK = False
try:
    if REDIS_URL:
        from celery_worker import run_pipeline_task
        from celery.result import AsyncResult
        _CELERY_OK = True
        log.info("Celery async dispatch enabled")
    else:
        log.info("REDIS_URL not set — async /analyse/async endpoint disabled")
except ImportError:
    log.info("celery_worker.py not found — async /analyse/async endpoint disabled")

# ---------------------------------------------------------------------------
# Rate limiter (slowapi) — uses Redis for distributed rate limiting across workers
# ---------------------------------------------------------------------------
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded

    # Don't trust REDIS_URL blindly — if it's set but unreachable (e.g. it
    # still has the Docker-internal "redis://redis:6379/0" value but the app
    # is now running outside Docker), slowapi/limits will raise an unhandled
    # redis.exceptions.ConnectionError on the FIRST real request instead of
    # at startup. Ping it now and fall back to in-memory storage if it fails,
    # the same defensive pattern pipeline.py already uses for its cache.
    _storage_uri = "memory://"
    if REDIS_URL:
        try:
            import redis as _redis_probe
            _probe_client = _redis_probe.from_url(REDIS_URL, socket_timeout=2)
            _probe_client.ping()
            _storage_uri = REDIS_URL
        except Exception as exc:
            log.warning(
                "REDIS_URL is set but unreachable (%s) — rate limiter falling "
                "back to in-memory storage for this process", exc,
            )

    _limiter     = Limiter(
        key_func=get_remote_address,
        storage_uri=_storage_uri,
    )
    _RATE_LIMIT_OK = True
    log.info("Rate limiting enabled (storage: %s)", "redis" if _storage_uri != "memory://" else "memory")
except ImportError:
    _RATE_LIMIT_OK = False
    log.warning("slowapi not installed — rate limiting disabled")


def _rate_limit(limit_string: str):
    """
    Returns the slowapi rate-limit decorator if available, else a transparent
    no-op decorator. MUST be applied as a real decorator (@_rate_limit(...))
    directly above a route function that takes `request: Request` as a
    parameter — slowapi inspects the function signature at call time to find
    the Request object and raises if it's missing. Calling limiter.limit(...)
    inline inside a function body (e.g. on a throwaway lambda) does NOT work
    and will 500 on every request, because that lambda has no `request` param.
    """
    if _RATE_LIMIT_OK:
        return _limiter.limit(limit_string)

    def _noop(func):
        return func
    return _noop

# ---------------------------------------------------------------------------
# Lifespan — startup + shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    startup()
    log.info("PULSEAI server ready — workers up")
    yield
    log.info("PULSEAI server shutting down")

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="PULSEAI",
    description="Production incident intelligence — AI-powered root cause analysis",
    version="4.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Register rate limiter on the app
if _RATE_LIMIT_OK:
    app.state.limiter = _limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---------------------------------------------------------------------------
# CORS — restrict in production via PULSEAI_ALLOWED_ORIGINS env var
# e.g. PULSEAI_ALLOWED_ORIGINS=https://app.pulseai.io,https://dashboard.pulseai.io
# ---------------------------------------------------------------------------
_raw_origins = os.environ.get("PULSEAI_ALLOWED_ORIGINS", "*")
_origins     = [o.strip() for o in _raw_origins.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Request ID middleware — every response gets X-Request-ID for tracing
# ---------------------------------------------------------------------------

@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    response   = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response

# ---------------------------------------------------------------------------
# Body size limit — reject requests over 1 MB
# ---------------------------------------------------------------------------

@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    max_body       = 1 * 1024 * 1024  # 1 MB
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > max_body:
        return JSONResponse(
            status_code=413,
            content={"detail": "Request body too large (max 1 MB)"},
        )
    return await call_next(request)

# ---------------------------------------------------------------------------
# Auth dependency — checks X-API-Key header on protected routes
# ---------------------------------------------------------------------------

def require_api_key(request: Request, x_api_key: str = Header(default="")):
    """
    Protects /analyse, /analyse/async, /result/{job_id}, and /history.

    Accepts either:
      - PULSEAI_API_KEY (singular) — one shared key, simplest setup
      - PULSEAI_API_KEYS (plural) — multiple named keys, one per customer,
        so each pilot company can be individually revoked without affecting
        the others. Generate one with generate_customer_key.py.

    If neither is set, auth is bypassed (fine for local dev, not production).
    On success, request.state.customer_name is set ("default" for the
    singular key) so route handlers and logs can identify who called.
    """
    if not PULSEAI_API_KEY and not PULSEAI_API_KEYS:
        request.state.customer_name = "unauthenticated"
        return
    if PULSEAI_API_KEY and x_api_key == PULSEAI_API_KEY:
        request.state.customer_name = "default"
        return
    if x_api_key in PULSEAI_API_KEYS:
        request.state.customer_name = PULSEAI_API_KEYS[x_api_key]
        return
    raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header")

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class AnalyseRequest(BaseModel):
    alert_name:   str       = Field(..., min_length=1, max_length=500)
    service:      str       = Field(..., min_length=1, max_length=100)
    triggered_at: str | None = Field(default=None, description="ISO 8601 timestamp")

    model_config = {
        "json_schema_extra": {
            "example": {
                "alert_name":   "High error rate on /api/checkout",
                "service":      "checkout-service",
                "triggered_at": None,
            }
        }
    }


class FixSuggestion(BaseModel):
    rank:       int
    action:     str
    confidence: int
    detail:     str


class AnalyseResponse(BaseModel):
    incident_id:       str
    summary:           str
    root_cause:        str
    confidence:        int
    fixes:             list[FixSuggestion]
    implicated_commit: str | None
    generated_at:      str
    input_tokens:      int = 0
    output_tokens:     int = 0


class AsyncJobResponse(BaseModel):
    job_id:  str
    status:  str   = "queued"
    message: str   = "Analysis queued. Poll /result/{job_id} for the result."


class PagerDutyWebhook(BaseModel):
    messages: list[dict]

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health", tags=["ops"])
def health():
    """
    Liveness + readiness check.
    Includes DB, Redis, and Celery worker health.
    Used by Kubernetes probes, Railway, and uptime monitors.
    """
    db_status    = check_db_health()
    redis_status = "ok"
    try:
        if REDIS_URL:
            import redis as redis_lib
            r = redis_lib.from_url(REDIS_URL, socket_timeout=2)
            r.ping()
        else:
            redis_status = "not_configured"
    except Exception as exc:
        redis_status = f"error: {exc}"

    celery_status = (
        "enabled" if _CELERY_OK else
        "not_configured" if not REDIS_URL else
        "error"
    )

    overall = "ok" if db_status.get("status") == "ok" else "degraded"

    return {
        "status":    overall,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version":   "4.0.0",
        "checks": {
            "database": db_status,
            "redis":    redis_status,
            "celery":   celery_status,
        },
    }


@app.get("/metrics", tags=["ops"])
def metrics():
    """
    Prometheus scrape endpoint.
    Point Grafana or Datadog agent here: GET /metrics
    Works correctly with multiple Gunicorn workers via multiprocess collector.
    """
    if not _PROM_OK:
        raise HTTPException(
            status_code=501,
            detail="prometheus_client not installed. Run: pip install prometheus-client",
        )
    registry = CollectorRegistry()
    multiprocess.MultiProcessCollector(registry)
    return Response(
        content=generate_latest(registry),
        media_type=CONTENT_TYPE_LATEST,
    )


@app.post(
    "/analyse",
    response_model=AnalyseResponse,
    tags=["core"],
    dependencies=[Depends(require_api_key)],
)
@_rate_limit("10/minute")
def analyse(request: Request, req: AnalyseRequest):
    """
    Synchronous RCA — runs the full pipeline and returns the result.
    Best for: direct API use, webhooks that need an immediate result.
    Rate limited: 10 requests/minute per IP.
    """
    customer = getattr(request.state, "customer_name", "unknown")
    log.info("PULSEAI_REQUEST customer=%s alert=%r service=%r", customer, req.alert_name, req.service)
    try:
        rca: RootCauseAnalysis = run_pipeline(
            alert_name   = req.alert_name,
            service      = req.service,
            triggered_at = req.triggered_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return AnalyseResponse(**asdict(rca))


@app.post(
    "/analyse/async",
    response_model=AsyncJobResponse,
    tags=["core"],
    dependencies=[Depends(require_api_key)],
)
@_rate_limit("30/minute")
def analyse_async(request: Request, req: AnalyseRequest):
    """
    Asynchronous RCA — returns a job_id immediately; Celery processes in background.
    Best for: high-load scenarios, dashboards, PagerDuty webhooks.
    Rate limited: 30 requests/minute per IP.
    Requires REDIS_URL to be configured.
    """
    if not _CELERY_OK:
        raise HTTPException(
            status_code=503,
            detail=(
                "Async dispatch not available. "
                "Set REDIS_URL and ensure celery_worker.py is present."
            ),
        )
    try:
        task = run_pipeline_task.delay(
            alert_name   = req.alert_name,
            service      = req.service,
            triggered_at = req.triggered_at,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to queue task: {exc}")
    return AsyncJobResponse(job_id=task.id)


@app.get(
    "/result/{job_id}",
    tags=["core"],
    dependencies=[Depends(require_api_key)],
)
@_rate_limit("100/minute")
def get_result(request: Request, job_id: str):
    """
    Poll Celery task result by job_id.
    Returns status: queued | processing | complete | failed
    Rate limited: 100 requests/minute per IP.
    """
    if not _CELERY_OK:
        raise HTTPException(
            status_code=503,
            detail="Async result lookup not available. REDIS_URL not configured.",
        )
    try:
        result = AsyncResult(job_id)
        state  = result.state
        if state == "PENDING":
            return {"job_id": job_id, "status": "queued"}
        elif state == "STARTED":
            return {"job_id": job_id, "status": "processing"}
        elif state == "SUCCESS":
            return {
                "job_id": job_id,
                "status": "complete",
                "result": result.get(timeout=1),
            }
        elif state == "FAILURE":
            return {
                "job_id": job_id,
                "status": "failed",
                "error":  str(result.info),
            }
        else:
            return {"job_id": job_id, "status": state.lower()}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/history", tags=["ops"], dependencies=[Depends(require_api_key)])
def history(limit: int = 20):
    """
    Return the most recent N analyses from the database.
    Used for dashboards and postmortem feeds.
    """
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=422, detail="limit must be 1–200")
    return {"analyses": get_recent_analyses(limit=limit)}


@app.post("/webhooks/pagerduty", tags=["integrations"])
async def pagerduty_webhook(
    request:          Request,
    background_tasks: BackgroundTasks,
):
    """
    Accepts PagerDuty v3 webhooks.
    - Verifies HMAC-SHA256 signature (if PAGERDUTY_WEBHOOK_SECRET is set).
    - Fires async pipeline task (Celery if available, else BackgroundTask).
    - Only processes incident.triggered events; all others silently ignored.
    - Returns 200 immediately so PagerDuty never retries due to timeout.
    """
    body = await request.body()
    sig  = request.headers.get("X-PagerDuty-Signature", "")

    if not verify_pagerduty_signature(body, sig):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    try:
        payload = PagerDutyWebhook.model_validate_json(body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid PagerDuty payload")

    triggered = [
        msg for msg in payload.messages
        if msg.get("event") == "incident.triggered"
    ]

    if triggered:
        if _CELERY_OK:
            # Preferred: dispatch to Celery for true async processing
            for msg in triggered:
                incident   = msg.get("incident", {})
                alert_name = incident.get("title", "Unknown alert")
                service    = incident.get("service", {}).get("name", "unknown-service")
                run_pipeline_task.delay(alert_name=alert_name, service=service)
        else:
            # Fallback: FastAPI BackgroundTask (blocks a worker thread)
            def _run_analyses():
                for msg in triggered:
                    incident   = msg.get("incident", {})
                    alert_name = incident.get("title", "Unknown alert")
                    service    = incident.get("service", {}).get("name", "unknown-service")
                    try:
                        run_pipeline(alert_name=alert_name, service=service)
                    except Exception as exc:
                        log.error(
                            "Background pipeline failed for '%s': %s", alert_name, exc
                        )
            background_tasks.add_task(_run_analyses)

    return {
        "accepted": len(triggered),
        "ignored":  len(payload.messages) - len(triggered),
        "message":  f"{len(triggered)} incident(s) queued for analysis",
        "mode":     "celery" if _CELERY_OK else "background_task",
    }
