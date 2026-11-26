"""
PULSEAI — Production Incident Intelligence Pipeline  (v4 — production-grade)

Upgrades from v3:
  [DB]         SQLite replaced with PostgreSQL + psycopg2 ThreadedConnectionPool
  [DB]         SQLite graceful fallback when DATABASE_URL is not set (local dev)
  [DB]         Upsert on conflict — safe to replay identical incidents
  [Monitor]    Prometheus metrics: analysis counter, duration histogram,
               error counter, cache hit/miss counter, inflight gauge
  [Health]     check_db_health() used by /health endpoint in server.py
  [Fix]        hmac digestmod is now hashlib.sha256 object (not plain string)
  [Fix]        Model updated to claude-sonnet-4-6
  [Fix]        load_dotenv() added — reads a local .env file automatically
               when running directly (uvicorn/python), not just under Docker
               (where docker-compose injects env vars itself). Real OS-level
               env vars still take priority over anything in .env.
  [Resilience] psycopg2 PoolError caught and surfaced clearly
  [Resilience] Pool connection always returned via finally block
  (All v3 features retained)
"""

import os
import re
import json
import time
import hmac
import signal
import hashlib
import logging
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

import httpx
import boto3
from anthropic import Anthropic

try:
    from dotenv import load_dotenv
    load_dotenv()   # no-op if .env doesn't exist (e.g. inside Docker) or python-dotenv isn't installed
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Prometheus multiprocess directory — must exist BEFORE prometheus_client is
# imported below. If PROMETHEUS_MULTIPROC_DIR is set in the environment (or
# .env), prometheus_client silently switches every metric to file-backed
# mmap storage rooted there — and crashes with FileNotFoundError on the
# very first metric if that directory doesn't exist yet. server.py also
# creates this directory, but that's too late: this module's own metrics
# below are created the moment something does `from pipeline import ...`,
# which happens DURING server.py's import, before server.py's own setup
# code gets a chance to run. This has to happen here, first, regardless of
# which file imports pipeline.py first (server.py, celery_worker.py, tests).
# tempfile.gettempdir() is used instead of a hardcoded "/tmp/..." path so
# this resolves correctly on Windows too, not just Linux/Mac.
# ---------------------------------------------------------------------------
import tempfile as _tempfile
_PROM_MULTIPROC_DIR = os.environ.get(
    "PROMETHEUS_MULTIPROC_DIR",
    os.path.join(_tempfile.gettempdir(), "pulseai_prom"),
)
try:
    os.makedirs(_PROM_MULTIPROC_DIR, exist_ok=True)
    os.environ["PROMETHEUS_MULTIPROC_DIR"] = _PROM_MULTIPROC_DIR
except OSError:
    pass   # if this fails, prometheus_client's own error below will explain why

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("PULSEAI")

# ---------------------------------------------------------------------------
# Prometheus metrics  (optional — degrades gracefully if not installed)
# ---------------------------------------------------------------------------

try:
    from prometheus_client import Counter, Histogram, Gauge, REGISTRY

    def _safe_metric(metric_cls, name, description, labelnames=None, **kwargs):
        """
        Create a Prometheus metric, but reuse the existing collector instead of
        crashing if it's already registered. Without this, re-importing this
        module in the same process — which happens under `uvicorn --reload`,
        pytest test collection, and some Celery prefork edge cases — raises
        ValueError: Duplicated timeseries, taking the whole process down.
        """
        try:
            if labelnames:
                return metric_cls(name, description, labelnames, **kwargs)
            return metric_cls(name, description, **kwargs)
        except ValueError:
            existing = REGISTRY._names_to_collectors.get(name)
            if existing is not None:
                return existing
            raise

    PROM_ANALYSES_TOTAL = _safe_metric(
        Counter, "pulseai_analyses_total", "Total completed analyses",
        ["service", "confidence_bucket"],
    )
    PROM_DURATION_S = _safe_metric(
        Histogram, "pulseai_analysis_duration_seconds",
        "End-to-end pipeline duration in seconds",
        buckets=[5, 10, 20, 30, 45, 60, 90, 120],
    )
    PROM_ERRORS = _safe_metric(
        Counter, "pulseai_pipeline_errors_total", "Pipeline errors by type",
        ["error_type"],
    )
    PROM_CACHE_HITS   = _safe_metric(Counter, "pulseai_cache_hits_total",   "Redis/memory cache hits")
    PROM_CACHE_MISSES = _safe_metric(Counter, "pulseai_cache_misses_total", "Redis/memory cache misses")
    PROM_INFLIGHT     = _safe_metric(Gauge,   "pulseai_inflight_analyses",  "Currently running analyses")
    _PROM_OK = True
    log.info("Prometheus metrics enabled")
except ImportError:
    _PROM_OK = False
    log.warning("prometheus_client not installed — metrics disabled (pip install prometheus-client)")

# ---------------------------------------------------------------------------
# Fail-fast: required secret
# ---------------------------------------------------------------------------

_ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
if not _ANTHROPIC_API_KEY:
    raise EnvironmentError(
        "ANTHROPIC_API_KEY is not set. "
        "Export it before starting: export ANTHROPIC_API_KEY=sk-ant-..."
    )

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DATADOG_API_KEY        = os.environ.get("DATADOG_API_KEY", "")
DATADOG_APP_KEY        = os.environ.get("DATADOG_APP_KEY", "")
GITHUB_TOKEN           = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO            = os.environ.get("GITHUB_REPO", "org/repo")
AWS_REGION             = os.environ.get("AWS_REGION", "us-east-1")
LOG_GROUP              = os.environ.get("CLOUDWATCH_LOG_GROUP", "/ecs/my-service")
SLACK_WEBHOOK_URL      = os.environ.get("SLACK_WEBHOOK_URL", "")
PAGERDUTY_HMAC_SECRET  = os.environ.get("PAGERDUTY_WEBHOOK_SECRET", "")
PULSEAI_API_KEY         = os.environ.get("PULSEAI_API_KEY", "")
# Supports multiple named keys for separate pilot customers, e.g.:
#   PULSEAI_API_KEYS=Vanta:a1b2c3...,Acme Inc:d4e5f6...
# Each customer gets their own key; revoking one doesn't affect the others.
# PULSEAI_API_KEY (singular, above) still works on its own as a simple
# single-key setup — the two are additive, not either/or.
_raw_api_keys = os.environ.get("PULSEAI_API_KEYS", "")
PULSEAI_API_KEYS: dict[str, str] = {}
for _pair in _raw_api_keys.split(","):
    _pair = _pair.strip()
    if not _pair or ":" not in _pair:
        continue
    _name, _key = _pair.split(":", 1)
    PULSEAI_API_KEYS[_key.strip()] = _name.strip()
REDIS_URL              = os.environ.get("REDIS_URL", "")

# Database — prefer PostgreSQL; fall back to SQLite for local dev
DATABASE_URL = os.environ.get("DATABASE_URL", "")
DB_PATH      = os.environ.get("PULSEAI_DB_PATH", "pulseai.db")

# Tuning knobs
LOOKBACK_MINUTES         = 30
MAX_LOG_LINES            = 200
MAX_COMMITS              = 10
MAX_PROMPT_CHARS         = 80_000
ANTHROPIC_TIMEOUT_S      = 30
HTTP_TIMEOUT_S           = 10
HTTP_MAX_RETRIES         = 3
HTTP_RETRY_BASE_S        = 1.0
LOW_CONFIDENCE_THRESHOLD = 40
CACHE_TTL_S              = 300
MAX_ALERT_NAME_LEN       = 500
MAX_SERVICE_NAME_LEN     = 100
HEARTBEAT_INTERVAL_S     = 86_400   # 24 h
DB_POOL_MIN              = 2
DB_POOL_MAX              = 20

# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------

_shutdown_event = threading.Event()
_inflight_lock  = threading.Lock()
_inflight_count = 0


def _on_sigterm(signum, frame):
    log.info("SIGTERM received — waiting for %d in-flight analyses", _inflight_count)
    _shutdown_event.set()
    deadline = time.time() + 60
    while _inflight_count > 0 and time.time() < deadline:
        time.sleep(0.5)
    log.info("Shutdown complete")


signal.signal(signal.SIGTERM, _on_sigterm)


def _incr_inflight():
    global _inflight_count
    with _inflight_lock:
        _inflight_count += 1
    if _PROM_OK:
        PROM_INFLIGHT.inc()


def _decr_inflight():
    global _inflight_count
    with _inflight_lock:
        _inflight_count -= 1
    if _PROM_OK:
        PROM_INFLIGHT.dec()


# ---------------------------------------------------------------------------
# Cache — Redis if available, else in-process dict
# ---------------------------------------------------------------------------

_mem_cache: dict[str, tuple[float, "RootCauseAnalysis"]] = {}
_mem_cache_lock = threading.Lock()
_redis_client   = None

# ---------------------------------------------------------------------------
# Flap-suppression cache — real, bounded noise reduction. The cache above
# only catches byte-identical repeats (same alert_name + same triggered_at).
# This one catches the much more common case: the SAME alert on the SAME
# service firing again a few minutes later because the underlying issue
# hasn't actually been fixed yet ("flapping"). Keyed on alert_name+service
# only (ignoring the timestamp), with its own short TTL — if a match is
# found, the existing analysis is returned instead of re-running the whole
# pipeline and paying for another Claude call to say the same thing again.
# This is intentionally narrow: it does NOT do cross-alert correlation,
# severity-based suppression, or maintenance windows — those are real,
# larger features, not faked here.
# ---------------------------------------------------------------------------

FLAP_SUPPRESSION_WINDOW_S = 300   # 5 minutes

_flap_cache: dict[str, tuple[float, "RootCauseAnalysis"]] = {}
_flap_cache_lock = threading.Lock()


def _flap_key(alert_name: str, service: str) -> str:
    return hashlib.md5(f"{alert_name}|{service}".encode()).hexdigest()[:8]


def _flap_check(alert_name: str, service: str) -> Optional["RootCauseAnalysis"]:
    key = _flap_key(alert_name, service)
    with _flap_cache_lock:
        entry = _flap_cache.get(key)
        if entry:
            ts, rca = entry
            if time.time() - ts < FLAP_SUPPRESSION_WINDOW_S:
                return rca
            del _flap_cache[key]
    return None


def _flap_record(alert_name: str, service: str, rca: "RootCauseAnalysis"):
    key = _flap_key(alert_name, service)
    with _flap_cache_lock:
        _flap_cache[key] = (time.time(), rca)


def _init_redis():
    global _redis_client
    if not REDIS_URL:
        return
    try:
        import redis as redis_lib
        client = redis_lib.from_url(REDIS_URL, decode_responses=True, socket_timeout=2)
        client.ping()
        _redis_client = client
        log.info("Redis cache connected at %s", REDIS_URL)
    except Exception as exc:
        log.warning("Redis unavailable (%s) — using in-process cache", exc)
        _redis_client = None


def _cache_get(key: str) -> Optional["RootCauseAnalysis"]:
    if _redis_client:
        try:
            raw = _redis_client.get(f"pulseai:{key}")
            if raw:
                if _PROM_OK:
                    PROM_CACHE_HITS.inc()
                d = json.loads(raw)
                return RootCauseAnalysis(**d)
        except Exception:
            pass
    with _mem_cache_lock:
        entry = _mem_cache.get(key)
        if entry:
            ts, rca = entry
            if time.time() - ts < CACHE_TTL_S:
                if _PROM_OK:
                    PROM_CACHE_HITS.inc()
                return rca
            del _mem_cache[key]
    if _PROM_OK:
        PROM_CACHE_MISSES.inc()
    return None


def _cache_set(key: str, rca: "RootCauseAnalysis"):
    if _redis_client:
        try:
            _redis_client.setex(f"pulseai:{key}", CACHE_TTL_S, json.dumps(asdict(rca)))
            return
        except Exception:
            pass
    with _mem_cache_lock:
        _mem_cache[key] = (time.time(), rca)


# ---------------------------------------------------------------------------
# Database persistence — PostgreSQL primary, SQLite fallback
# ---------------------------------------------------------------------------

try:
    import psycopg2
    from psycopg2 import pool as _pg_pool_module
    from psycopg2 import OperationalError as PgOperationalError
    _PSYCOPG2_OK = True
except ImportError:
    _PSYCOPG2_OK = False
    log.warning("psycopg2 not installed — PostgreSQL unavailable; using SQLite fallback")

_pg_pool: Optional[object] = None          # psycopg2.pool.ThreadedConnectionPool
_db_mode: str               = "none"       # "postgres" | "sqlite" | "none"
_db_init_lock               = threading.Lock()

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS analyses (
    incident_id       TEXT PRIMARY KEY,
    alert_name        TEXT     NOT NULL,
    service           TEXT     NOT NULL,
    triggered_at      TEXT,
    generated_at      TEXT,
    confidence        INTEGER,
    summary           TEXT,
    root_cause        TEXT,
    implicated_commit TEXT,
    fixes_json        TEXT,
    input_tokens      INTEGER  DEFAULT 0,
    output_tokens     INTEGER  DEFAULT 0
)
"""


def _init_postgres() -> bool:
    """
    Initialize PostgreSQL connection pool.
    Returns True on success, False if unavailable.
    """
    global _pg_pool, _db_mode
    if not _PSYCOPG2_OK or not DATABASE_URL:
        return False
    try:
        pool = _pg_pool_module.ThreadedConnectionPool(
            minconn=DB_POOL_MIN,
            maxconn=DB_POOL_MAX,
            dsn=DATABASE_URL,
            connect_timeout=5,
        )
        conn = pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(_CREATE_TABLE_SQL)
            conn.commit()
        finally:
            pool.putconn(conn)
        _pg_pool = pool
        _db_mode = "postgres"
        log.info("PostgreSQL pool ready (min=%d max=%d)", DB_POOL_MIN, DB_POOL_MAX)
        return True
    except Exception as exc:
        log.error("PostgreSQL init failed (%s) — falling back to SQLite", exc)
        return False


_sqlite_initialised = False


def _init_sqlite():
    """Initialize SQLite fallback."""
    global _sqlite_initialised, _db_mode
    if _sqlite_initialised:
        return
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(_CREATE_TABLE_SQL)
        conn.commit()
        conn.close()
        _sqlite_initialised = True
        _db_mode = "sqlite"
        log.info("SQLite DB ready at %s (fallback mode)", DB_PATH)
    except Exception as exc:
        log.error("SQLite init failed: %s", exc)


def _init_db():
    """Initialize the best available database (call once at startup)."""
    global _db_mode
    with _db_init_lock:
        if _db_mode != "none":
            return
        if not _init_postgres():
            _init_sqlite()


def _persist_rca(rca: "RootCauseAnalysis", alert_name: str, service: str, triggered_at: str):
    _init_db()
    values = (
        rca.incident_id, alert_name, service, triggered_at,
        rca.generated_at, rca.confidence, rca.summary,
        rca.root_cause, rca.implicated_commit,
        json.dumps(rca.fixes), rca.input_tokens, rca.output_tokens,
    )
    if _db_mode == "postgres":
        conn = None
        try:
            conn = _pg_pool.getconn()
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO analyses VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (incident_id) DO UPDATE SET
                        generated_at      = EXCLUDED.generated_at,
                        confidence        = EXCLUDED.confidence,
                        summary           = EXCLUDED.summary,
                        root_cause        = EXCLUDED.root_cause,
                        implicated_commit = EXCLUDED.implicated_commit,
                        fixes_json        = EXCLUDED.fixes_json,
                        input_tokens      = EXCLUDED.input_tokens,
                        output_tokens     = EXCLUDED.output_tokens
                """, values)
            conn.commit()
        except _pg_pool_module.PoolError:
            log.error("PG pool exhausted — RCA %s not persisted", rca.incident_id)
        except Exception as exc:
            log.warning("PostgreSQL persist failed: %s", exc)
            if conn:
                conn.rollback()
        finally:
            if conn and _pg_pool:
                _pg_pool.putconn(conn)

    elif _db_mode == "sqlite":
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute(
                "INSERT OR REPLACE INTO analyses VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", values
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            log.warning("SQLite persist failed: %s", exc)


def get_recent_analyses(limit: int = 20) -> list[dict]:
    """Return the most recent N analyses. Used by /history endpoint."""
    _init_db()
    cols = [
        "incident_id", "alert_name", "service", "triggered_at", "generated_at",
        "confidence", "summary", "root_cause", "implicated_commit",
        "fixes_json", "input_tokens", "output_tokens",
    ]
    if _db_mode == "postgres":
        conn = None
        try:
            conn = _pg_pool.getconn()
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM analyses ORDER BY generated_at DESC LIMIT %s",
                    (limit,),
                )
                rows = cur.fetchall()
            return [dict(zip(cols, row)) for row in rows]
        except Exception as exc:
            log.error("get_recent_analyses (PG) failed: %s", exc)
            return []
        finally:
            if conn and _pg_pool:
                _pg_pool.putconn(conn)
    elif _db_mode == "sqlite":
        try:
            conn = sqlite3.connect(DB_PATH)
            rows = conn.execute(
                "SELECT * FROM analyses ORDER BY generated_at DESC LIMIT ?", (limit,)
            ).fetchall()
            conn.close()
            return [dict(zip(cols, row)) for row in rows]
        except Exception:
            return []
    return []


def check_db_health() -> dict:
    """
    Run a lightweight ping against the active database.
    Returns {"status": "ok"|"error", "mode": "postgresql"|"sqlite"|"none"}.
    Used by the /health endpoint in server.py.
    """
    _init_db()
    if _db_mode == "postgres":
        conn = None
        try:
            conn = _pg_pool.getconn()
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
            return {"status": "ok", "mode": "postgresql"}
        except Exception as exc:
            return {"status": "error", "mode": "postgresql", "detail": str(exc)}
        finally:
            if conn and _pg_pool:
                _pg_pool.putconn(conn)
    elif _db_mode == "sqlite":
        try:
            conn = sqlite3.connect(DB_PATH, timeout=3)
            conn.execute("SELECT 1")
            conn.close()
            return {"status": "ok", "mode": "sqlite"}
        except Exception as exc:
            return {"status": "error", "mode": "sqlite", "detail": str(exc)}
    return {"status": "not_initialised", "mode": "none"}


MAX_PAST_INCIDENTS = 3   # how many prior analyses for this service to show Claude


def get_similar_past_incidents(service: str, exclude_incident_id: str = "", limit: int = MAX_PAST_INCIDENTS) -> list[dict]:
    """
    Incident memory — returns the most recent past analyses for this SAME
    service, most recent first. This is the "quick" version: matching is
    by exact service name only, not cross-service semantic similarity, and
    there's no feedback loop on whether a past suggested fix actually
    worked. Both of those are real, larger features for later, not faked
    here — this just gives Claude visibility into what's happened on this
    service before, which it previously had zero access to.
    """
    _init_db()
    cols = [
        "incident_id", "alert_name", "service", "triggered_at", "generated_at",
        "confidence", "summary", "root_cause", "implicated_commit",
        "fixes_json", "input_tokens", "output_tokens",
    ]
    rows: list[tuple] = []
    if _db_mode == "postgres":
        conn = None
        try:
            conn = _pg_pool.getconn()
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM analyses WHERE service = %s AND incident_id != %s "
                    "ORDER BY generated_at DESC LIMIT %s",
                    (service, exclude_incident_id, limit),
                )
                rows = cur.fetchall()
        except Exception as exc:
            log.warning("get_similar_past_incidents (PG) failed: %s", exc)
            return []
        finally:
            if conn and _pg_pool:
                _pg_pool.putconn(conn)
    elif _db_mode == "sqlite":
        try:
            conn = sqlite3.connect(DB_PATH)
            rows = conn.execute(
                "SELECT * FROM analyses WHERE service = ? AND incident_id != ? "
                "ORDER BY generated_at DESC LIMIT ?",
                (service, exclude_incident_id, limit),
            ).fetchall()
            conn.close()
        except Exception as exc:
            log.warning("get_similar_past_incidents (SQLite) failed: %s", exc)
            return []
    return [dict(zip(cols, row)) for row in rows]


# ---------------------------------------------------------------------------
# Heartbeat — warns if no analysis runs in 24 hours
# ---------------------------------------------------------------------------

_last_analysis_ts = time.time()


def _heartbeat_worker():
    while not _shutdown_event.wait(timeout=HEARTBEAT_INTERVAL_S):
        elapsed = time.time() - _last_analysis_ts
        if elapsed > HEARTBEAT_INTERVAL_S:
            log.warning(
                "PULSEAI_HEARTBEAT_WARN no analysis in %.1f hours — "
                "pipeline may be broken or no incidents firing",
                elapsed / 3600,
            )
        else:
            log.info("PULSEAI_HEARTBEAT ok — last analysis %.0f min ago", elapsed / 60)


threading.Thread(target=_heartbeat_worker, daemon=True, name="heartbeat").start()


# ---------------------------------------------------------------------------
# Per-incident locks — prevents "cache stampede" on concurrent identical
# requests. Without this, N concurrent requests for the SAME incident_id
# (e.g. duplicate PagerDuty webhook deliveries, which are common in
# practice) all miss the empty cache simultaneously and each fire a separate
# Claude API call, multiplying cost and load. With the lock, only the first
# caller does the real work; the rest wait briefly then read its result.
# ---------------------------------------------------------------------------

_incident_locks: dict[str, threading.Lock] = {}
_incident_locks_guard = threading.Lock()
_INCIDENT_LOCKS_MAX = 10_000   # soft cap to bound long-term memory growth


def _get_incident_lock(incident_id: str) -> threading.Lock:
    with _incident_locks_guard:
        if len(_incident_locks) > _INCIDENT_LOCKS_MAX:
            # Periodic cleanup. Safe under concurrency: clearing only risks
            # missing a dedup opportunity for whatever is in-flight at this
            # exact instant, never incorrect data, since the cache check
            # after acquiring the (possibly new) lock object is unaffected.
            _incident_locks.clear()
        return _incident_locks.setdefault(incident_id, threading.Lock())


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Metric:
    name: str
    value: float
    unit: str
    timestamp: str


@dataclass
class LogLine:
    timestamp: str
    level: str
    message: str
    service: str = ""


@dataclass
class Commit:
    sha: str
    author: str
    message: str
    timestamp: str
    files_changed: list[str] = field(default_factory=list)


@dataclass
class IncidentContext:
    incident_id: str
    alert_name: str
    triggered_at: str
    service: str
    metrics: list[Metric]         = field(default_factory=list)
    logs: list[LogLine]           = field(default_factory=list)
    recent_commits: list[Commit]  = field(default_factory=list)
    past_incidents: list[dict]    = field(default_factory=list)


@dataclass
class RootCauseAnalysis:
    incident_id: str
    summary: str
    root_cause: str
    confidence: int
    fixes: list[dict]
    implicated_commit: Optional[str]
    generated_at: str
    input_tokens: int  = 0
    output_tokens: int = 0


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def validate_inputs(alert_name: str, service: str):
    """Raise ValueError if inputs are unsafe or exceed limits."""
    if not alert_name or not alert_name.strip():
        raise ValueError("alert_name must not be empty")
    if len(alert_name) > MAX_ALERT_NAME_LEN:
        raise ValueError(f"alert_name too long (max {MAX_ALERT_NAME_LEN} chars)")
    if not service or not service.strip():
        raise ValueError("service must not be empty")
    if len(service) > MAX_SERVICE_NAME_LEN:
        raise ValueError(f"service name too long (max {MAX_SERVICE_NAME_LEN} chars)")
    if "\x00" in alert_name or "\x00" in service:
        raise ValueError("null bytes not allowed in inputs")


# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

def _redact_secrets(text: str) -> str:
    for s in [DATADOG_API_KEY, DATADOG_APP_KEY, GITHUB_TOKEN,
              _ANTHROPIC_API_KEY, PULSEAI_API_KEY]:
        if s:
            text = text.replace(s, "***REDACTED***")
    return text


def _sanitise_log_content(raw: str) -> str:
    cleaned = re.sub(r"[\r\n]+", " ", raw)
    for marker in ("IGNORE PREVIOUS", "IGNORE ALL", "SYSTEM:", "USER:", "ASSISTANT:"):
        cleaned = re.sub(re.escape(marker), "[REDACTED]", cleaned, flags=re.IGNORECASE)
    return cleaned


def verify_pagerduty_signature(body: bytes, signature_header: str) -> bool:
    """
    Verify PagerDuty v3 webhook HMAC-SHA256 signature.
    Header format: v1=<hex_digest>
    Returns True if valid, or if PAGERDUTY_WEBHOOK_SECRET is not configured.
    """
    if not PAGERDUTY_HMAC_SECRET:
        log.warning("PAGERDUTY_WEBHOOK_SECRET not set — skipping signature verification")
        return True
    if not signature_header:
        log.warning("Missing X-PagerDuty-Signature header — rejecting webhook")
        return False
    try:
        parts    = dict(p.split("=", 1) for p in signature_header.split(",") if "=" in p)
        expected = hmac.new(
            PAGERDUTY_HMAC_SECRET.encode(),
            body,
            hashlib.sha256,           # ← FIX: use hashlib.sha256 object, not string "sha256"
        ).hexdigest()
        return hmac.compare_digest(parts.get("v1", ""), expected)
    except Exception as exc:
        log.error("Signature verification error: %s", exc)
        return False


# ---------------------------------------------------------------------------
# HTTP helper — retry with exponential back-off
# ---------------------------------------------------------------------------

def _http_get_with_retry(
    url: str, *, headers: dict, params: dict | None = None
) -> httpx.Response:
    delay    = HTTP_RETRY_BASE_S
    last_exc: Exception | None = None
    for attempt in range(1, HTTP_MAX_RETRIES + 1):
        try:
            resp = httpx.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT_S)
            if resp.status_code == 429 or resp.status_code >= 500:
                raise httpx.HTTPStatusError(
                    f"HTTP {resp.status_code}", request=resp.request, response=resp
                )
            resp.raise_for_status()
            return resp
        except Exception as exc:
            last_exc = exc
            safe_msg = _redact_secrets(str(exc))
            if attempt < HTTP_MAX_RETRIES:
                log.warning(
                    "Attempt %d/%d failed (%s) — retrying in %.1fs",
                    attempt, HTTP_MAX_RETRIES, safe_msg, delay,
                )
                time.sleep(delay)
                delay *= 2
            else:
                log.error("All %d attempts failed: %s", HTTP_MAX_RETRIES, safe_msg)
    raise RuntimeError(_redact_secrets(str(last_exc))) from last_exc


# ---------------------------------------------------------------------------
# Ingestion: Datadog
# ---------------------------------------------------------------------------

def fetch_datadog_metrics(
    service: str, lookback_minutes: int = LOOKBACK_MINUTES
) -> list[Metric]:
    if not DATADOG_API_KEY:
        log.warning("DATADOG_API_KEY not set — skipping Datadog metrics")
        return []
    now  = int(datetime.now(timezone.utc).timestamp())
    then = now - lookback_minutes * 60
    headers = {
        "DD-API-KEY":         DATADOG_API_KEY,
        "DD-APPLICATION-KEY": DATADOG_APP_KEY,
    }
    queries = [
        f"avg:trace.web.request.errors{{service:{service}}}",
        f"avg:trace.web.request.duration{{service:{service}}}",
        f"avg:system.cpu.user{{service:{service}}}",
        f"avg:system.mem.used{{service:{service}}}",
    ]
    metrics: list[Metric] = []
    for query in queries:
        try:
            resp = _http_get_with_retry(
                "https://api.datadoghq.com/api/v1/query",
                headers=headers,
                params={"from": then, "to": now, "query": query},
            )
            for series in resp.json().get("series", []):
                pointlist = series.get("pointlist", [])
                if pointlist:
                    latest_ts, latest_val = pointlist[-1]
                    metrics.append(Metric(
                        name=series.get("metric", query),
                        value=round(latest_val, 4) if latest_val is not None else 0.0,
                        unit=series.get("unit", [{}])[0].get("name", ""),
                        timestamp=datetime.fromtimestamp(
                            latest_ts / 1000, tz=timezone.utc
                        ).isoformat(),
                    ))
        except Exception as exc:
            log.error(
                "Datadog query failed for '%s': %s",
                query, _redact_secrets(str(exc)),
            )
    log.info("Fetched %d metrics from Datadog", len(metrics))
    return metrics


# ---------------------------------------------------------------------------
# Ingestion: CloudWatch (with pagination)
# ---------------------------------------------------------------------------

def fetch_cloudwatch_logs(
    log_group: str = LOG_GROUP,
    lookback_minutes: int = LOOKBACK_MINUTES,
    max_lines: int = MAX_LOG_LINES,
) -> list[LogLine]:
    try:
        client = boto3.client("logs", region_name=AWS_REGION)
    except Exception as exc:
        log.warning("Could not create CloudWatch client: %s", _redact_secrets(str(exc)))
        return []
    end_ms   = int(datetime.now(timezone.utc).timestamp() * 1000)
    start_ms = end_ms - lookback_minutes * 60 * 1000
    raw_events: list[dict] = []
    kwargs: dict = dict(
        logGroupName=log_group,
        startTime=start_ms,
        endTime=end_ms,
        filterPattern='?"ERROR" ?"WARN" ?"Exception" ?"panic" ?"fatal"',
        limit=min(max_lines, 10_000),
    )
    try:
        while len(raw_events) < max_lines:
            response = client.filter_log_events(**kwargs)
            raw_events.extend(response.get("events", []))
            next_token = response.get("nextToken")
            if not next_token:
                break
            kwargs["nextToken"] = next_token
    except Exception as exc:
        safe = _redact_secrets(str(exc))
        if "ResourceNotFoundException" in safe:
            log.warning("Log group '%s' not found", log_group)
        else:
            log.error("CloudWatch query failed: %s", safe)
        return []
    lines: list[LogLine] = []
    for event in raw_events[:max_lines]:
        raw  = event.get("message", "").strip()
        ts   = datetime.fromtimestamp(
            event["timestamp"] / 1000, tz=timezone.utc
        ).isoformat()
        level = "INFO"
        for lvl in ("CRITICAL", "ERROR", "WARN", "DEBUG"):
            if lvl in raw.upper():
                level = lvl
                break
        lines.append(LogLine(
            timestamp=ts, level=level,
            message=_sanitise_log_content(raw[:500]),
        ))
    log.info("Fetched %d log lines from CloudWatch", len(lines))
    return lines


# ---------------------------------------------------------------------------
# Ingestion: GitHub
# ---------------------------------------------------------------------------

def fetch_recent_commits(
    repo: str = GITHUB_REPO,
    max_commits: int = MAX_COMMITS,
    lookback_hours: int = 6,
) -> list[Commit]:
    if not GITHUB_TOKEN:
        log.warning("GITHUB_TOKEN not set — skipping commit correlation")
        return []
    since   = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).isoformat()
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
    }
    try:
        resp = _http_get_with_retry(
            f"https://api.github.com/repos/{repo}/commits",
            headers=headers,
            params={"since": since, "per_page": max_commits},
        )
    except Exception as exc:
        log.error("GitHub API failed: %s", _redact_secrets(str(exc)))
        return []
    commits: list[Commit] = []
    for item in resp.json():
        sha     = item["sha"][:8]
        author  = item.get("commit", {}).get("author", {}).get("name", "unknown")
        message = item.get("commit", {}).get("message", "").split("\n")[0][:120]
        ts      = item.get("commit", {}).get("author", {}).get("date", "")
        files_changed: list[str] = []
        try:
            detail = _http_get_with_retry(
                f"https://api.github.com/repos/{repo}/commits/{item['sha']}",
                headers=headers,
            )
            files_changed = [f["filename"] for f in detail.json().get("files", [])[:10]]
        except Exception:
            pass
        commits.append(Commit(
            sha=sha, author=author, message=message,
            timestamp=ts, files_changed=files_changed,
        ))
    log.info("Fetched %d commits from GitHub", len(commits))
    return commits


# ---------------------------------------------------------------------------
# Slack notification
# ---------------------------------------------------------------------------

def _post_slack_notification(rca: "RootCauseAnalysis", service: str):
    """Post a compact RCA summary to Slack. Silently skips if no webhook configured."""
    if not SLACK_WEBHOOK_URL:
        return
    color   = "#27500A" if rca.confidence >= 70 else "#633806" if rca.confidence >= 40 else "#791F1F"
    top_fix = rca.fixes[0] if rca.fixes else {}
    payload = {
        "attachments": [{
            "color": color,
            "title": f"PULSEAI — {service} incident {rca.incident_id}",
            "text":  rca.summary,
            "fields": [
                {"title": "Root cause",  "value": rca.root_cause, "short": False},
                {"title": "Confidence",  "value": f"{rca.confidence}%", "short": True},
                {"title": "Implicated commit",
                 "value": rca.implicated_commit or "None identified", "short": True},
                {"title": "Top fix",
                 "value": (
                     f"#{top_fix.get('rank',1)} "
                     f"({top_fix.get('confidence',0)}%) "
                     f"{top_fix.get('action','')}"
                 ), "short": False},
            ],
            "footer": "PULSEAI",
            "ts": int(datetime.now(timezone.utc).timestamp()),
        }]
    }
    try:
        httpx.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
        log.info("Slack notification posted for incident %s", rca.incident_id)
    except Exception as exc:
        log.warning("Slack notification failed: %s", exc)


# ---------------------------------------------------------------------------
# Claude analysis
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """
You are PULSEAI, an expert Site Reliability Engineer with deep expertise in
distributed systems, cloud infrastructure, and incident response.

When given an incident context (alert name, service, metrics, log lines,
recent commits, and any past incidents on this same service), you must:
1. Identify the most likely root cause with reasoning.
2. Assess whether any recent commit is implicated (be specific about SHA and files).
3. If past incidents on this service are provided, explicitly note whether
   this looks like a recurrence of a known issue, and whether a previously
   suggested fix may not have actually been applied.
4. Provide 3 ranked fix suggestions, each with an estimated confidence (0-100%).
5. Keep your tone direct and actionable — engineers are reading this during an outage.

Respond ONLY with valid JSON matching this exact schema (no markdown fences):
{
  "summary": "<1-sentence incident summary>",
  "root_cause": "<2-4 sentence root cause explanation>",
  "confidence": <integer 0-100>,
  "implicated_commit": "<SHA + author + message, or null>",
  "fixes": [
    {"rank": 1, "action": "<short action title>", "confidence": <int>, "detail": "<how to do it>"},
    {"rank": 2, "action": "<short action title>", "confidence": <int>, "detail": "<how to do it>"},
    {"rank": 3, "action": "<short action title>", "confidence": <int>, "detail": "<how to do it>"}
  ]
}
""".strip()


def _build_user_message(ctx: IncidentContext) -> str:
    parts = [
        f"INCIDENT: {ctx.alert_name}",
        f"SERVICE:  {ctx.service}",
        f"TRIGGERED AT: {ctx.triggered_at}",
        "",
    ]
    if ctx.metrics:
        parts.append("=== METRICS (latest values) ===")
        for m in ctx.metrics:
            parts.append(f"  {m.name}: {m.value} {m.unit}  @ {m.timestamp}")
        parts.append("")
    if ctx.logs:
        parts.append(f"=== LOGS (last {len(ctx.logs)} lines) ===")
        for line in ctx.logs[-MAX_LOG_LINES:]:
            parts.append(f"  [{line.level}] {line.timestamp}  {line.message}")
        parts.append("")
    if ctx.recent_commits:
        parts.append(f"=== RECENT COMMITS (last {len(ctx.recent_commits)}, past 6 hours) ===")
        for c in ctx.recent_commits:
            files = ", ".join(c.files_changed[:5]) or "—"
            parts.append(f"  [{c.sha}] {c.author}: {c.message}")
            parts.append(f"    changed: {files}")
            parts.append(f"    at: {c.timestamp}")
        parts.append("")
    if ctx.past_incidents:
        parts.append(f"=== PAST INCIDENTS ON {ctx.service} (most recent {len(ctx.past_incidents)}) ===")
        parts.append("This service has had prior incidents. Use these for context — if the "
                      "same pattern is recurring, say so explicitly and note whether a "
                      "previously suggested fix may not have actually been applied.")
        for p in ctx.past_incidents:
            parts.append(f"  [{p.get('generated_at', '?')}] {p.get('alert_name', '?')}")
            parts.append(f"    root cause: {p.get('root_cause', '?')}")
            parts.append(f"    confidence: {p.get('confidence', '?')}%")
        parts.append("")
    parts.append("Analyse and return the JSON root cause analysis now.")
    msg = "\n".join(parts)
    if len(msg) > MAX_PROMPT_CHARS:
        log.warning(
            "Prompt too large (%d chars) — truncating to %d", len(msg), MAX_PROMPT_CHARS
        )
        msg = (
            msg[:MAX_PROMPT_CHARS]
            + "\n\n[TRUNCATED]\nAnalyse and return the JSON root cause analysis now."
        )
    log.info("Prompt size: %d chars (~%d tokens)", len(msg), len(msg) // 4)
    return msg


def analyse_incident(ctx: IncidentContext) -> RootCauseAnalysis:
    client   = Anthropic(timeout=ANTHROPIC_TIMEOUT_S)
    user_msg = _build_user_message(ctx)
    log.info("Sending incident '%s' to Claude", ctx.alert_name)
    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",     # ← updated from claude-sonnet-4-20250514
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )
    except Exception as exc:
        if _PROM_OK:
            PROM_ERRORS.labels(error_type="claude_api").inc()
        # Log the full detail server-side BEFORE redacting/wrapping it for
        # the client response — otherwise a failed Claude call only ever
        # shows "400 Bad Request" in the terminal with no explanation of
        # why, and the real reason is only visible in the browser's network
        # tab on the machine that happened to make the request.
        log.error("Claude API call failed: %s", _redact_secrets(str(exc)))
        raise RuntimeError(_redact_secrets(str(exc))) from exc

    raw_text = response.content[0].text.strip()
    # Strip markdown fences if Claude wraps its JSON
    if raw_text.startswith("```"):
        raw_text = raw_text.split("```")[1]
        if raw_text.startswith("json"):
            raw_text = raw_text[4:]
    raw_text = raw_text.strip()

    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        log.error("Claude returned non-JSON: %s\n\nRaw:\n%s", exc, raw_text[:500])
        if _PROM_OK:
            PROM_ERRORS.labels(error_type="json_parse").inc()
        raise

    in_tok  = getattr(response.usage, "input_tokens",  0)
    out_tok = getattr(response.usage, "output_tokens", 0)
    cost    = (in_tok * 3 + out_tok * 15) / 1_000_000
    log.info("Claude usage: %d in + %d out tokens (~$%.4f)", in_tok, out_tok, cost)

    rca = RootCauseAnalysis(
        incident_id       = ctx.incident_id,
        summary           = parsed.get("summary", ""),
        root_cause        = parsed.get("root_cause", ""),
        confidence        = parsed.get("confidence", 0),
        fixes             = parsed.get("fixes", []),
        implicated_commit = parsed.get("implicated_commit"),
        generated_at      = datetime.now(timezone.utc).isoformat(),
        input_tokens      = in_tok,
        output_tokens     = out_tok,
    )
    if rca.confidence < LOW_CONFIDENCE_THRESHOLD:
        log.warning(
            "Low-confidence analysis (confidence=%d%%) for incident %s",
            rca.confidence, rca.incident_id,
        )
    return rca


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_pipeline(
    alert_name: str,
    service: str,
    triggered_at: Optional[str] = None,
) -> RootCauseAnalysis:
    """
    Full pipeline: validate → cache check → parallel ingest →
    Claude analysis → persist → cache write → Slack notify.
    """
    validate_inputs(alert_name, service)

    if triggered_at is None:
        triggered_at = datetime.now(timezone.utc).isoformat()

    incident_id = hashlib.md5(f"{alert_name}{triggered_at}".encode()).hexdigest()[:8]

    # Cache check — skip Claude call if we already have the result
    cached = _cache_get(incident_id)
    if cached:
        log.info("Cache hit for incident %s — skipping Claude call", incident_id)
        return cached

    # Flap-suppression check — same alert+service fired again recently.
    # This is a DIFFERENT check from the exact-match cache above: that one
    # matches on alert_name + triggered_at (catches byte-identical retries),
    # this one matches on alert_name + service only (catches the same issue
    # recurring with a new timestamp a few minutes later).
    flap_hit = _flap_check(alert_name, service)
    if flap_hit:
        log.info(
            "PULSEAI_FLAP_SUPPRESSED alert=%r service=%r — same alert fired again "
            "within %ds, returning existing analysis instead of re-running",
            alert_name, service, FLAP_SUPPRESSION_WINDOW_S,
        )
        return flap_hit

    if _shutdown_event.is_set():
        raise RuntimeError("Server is shutting down — not accepting new analyses")

    # Acquire this incident's lock before doing the expensive work. If
    # another thread is already processing the SAME incident_id (e.g. two
    # near-simultaneous webhook deliveries for the same alert), this call
    # blocks here instead of starting a redundant, costly Claude call.
    lock = _get_incident_lock(incident_id)
    with lock:
        # Re-check the cache now that we hold the lock — the thread that
        # was ahead of us may have just finished and populated it.
        cached = _cache_get(incident_id)
        if cached:
            log.info(
                "Cache hit for incident %s after lock wait — avoided duplicate Claude call",
                incident_id,
            )
            return cached

        log.info("=== PULSEAI pipeline starting — incident %s ===", incident_id)
        t_start = time.time()
        _incr_inflight()

        try:
            # Parallel data ingestion from all three sources
            with ThreadPoolExecutor(max_workers=3) as pool:
                f_metrics = pool.submit(fetch_datadog_metrics, service)
                f_logs    = pool.submit(fetch_cloudwatch_logs)
                f_commits = pool.submit(fetch_recent_commits)
                metrics = f_metrics.result()
                logs    = f_logs.result()
                commits = f_commits.result()

            # Incident memory — look up past analyses for this same service
            # so Claude has visibility into whether this is a recurrence.
            past_incidents = get_similar_past_incidents(service, exclude_incident_id=incident_id)

            ctx = IncidentContext(
                incident_id    = incident_id,
                alert_name     = alert_name,
                triggered_at   = triggered_at,
                service        = service,
                metrics        = metrics,
                logs           = logs,
                recent_commits = commits,
                past_incidents = past_incidents,
            )

            rca      = analyse_incident(ctx)
            duration = time.time() - t_start

            # Prometheus metrics
            if _PROM_OK:
                bucket = (
                    "high"   if rca.confidence >= 70 else
                    "medium" if rca.confidence >= 40 else
                    "low"
                )
                PROM_ANALYSES_TOTAL.labels(service=service, confidence_bucket=bucket).inc()
                PROM_DURATION_S.observe(duration)

            log.info(
                "PULSEAI_ANALYSIS incident_id=%s service=%s confidence=%d "
                "duration_ms=%d input_tokens=%d output_tokens=%d "
                "metrics=%d logs=%d commits=%d",
                rca.incident_id, service, rca.confidence,
                int(duration * 1000),
                rca.input_tokens, rca.output_tokens,
                len(metrics), len(logs), len(commits),
            )

            _cache_set(incident_id, rca)
            _flap_record(alert_name, service, rca)
            _persist_rca(rca, alert_name, service, triggered_at)
            _post_slack_notification(rca, service)

            global _last_analysis_ts
            _last_analysis_ts = time.time()

            return rca

        except Exception as exc:
            if _PROM_OK:
                PROM_ERRORS.labels(error_type="pipeline").inc()
            raise

        finally:
            _decr_inflight()


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

def startup():
    """Call once at server start (lifespan hook in server.py)."""
    _init_redis()
    _init_db()
    if not PULSEAI_API_KEY:
        log.warning(
            "PULSEAI_API_KEY not set — /analyse and /history are unprotected! "
            "Set this env var before deploying to production."
        )
    log.info("PULSEAI pipeline startup complete (db_mode=%s)", _db_mode)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    startup()
    alert   = sys.argv[1] if len(sys.argv) > 1 else "High error rate on /api/checkout"
    service = sys.argv[2] if len(sys.argv) > 2 else "checkout-service"
    rca     = run_pipeline(alert_name=alert, service=service)
    print("\n" + "=" * 60)
    print("ROOT CAUSE ANALYSIS")
    print("=" * 60)
    print(json.dumps(asdict(rca), indent=2))
