"""
PULSEAI — Gunicorn configuration (production)

Usage:
    gunicorn server:app \\
        --worker-class uvicorn.workers.UvicornWorker \\
        --config gunicorn_conf.py

All settings can be overridden via environment variables.
"""

import multiprocessing
import os

# ---------------------------------------------------------------------------
# Workers
# ---------------------------------------------------------------------------

# Standard recommendation: 2 × CPU + 1
# Override with GUNICORN_WORKERS env var (e.g. set to 1 for low-RAM containers)
workers = int(os.environ.get("GUNICORN_WORKERS", multiprocessing.cpu_count() * 2 + 1))

# Use Uvicorn's async worker — required for FastAPI
worker_class = "uvicorn.workers.UvicornWorker"

# Threads per worker (UvicornWorker ignores this, but set for safety)
threads = 1

# ---------------------------------------------------------------------------
# Binding
# ---------------------------------------------------------------------------

bind = os.environ.get("GUNICORN_BIND", "0.0.0.0:8000")

# ---------------------------------------------------------------------------
# Timeouts
# ---------------------------------------------------------------------------

# Kill a worker if it doesn't respond in 90s (pipeline can take up to 60s)
timeout             = 90

# Graceful timeout — wait this long for in-flight requests before SIGKILL
graceful_timeout    = 30

# Keep-alive — seconds to wait for next request on a keep-alive connection
keepalive           = 5

# ---------------------------------------------------------------------------
# Process naming
# ---------------------------------------------------------------------------

proc_name  = "pulseai"
default_proc_name = "pulseai"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

loglevel     = os.environ.get("LOG_LEVEL", "info")
accesslog    = "-"    # stdout
errorlog     = "-"    # stderr
access_log_format = (
    '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s '
    '"%(f)s" "%(a)s" %(D)sµs'
)

# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

# Limit request line size to 8 KB
limit_request_line   = 8190
limit_request_fields = 100

# ---------------------------------------------------------------------------
# Prometheus multiprocess — must set before workers fork
# ---------------------------------------------------------------------------

prom_dir = os.environ.get("PROMETHEUS_MULTIPROC_DIR", "/tmp/pulseai_prom")

def on_starting(server):
    """Called just before the master process is initialized."""
    import os
    os.makedirs(prom_dir, exist_ok=True)
    os.environ["PROMETHEUS_MULTIPROC_DIR"] = prom_dir
    server.log.info("PULSEAI master starting — %d workers", workers)


def post_fork(server, worker):
    """Called in each worker after fork."""
    # Each worker needs its own Prometheus files directory
    os.environ["PROMETHEUS_MULTIPROC_DIR"] = prom_dir
    server.log.info("Worker %s forked (pid=%s)", worker.age, worker.pid)


def worker_exit(server, worker):
    """Called just before a worker exits — cleans up Prometheus files."""
    try:
        from prometheus_client import multiprocess
        multiprocess.mark_process_dead(worker.pid)
    except Exception:
        pass


def on_exit(server):
    """Called just before the master exits."""
    server.log.info("PULSEAI master shutting down")
