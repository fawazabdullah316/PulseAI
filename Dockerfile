# ─── Stage 1: build dependencies ─────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build tools (needed for psycopg2 even with binary wheel)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ─── Stage 2: runtime image ───────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL maintainer="PulseAI Team"
LABEL description="PULSEAI — AI-powered incident root cause analysis"

# Runtime PostgreSQL client lib only (no build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for security
RUN groupadd -r pulseai && useradd -r -g pulseai pulseai

WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Copy application source
COPY pipeline.py       ./pipeline.py
COPY server.py         ./server.py
COPY celery_worker.py  ./celery_worker.py
COPY gunicorn_conf.py  ./gunicorn_conf.py

# Prometheus multiprocess directory
RUN mkdir -p /tmp/pulseai_prom && chown pulseai:pulseai /tmp/pulseai_prom

# Switch to non-root
USER pulseai

EXPOSE 8000

# Health check — used by Docker and Kubernetes
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8000/health || exit 1

# Default: run Gunicorn with Uvicorn workers
CMD ["gunicorn", "server:app", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--config", "gunicorn_conf.py"]
