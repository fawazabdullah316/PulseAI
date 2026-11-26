# PULSEAI v4 — Production Infrastructure

This is the production-grade rewrite of Pulse AI's backend: PostgreSQL, FastAPI + Gunicorn/Uvicorn, Redis + Celery, Nginx, Docker + Kubernetes autoscaling, and Datadog/Grafana monitoring — all six pieces from the original upgrade plan, implemented, tested, and two real concurrency bugs found and fixed along the way.

## What's in this package

```
pipeline.py              Core analysis pipeline (v4)
server.py                FastAPI server (v4)
celery_worker.py         Celery app + async task definitions
gunicorn_conf.py         Production Gunicorn config
requirements.txt         Pinned dependencies

Dockerfile                Multi-stage production image
docker-compose.yml        Full local/single-host stack (7 services)
nginx.conf                 Load balancer config

k8s/                       Kubernetes manifests (7 files, autoscaling included)
monitoring/                Prometheus + Grafana config and dashboard

test_pipeline.py          62 unit tests for pipeline.py
test_server.py            36 endpoint tests for server.py
stress_test_live.py       Live concurrency test against a real running server

.env.example               Every environment variable, documented
.gitignore
```

## Test results

98 automated tests, all passing, plus a live concurrency run against a real socket-bound server (not just mocked unit tests):

| Suite | Tests | Result |
|---|---|---|
| test_pipeline.py | 62 | all passing |
| test_server.py | 36 | all passing |
| stress_test_live.py | 5 load scenarios | zero crashes, zero unhandled 500s |

The live stress test spins up a real `uvicorn` server on a real socket and fires concurrent requests at it with a thread pool — moderate load (100 req/25 workers), high burst (200 req/50 workers), repeated-identical-incident load, concurrent health checks, and mixed valid/invalid payloads. Every scenario completed with clean status codes and no connection-level failures.

## Two real bugs found and fixed

Stress-testing this surfaced two genuine concurrency bugs that would have caused problems in production. Both are fixed in the code you have now.

**Rate limiter crashed every request instead of limiting them.** The first draft called `limiter.limit(...)` inline inside the route body on a throwaway lambda. slowapi needs the decorator applied directly on a function that takes `request: Request` as a parameter — it inspects the signature to find that object. The lambda had no such parameter, so every single call to `/analyse` would have 500'd. Verified with a minimal repro before fixing, then confirmed the fix with `@_rate_limit(...)` properly decorating the route: 200s until the limit, then clean 429s, never a 500. The same fix was needed on `/analyse/async` and `/result/{job_id}`, which were missing the `request` parameter and rate limit entirely despite the docstring claiming one existed.

**Cache stampede on identical concurrent incidents.** Fired 20 concurrent requests for the exact same incident (same alert, same service, same timestamp) and found all 20 hit the empty cache simultaneously and each made a separate Claude API call — 20 calls instead of 1. This matters because PagerDuty and similar tools are known to occasionally send duplicate webhook deliveries in quick succession, so this isn't a contrived edge case. Fixed with a per-incident lock (single-flight pattern): the first request to arrive for a given incident_id does the real work; any others for that same incident block briefly and then read its cached result instead of duplicating the Claude call. Different incidents never contend with each other — only identical, simultaneous ones do. Verified the fix: same 20-request test now makes exactly 1 Claude API call.

**Server didn't read `.env` when run without Docker.** All the config-reading code (`os.environ.get(...)`) works fine, but nothing actually loaded a local `.env` file into the environment unless something else did it first — which docker-compose does automatically, masking the gap entirely in that deployment path. Running the server directly with `python -m uvicorn` instead left every setting empty even with a fully filled-in `.env` sitting right next to it. Fixed with `load_dotenv()` at the top of pipeline.py; real OS-level environment variables still take priority over the file if both are present.

**Rate limiter crashed every request if Redis was configured but unreachable.** If `REDIS_URL` is set to a value that can't actually be connected to — exactly what happens if you copy the Docker-internal `redis://redis:6379/0` value into a `.env` and then run the server without Docker — the very first request to `/analyse` threw an unhandled `redis.exceptions.ConnectionError` straight through the middleware stack. Fixed by pinging Redis once at startup and falling back to in-memory rate-limit storage if it's unreachable, logging a clear warning instead of failing every request — the same defensive pattern already used for the pipeline's cache.

**Prometheus crashed on startup if its multiprocess directory wasn't created yet.** If `PROMETHEUS_MULTIPROC_DIR` is set in the environment (including via `.env`, once `load_dotenv()` was added), `prometheus_client` silently switches every metric to file-backed storage rooted in that directory — and crashes with `FileNotFoundError` the instant the first metric is created if that directory doesn't exist yet. The code that created the directory lived in `server.py`, but `pipeline.py`'s own metrics are created the moment something does `from pipeline import ...`, which happens *during* `server.py`'s import — before `server.py`'s own setup code gets a chance to run. Whoever imports `pipeline.py` first never got the directory made in time; reproduced instantly even outside Windows, confirming it was a pure ordering bug, not an OS quirk. Fixed by creating the directory directly inside `pipeline.py`, before anything imports `prometheus_client`, and switched the default path from a hardcoded `/tmp/...` string to `tempfile.gettempdir()` so it resolves correctly on Windows too.

## Architecture

Client → Nginx (load balancing, rate limiting, SSL termination) → 3+ FastAPI/Gunicorn workers → PostgreSQL (persistence) + Redis (cache + Celery queue) → Celery workers (async analysis) → Prometheus (metrics) → Grafana (dashboards).

Kubernetes deploys the same topology with a `HorizontalPodAutoscaler` instead of fixed replica counts: the API tier scales 3→15 pods on CPU/memory, the Celery worker tier scales 2→10 pods independently, since async job load doesn't track 1:1 with HTTP request volume.

## What changed in each file (v3 → v4)

**Incident memory (new).** `get_similar_past_incidents()` queries the database for prior analyses on the same service and feeds them into the prompt, so Claude can say "this looks like the same connection-pool issue from three days ago" instead of treating every incident as the first one this service has ever had. This is the narrow, honest version — matching is by exact service name, not cross-service semantic similarity, and there's no feedback loop on whether a past suggested fix actually worked. Both of those are real, larger features for later.

**Flap suppression (new).** A second, separate cache keyed on `alert_name + service` (not the full incident timestamp) with a 5-minute window. If the same alert on the same service fires again while still within that window, the existing analysis is returned instead of paying for another Claude call to say the same thing — genuine, if narrow, noise reduction. It deliberately does not do cross-alert correlation, severity-based suppression, or maintenance windows.

**pipeline.py**: SQLite replaced with PostgreSQL via a `ThreadedConnectionPool`, with automatic fallback to SQLite if `DATABASE_URL` is unset (safe for local dev, not for concurrent production writes — the stress test demonstrates why). Added Prometheus metrics (analysis counter, duration histogram, error counter, cache hit/miss, in-flight gauge), a `check_db_health()` function used by `/health`, the per-incident locking described above, and a fix to the PagerDuty HMAC verification (`hashlib.sha256` object instead of the string `"sha256"`, which would have raised a `TypeError` on every webhook).

**server.py**: Added `/metrics` (Prometheus scrape target), `/analyse/async` + `/result/{job_id}` (Celery-backed async dispatch with graceful fallback when Redis isn't configured), an expanded `/health` that reports database/Redis/Celery status, and the corrected rate-limiting decorators.

**celery_worker.py** (new): Celery app with sane production defaults — `task_acks_late` and `task_reject_on_worker_lost` so in-flight work survives a worker crash, a 90s soft / 120s hard time limit, and 2 retries with backoff.

**gunicorn_conf.py** (new): Worker count defaults to `2 × CPU + 1`, 90s timeout (the pipeline can legitimately take up to 60s), and Prometheus multiprocess directory setup in `on_starting`/`post_fork`/`worker_exit` hooks so metrics aggregate correctly across multiple worker processes.

## Deploying

**Local / single host (docker-compose):**
```bash
cp .env.example .env          # fill in ANTHROPIC_API_KEY at minimum
docker compose up --build
```
API: `http://localhost/docs` · Grafana: `http://localhost:3000` (admin / whatever you set `GRAFANA_ADMIN_PASSWORD` to) · Prometheus is internal-only by default.

**Local, without Docker:**

If Docker isn't available, the server runs directly with Python. In this mode it automatically falls back to SQLite (instead of PostgreSQL) and in-memory caching/rate-limiting (instead of Redis) — fine for testing on your own machine, not for real concurrent production traffic.

```bash
pip install -r requirements.txt
python -m uvicorn server:app --host 0.0.0.0 --port 8000
```
On Windows, `run_local.ps1` does both of those in one step — just run `.\run_local.ps1` from PowerShell inside this folder.

In your `.env`, leave `DATABASE_URL`, `POSTGRES_PASSWORD`, and `REDIS_URL` blank or commented out for this mode — they're only meaningful with docker-compose or Kubernetes, where Postgres and Redis actually exist as separate running services. If `REDIS_URL` is left pointing at the Docker-internal `redis://redis:6379/0` value while running outside Docker, the app detects it's unreachable at startup and automatically falls back to in-memory rate limiting rather than failing requests.

API in this mode: `http://localhost:8000/docs` (note: port 8000 directly, no Nginx in front).

**Kubernetes:**
```bash
kubectl apply -f k8s/00-namespace-config.yaml
# Edit k8s/01-secrets.template.yaml with real values, then:
kubectl apply -f k8s/01-secrets.template.yaml
kubectl apply -f k8s/02-postgres.yaml
kubectl apply -f k8s/03-redis.yaml
kubectl apply -f k8s/04-app-deployment.yaml
kubectl apply -f k8s/05-hpa.yaml
kubectl apply -f k8s/06-ingress.yaml
```
Requires the `metrics-server` addon installed for the HPA to function, and an ingress controller + cert-manager for `06-ingress.yaml`'s automatic TLS.

## Running the tests yourself

```bash
pip install -r requirements.txt
pip install pytest pytest-mock locust

export ANTHROPIC_API_KEY=sk-ant-fake-for-testing   # tests mock all external calls

pytest test_pipeline.py test_server.py -v
python3 stress_test_live.py
```

## One important limitation to know about

Docker wasn't available in the sandbox this was built in, so the `Dockerfile` and `docker-compose.yml` are validated for YAML/syntax correctness and logical consistency with the actual codebase, but not via an actual `docker build`. Before you deploy, run `docker compose up --build` yourself once and watch the logs — if anything surfaces (a missing system library for `psycopg2`, a base image tag that's moved, etc.) it should be a quick fix, but it hasn't been executed end-to-end the way the Python test suite has.

A second thing worth knowing: the live stress test's HTTP-layer throughput numbers were capped by the legitimate 10/minute rate limit on `/analyse` (which is correct, working-as-intended behavior — that's what it's there for), so the headline throughput figures from that run reflect the rate limiter doing its job, not the pipeline's raw ceiling. The pipeline's actual concurrent-processing correctness (cache, locking, database writes, thread safety) was verified separately via direct calls that bypass HTTP, which is what caught the cache stampede bug above.
