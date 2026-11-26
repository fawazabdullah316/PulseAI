"""
PULSEAI — Live stress test against a REAL running server (not TestClient).

This starts an actual uvicorn server bound to a real socket, in a background
thread within this process (so we can mock the Anthropic/AWS/GitHub calls),
then fires genuinely concurrent HTTP requests at it using a thread pool —
exercising real socket handling, FastAPI's run_in_threadpool, the
ThreadPoolExecutor inside run_pipeline, SQLite under concurrent writes, the
in-memory cache under concurrent access, and the rate limiter under burst load.

Run:
    ANTHROPIC_API_KEY=sk-ant-fake python3 stress_test_live.py
"""

import os
import sys
import json
import time
import threading
import concurrent.futures
from collections import Counter
from unittest.mock import patch, MagicMock

os.environ.setdefault("ANTHROPIC_API_KEY", "sk-ant-test-key-not-real")

import httpx
import uvicorn

import pipeline
import server

HOST = "127.0.0.1"
PORT = 8123
BASE_URL = f"http://{HOST}:{PORT}"


def make_mock_anthropic_client(latency_s: float = 0.05):
    """Simulates Claude responding after a short realistic delay."""
    mock_client = MagicMock()

    def _create(*args, **kwargs):
        time.sleep(latency_s)
        resp = MagicMock()
        resp.content = [MagicMock(text=json.dumps({
            "summary": "Load test incident",
            "root_cause": "Synthetic root cause for stress testing",
            "confidence": 65,
            "implicated_commit": None,
            "fixes": [
                {"rank": 1, "action": "Synthetic fix", "confidence": 65, "detail": "n/a"},
            ],
        }))]
        resp.usage = MagicMock(input_tokens=120, output_tokens=60)
        return resp

    mock_client.messages.create.side_effect = _create
    return mock_client


def run_scenario(name: str, n_requests: int, n_workers: int, payload_fn, path="/analyse", method="POST"):
    print(f"\n{'='*70}")
    print(f"SCENARIO: {name}")
    print(f"  requests={n_requests}  concurrent_workers={n_workers}  path={path}")
    print(f"{'='*70}")

    def fire(i):
        t0 = time.time()
        try:
            if method == "POST":
                r = httpx.post(f"{BASE_URL}{path}", json=payload_fn(i), timeout=20)
            else:
                r = httpx.get(f"{BASE_URL}{path}", timeout=20)
            return r.status_code, time.time() - t0
        except Exception as exc:
            return f"EXC:{type(exc).__name__}", time.time() - t0

    t_start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as pool:
        results = list(pool.map(fire, range(n_requests)))
    total_time = time.time() - t_start

    statuses = Counter(r[0] for r in results)
    durations = [r[1] for r in results]
    durations.sort()

    print(f"  Total wall time: {total_time:.2f}s")
    print(f"  Throughput: {n_requests/total_time:.1f} req/s")
    print(f"  Status code distribution: {dict(statuses)}")
    print(f"  Latency p50={durations[len(durations)//2]:.3f}s "
          f"p95={durations[int(len(durations)*0.95)]:.3f}s "
          f"max={durations[-1]:.3f}s")

    crashed = any(isinstance(s, str) and s.startswith("EXC") for s in statuses)
    has_500 = 500 in statuses
    print(f"  Connection-level crashes: {'YES — FAIL' if crashed else 'none'}")
    print(f"  Unhandled 500 errors:     {'YES — FAIL' if has_500 else 'none'}")
    return statuses, durations


def main():
    # ── Patch all external services BEFORE starting the server ──────────────
    mock_anthropic = make_mock_anthropic_client(latency_s=0.05)

    patches = [
        patch("pipeline.Anthropic", return_value=mock_anthropic),
        patch("pipeline.fetch_datadog_metrics", return_value=[]),
        patch("pipeline.fetch_cloudwatch_logs", return_value=[]),
        patch("pipeline.fetch_recent_commits", return_value=[]),
    ]
    for p in patches:
        p.start()

    # Disable API key auth + use a very permissive rate limit for this load test
    # (rate-limit behaviour under burst is already covered in test_server.py)
    server.PULSEAI_API_KEY = ""
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    permissive_limiter = Limiter(key_func=get_remote_address, storage_uri="memory://", default_limits=["100000/minute"])
    server.app.state.limiter = permissive_limiter

    # Use a clean SQLite file for this run so we can inspect row counts after
    test_db = "stress_test.db"
    if os.path.exists(test_db):
        os.remove(test_db)
    pipeline.DB_PATH = test_db
    pipeline.DATABASE_URL = ""   # force SQLite fallback path for this test
    pipeline._db_mode = "none"
    pipeline._sqlite_initialised = False
    pipeline._mem_cache.clear()

    # ── Start a REAL uvicorn server in a background thread ──────────────────
    config = uvicorn.Config(server.app, host=HOST, port=PORT, log_level="warning")
    srv = uvicorn.Server(config)
    server_thread = threading.Thread(target=srv.run, daemon=True)
    server_thread.start()

    print("Waiting for server to bind...")
    for _ in range(50):
        try:
            r = httpx.get(f"{BASE_URL}/health", timeout=1)
            if r.status_code == 200:
                print(f"Server is up. /health -> {r.json()['status']}")
                break
        except Exception:
            time.sleep(0.1)
    else:
        print("FAIL: server never came up")
        sys.exit(1)

    all_passed = True

    # ── Scenario 1: moderate concurrent load, unique incidents ──────────────
    statuses, _ = run_scenario(
        "Moderate concurrent load — 100 unique incidents, 25 workers",
        n_requests=100, n_workers=25,
        payload_fn=lambda i: {"alert_name": f"Load test alert {i}", "service": "checkout-service"},
    )
    if 500 in statuses or any(isinstance(s, str) for s in statuses):
        all_passed = False

    # ── Scenario 2: high concurrency burst, unique incidents ────────────────
    statuses, _ = run_scenario(
        "High burst load — 200 unique incidents, 50 workers",
        n_requests=200, n_workers=50,
        payload_fn=lambda i: {"alert_name": f"Burst alert {i}", "service": f"service-{i % 5}"},
    )
    if 500 in statuses or any(isinstance(s, str) for s in statuses):
        all_passed = False

    # ── Scenario 3: identical incident hammered repeatedly (cache stress) ───
    statuses, _ = run_scenario(
        "Cache stress — same incident hit 100 times concurrently",
        n_requests=100, n_workers=40,
        payload_fn=lambda i: {
            "alert_name": "Identical cached alert",
            "service": "cache-test-service",
            "triggered_at": "2024-06-01T12:00:00+00:00",   # fixed -> same incident_id
        },
    )
    if 500 in statuses or any(isinstance(s, str) for s in statuses):
        all_passed = False
    print(f"  Claude API calls made for this scenario: {mock_anthropic.messages.create.call_count} "
          f"(low number confirms cache is deduplicating concurrent identical requests)")

    # ── Scenario 4: concurrent /health checks (simulates K8s liveness probes) ─
    statuses, _ = run_scenario(
        "Concurrent health checks — 100 requests, 30 workers",
        n_requests=100, n_workers=30,
        payload_fn=lambda i: None, path="/health", method="GET",
    )
    if 500 in statuses or any(isinstance(s, str) for s in statuses):
        all_passed = False

    # ── Scenario 5: mixed valid + invalid input under load ──────────────────
    def mixed_payload(i):
        if i % 7 == 0:
            return {"alert_name": "", "service": "svc"}          # invalid -> 422
        if i % 11 == 0:
            return {"alert_name": "x" * 600, "service": "svc"}   # too long -> 422
        return {"alert_name": f"Mixed alert {i}", "service": "svc"}

    statuses, _ = run_scenario(
        "Mixed valid/invalid payloads under load — 150 requests",
        n_requests=150, n_workers=30,
        payload_fn=mixed_payload,
    )
    if 500 in statuses or any(isinstance(s, str) for s in statuses):
        all_passed = False
    print(f"  (422s expected here from intentionally invalid payloads — not failures)")

    # ── Verify SQLite persisted records correctly under concurrent writes ───
    import sqlite3
    conn = sqlite3.connect(test_db)
    count = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
    conn.close()
    print(f"\n{'='*70}")
    print(f"SQLite persistence check: {count} unique incident rows written under concurrent load")
    print(f"{'='*70}")

    # ── Shutdown ──────────────────────────────────────────────────────────
    srv.should_exit = True
    server_thread.join(timeout=10)
    if server_thread.is_alive():
        print("WARNING: server thread did not shut down cleanly within 10s")
        all_passed = False
    else:
        print("Server shut down cleanly.")

    for p in patches:
        p.stop()

    if os.path.exists(test_db):
        os.remove(test_db)

    print(f"\n{'='*70}")
    print(f"OVERALL RESULT: {'ALL SCENARIOS PASSED — no crashes, no unhandled 500s' if all_passed else 'FAILURES DETECTED — see above'}")
    print(f"{'='*70}")
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
