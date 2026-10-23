import json

from socify.db import get_db
from socify.import_worker import claim_import_job, run_import_worker_once


def _queue_import(client, app, content: str, filename: str):
    app.config["IMPORT_INLINE_EXECUTION"] = False
    response = client.post("/api/imports", json={"filename": filename, "format": "jsonl", "content": content})
    assert response.status_code == 202
    assert response.json["status"] == "queued"
    return response.json["id"]


def _json_lines(count: int, source: str) -> str:
    return "\n".join(
        json.dumps(
            {
                "source": source,
                "event_time": f"2026-10-20T10:{index // 60:02d}:{index % 60:02d}Z",
                "event_type": "worker_fixture",
                "severity": "low",
                "title": f"Worker fixture {index}",
            }
        )
        for index in range(count)
    )


def test_import_worker_processes_queue_and_reports_health(client, app, login_as):
    login_as("analyst")
    job_id = _queue_import(client, app, _json_lines(3, "worker-import"), "worker.jsonl")
    health = client.get("/api/health").json["import_jobs"]
    assert health == {"queued": 1, "processing": 0, "failed": 0, "expired_leases": 0}
    with app.app_context():
        assert run_import_worker_once(get_db(), "import-worker-one", lease_seconds=10) == job_id
        assert run_import_worker_once(get_db(), "import-worker-one", lease_seconds=10) is None
    completed = client.get(f"/api/imports/{job_id}").json
    assert completed["status"] == "completed"
    assert completed["accepted"] == 3
    assert completed["checkpoint"] == 3


def test_import_worker_recovers_checkpoint_after_crash(client, app, login_as, database, monkeypatch):
    login_as("analyst")
    job_id = _queue_import(client, app, _json_lines(150, "checkpoint-worker"), "checkpoint.jsonl")
    from socify import ingestion

    original = ingestion.ingest_event
    calls = 0

    def interrupted(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 101:
            raise RuntimeError("simulated worker termination")
        return original(*args, **kwargs)

    monkeypatch.setattr(ingestion, "ingest_event", interrupted)
    with app.app_context():
        assert run_import_worker_once(get_db(), "import-worker-crashed", lease_seconds=10) == job_id
    interrupted_job = database.execute("SELECT status, accepted, checkpoint, retry_count FROM ingestion_jobs WHERE id = ?", (job_id,)).fetchone()
    assert dict(interrupted_job) == {"status": "interrupted", "accepted": 100, "checkpoint": 100, "retry_count": 1}

    monkeypatch.setattr(ingestion, "ingest_event", original)
    database.execute("UPDATE ingestion_jobs SET available_at = '2000-01-01T00:00:00Z' WHERE id = ?", (job_id,))
    with app.app_context():
        assert run_import_worker_once(get_db(), "import-worker-restarted", lease_seconds=10) == job_id
    completed = database.execute("SELECT status, accepted, checkpoint FROM ingestion_jobs WHERE id = ?", (job_id,)).fetchone()
    assert dict(completed) == {"status": "completed", "accepted": 150, "checkpoint": 150}
    assert database.execute("SELECT COUNT(*) FROM security_events WHERE source = 'checkpoint-worker'").fetchone()[0] == 150


def test_import_workers_claim_distinct_jobs(client, app, login_as, database):
    login_as("analyst")
    first = _queue_import(client, app, _json_lines(1, "claim-first"), "claim-first.jsonl")
    second = _queue_import(client, app, _json_lines(1, "claim-second"), "claim-second.jsonl")
    claimed_a = claim_import_job(database, "import-worker-a", lease_seconds=10)
    claimed_b = claim_import_job(database, "import-worker-b", lease_seconds=10)
    assert claimed_a is not None
    assert claimed_b is not None
    assert {claimed_a, claimed_b} == {first, second}
    assert claim_import_job(database, "import-worker-c", lease_seconds=10) is None


def test_import_queue_enforces_backpressure(client, app, login_as):
    login_as("analyst")
    app.config["MAX_PENDING_IMPORT_JOBS"] = 1
    _queue_import(client, app, _json_lines(1, "bounded-first"), "bounded-first.jsonl")
    rejected = client.post(
        "/api/imports",
        json={"filename": "bounded-second.jsonl", "format": "jsonl", "content": _json_lines(1, "bounded-second")},
    )
    assert rejected.status_code == 429
    assert rejected.json["error"]["code"] == "IMPORT_QUEUE_FULL"
