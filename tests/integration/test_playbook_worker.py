import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Barrier

from socify.db import connect_path
from socify.playbook_worker import claim_playbook_run, process_playbook_run, run_worker_once


def _queued_run(client, app, steps, key="durable-worker-run"):
    app.config["PLAYBOOK_INLINE_EXECUTION"] = False
    playbook = client.post("/api/playbooks", json={"name": "Durable worker", "steps": steps, "publish": True})
    assert playbook.status_code == 201
    response = client.post(
        "/api/playbook-runs",
        json={"playbook_id": playbook.json["id"], "idempotency_key": key},
    )
    assert response.status_code == 201
    assert response.json["state"] == "pending"
    return response.json["id"]


def test_worker_executes_queued_run_exactly_once(client, app, login_as, database):
    login_as("admin")
    run_id = _queued_run(client, app, [{"action": "notify_training_team"}])
    assert run_worker_once(database, "worker-one", lease_seconds=10) == run_id
    assert run_worker_once(database, "worker-one", lease_seconds=10) is None

    run = client.get(f"/api/playbook-runs/{run_id}").json
    assert run["state"] == "succeeded"
    assert run["steps"][0]["status"] == "succeeded"
    assert run["steps"][0]["attempt"] == 1
    assert run["steps"][0]["effect_key"].startswith("playbook-step:")
    notifications = database.execute("SELECT COUNT(*) FROM outbox_events WHERE event_type = 'training.notification'").fetchone()[0]
    assert notifications == 1


def test_queue_backpressure_and_health_metrics(client, app, login_as):
    login_as("admin")
    app.config["MAX_PENDING_PLAYBOOK_RUNS"] = 1
    run_id = _queued_run(client, app, [{"action": "notify_training_team"}], "bounded-queue-first")
    playbook_id = client.get("/api/playbooks").json["items"][0]["id"]
    rejected = client.post(
        "/api/playbook-runs",
        json={"playbook_id": playbook_id, "idempotency_key": "bounded-queue-second"},
    )
    assert rejected.status_code == 429
    assert rejected.json["error"]["code"] == "PLAYBOOK_QUEUE_FULL"
    health = client.get("/api/health").json["playbook_jobs"]
    assert health == {"queued": 1, "running": 0, "failed": 0, "expired_leases": 0}
    assert client.get(f"/api/playbook-runs/{run_id}").json["state"] == "pending"


def test_queued_run_keeps_immutable_playbook_version(client, app, login_as, database):
    login_as("admin")
    app.config["PLAYBOOK_INLINE_EXECUTION"] = False
    created = client.post(
        "/api/playbooks",
        json={"name": "Pinned version", "steps": [{"action": "notify_training_team"}], "publish": True},
    )
    playbook_id = created.json["id"]
    queued = client.post(
        "/api/playbook-runs",
        json={"playbook_id": playbook_id, "idempotency_key": "pinned-version-run"},
    ).json
    original_version_id = database.execute("SELECT playbook_version_id FROM playbook_runs WHERE id = ?", (queued["id"],)).fetchone()[0]
    versioned = client.post(
        f"/api/playbooks/{playbook_id}/versions",
        json={
            "name": "Pinned version updated",
            "steps": [{"action": "isolate_virtual_host", "parameters": {"host": "new-version-host"}}],
            "publish": True,
        },
    )
    assert versioned.json["version"] == 2
    assert run_worker_once(database, "worker-version", lease_seconds=10) == queued["id"]
    assert database.execute("SELECT playbook_version_id FROM playbook_runs WHERE id = ?", (queued["id"],)).fetchone()[0] == original_version_id
    assert database.execute("SELECT COUNT(*) FROM outbox_events WHERE event_type = 'training.notification'").fetchone()[0] == 1
    assert database.execute("SELECT COUNT(*) FROM response_simulation_state WHERE entity_id = 'new-version-host'").fetchone()[0] == 0


def test_expired_lease_recovers_without_duplicate_effect(client, app, login_as, database):
    login_as("admin")
    run_id = _queued_run(
        client,
        app,
        [{"action": "isolate_virtual_host", "parameters": {"host": "training-host"}}],
        "lease-recovery-run",
    )
    assert claim_playbook_run(database, "worker-dead", lease_seconds=5) == run_id
    database.execute("UPDATE playbook_runs SET lease_expires_at = '2000-01-01T00:00:00Z' WHERE id = ?", (run_id,))
    database.execute("UPDATE playbook_step_runs SET status = 'running', attempt = 1 WHERE run_id = ?", (run_id,))

    assert claim_playbook_run(database, "worker-replacement", lease_seconds=10) == run_id
    assert process_playbook_run(database, run_id, "worker-replacement", lease_seconds=10) == "succeeded"
    step = database.execute("SELECT status, attempt FROM playbook_step_runs WHERE run_id = ?", (run_id,)).fetchone()
    assert dict(step) == {"status": "succeeded", "attempt": 2}
    state = database.execute("SELECT state FROM response_simulation_state WHERE entity_type = 'host' AND entity_id = 'training-host'").fetchall()
    assert [row["state"] for row in state] == ["isolated"]


def test_workers_claim_distinct_runs(client, app, login_as, database):
    login_as("admin")
    first = _queued_run(client, app, [{"action": "notify_training_team"}], "parallel-worker-first")
    second = _queued_run(client, app, [{"action": "notify_training_team"}], "parallel-worker-second")
    claimed_a = claim_playbook_run(database, "worker-a", lease_seconds=10)
    claimed_b = claim_playbook_run(database, "worker-b", lease_seconds=10)
    assert {claimed_a, claimed_b} == {first, second}
    assert claim_playbook_run(database, "worker-c", lease_seconds=10) is None
    assert process_playbook_run(database, int(claimed_a), "worker-a", lease_seconds=10) == "succeeded"
    assert process_playbook_run(database, int(claimed_b), "worker-b", lease_seconds=10) == "succeeded"


def test_simultaneous_connections_claim_one_owner_in_wal_mode(client, app, login_as, database):
    login_as("admin")
    run_id = _queued_run(client, app, [{"action": "notify_training_team"}], "concurrent-wal-claim")
    gate = Barrier(4)

    def claim(index):
        connection = connect_path(app.config["DATABASE"], testing=True)
        try:
            assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
            gate.wait(timeout=10)
            return claim_playbook_run(connection, f"concurrent-{index}", lease_seconds=10)
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=4) as executor:
        claimed = list(executor.map(claim, range(4)))
    assert claimed.count(run_id) == 1 and claimed.count(None) == 3
    assert database.execute("SELECT state FROM playbook_runs WHERE id=?", (run_id,)).fetchone()[0] == "running"


def test_worker_retries_with_backoff_then_stops_at_limit(client, app, login_as, database):
    login_as("admin")
    run_id = _queued_run(
        client,
        app,
        [{"action": "collect_evidence", "retry_limit": 2}],
        "worker-backoff-run",
    )
    assert run_worker_once(database, "worker-retry", lease_seconds=10) == run_id
    first = database.execute("SELECT state, available_at, last_error FROM playbook_runs WHERE id = ?", (run_id,)).fetchone()
    assert first["state"] == "retry_wait"
    assert first["last_error"] == "collect_evidence requires a case"
    assert datetime.fromisoformat(first["available_at"].replace("Z", "+00:00")) > datetime.now(UTC)

    database.execute("UPDATE playbook_runs SET available_at = '2000-01-01T00:00:00Z' WHERE id = ?", (run_id,))
    assert run_worker_once(database, "worker-retry", lease_seconds=10) == run_id
    final = database.execute("SELECT state, completed_at FROM playbook_runs WHERE id = ?", (run_id,)).fetchone()
    assert final["state"] == "failed"
    assert final["completed_at"] is not None
    assert database.execute("SELECT attempt FROM playbook_step_runs WHERE run_id = ?", (run_id,)).fetchone()[0] == 2


def test_worker_honors_cancel_request_before_effect(client, app, login_as, database):
    login_as("admin")
    run_id = _queued_run(client, app, [{"action": "notify_training_team"}], "worker-cancel-run")
    assert claim_playbook_run(database, "worker-cancel", lease_seconds=10) == run_id
    database.execute("UPDATE playbook_runs SET cancel_requested = 1 WHERE id = ?", (run_id,))
    assert process_playbook_run(database, run_id, "worker-cancel", lease_seconds=10) == "cancelled"
    assert database.execute("SELECT status FROM playbook_step_runs WHERE run_id = ?", (run_id,)).fetchone()[0] == "skipped"


def test_timed_out_effect_is_rolled_back(client, app, login_as, database, monkeypatch):
    login_as("admin")
    run_id = _queued_run(
        client,
        app,
        [{"action": "notify_training_team", "timeout_seconds": 1, "retry_limit": 0}],
        "worker-timeout-run",
    )
    values = iter([0.0, 2.0, 2.0])
    monkeypatch.setattr("socify.playbook_worker.time.monotonic", lambda: next(values))
    assert run_worker_once(database, "worker-timeout", lease_seconds=10) == run_id
    run = database.execute("SELECT state, last_error FROM playbook_runs WHERE id = ?", (run_id,)).fetchone()
    assert run["state"] == "failed"
    assert "timeout" in run["last_error"]
    assert database.execute("SELECT COUNT(*) FROM outbox_events WHERE event_type = 'training.notification'").fetchone()[0] == 0


def test_worker_persists_redacted_inputs_and_timing(client, app, login_as, database):
    login_as("admin")
    app.config["PLAYBOOK_INLINE_EXECUTION"] = False
    playbook = client.post(
        "/api/playbooks",
        json={
            "name": "Redacted worker inputs",
            "steps": [
                {"action": "notify_training_team", "parameters": {"message": "safe", "api_key": "must-not-persist"}}  # pragma: allowlist secret
            ],
            "publish": True,
        },
    ).json
    run = client.post(
        "/api/playbook-runs",
        json={"playbook_id": playbook["id"], "idempotency_key": "redacted-worker-input"},
    ).json
    stored = json.loads(database.execute("SELECT input FROM playbook_step_runs WHERE run_id = ?", (run["id"],)).fetchone()[0])
    assert stored == {"message": "safe", "api_key": "[REDACTED]"}
    run_worker_once(database, "worker-redaction", lease_seconds=10)
    step = database.execute("SELECT duration_ms, impact FROM playbook_step_runs WHERE run_id = ?", (run["id"],)).fetchone()
    assert step["duration_ms"] is not None
    assert json.loads(step["impact"]) == {"notification": "queued"}
