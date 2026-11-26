"""Worker heartbeats, the container health check script, and the heartbeat ages in metrics and the health API."""

import socket
import sqlite3
import threading
from datetime import timedelta
from pathlib import Path

import pytest

from scripts import healthcheck
from scripts.run_autopsy_worker import serve as serve_autopsy
from scripts.run_import_worker import serve as serve_imports
from socify.analysis_transport import MAX_REQUEST, MAX_RESPONSE, ping, receive, send
from socify.timeutils import utc_now
from socify.version import VERSION
from socify.worker_health import Heartbeat, heartbeat_ages, record_heartbeat, worker_healthy
from tests.conftest import linux_only


def _stamp(moment):
    return moment.isoformat().replace("+00:00", "Z")


def _age(database, name, seconds):
    database.execute("UPDATE worker_heartbeats SET last_beat_at = ? WHERE name = ?", (_stamp(utc_now() - timedelta(seconds=seconds)), name))


def test_each_worker_records_a_heartbeat_when_it_starts_and_after_each_poll(app, database):
    serve_imports(app, "import-test-instance", 60, 0.1, once=True)
    serve_autopsy(app, "autopsy-test-instance", 0.1, once=True)
    rows = {row["name"]: row for row in database.execute("SELECT * FROM worker_heartbeats").fetchall()}
    assert set(rows) == {"import-worker", "autopsy-worker"}
    assert rows["import-worker"]["instance"] == "import-test-instance" and rows["autopsy-worker"]["instance"] == "autopsy-test-instance"
    assert all(row["state"] == "idle" and row["version"] == VERSION and row["pid"] and row["started_at"] <= row["last_beat_at"] for row in rows.values())


def test_idle_beats_are_written_at_most_once_per_interval_and_forced_beats_always(database):
    heartbeat = Heartbeat("backup", "backup-test", interval=30)
    heartbeat.beat(database, "idle")
    _age(database, "backup", 10)
    stale = database.execute("SELECT last_beat_at FROM worker_heartbeats WHERE name = 'backup'").fetchone()[0]
    heartbeat.beat(database, "idle")
    assert database.execute("SELECT last_beat_at FROM worker_heartbeats WHERE name = 'backup'").fetchone()[0] == stale
    heartbeat.beat(database, "failed")
    assert database.execute("SELECT state FROM worker_heartbeats WHERE name = 'backup'").fetchone()[0] == "failed"
    _age(database, "backup", 10)
    stale = database.execute("SELECT last_beat_at FROM worker_heartbeats WHERE name = 'backup'").fetchone()[0]
    heartbeat.beat(database, "active", force=True)
    row = database.execute("SELECT last_beat_at, state FROM worker_heartbeats WHERE name = 'backup'").fetchone()
    assert row["last_beat_at"] > stale and row["state"] == "active"


def test_unknown_worker_names_are_refused(database):
    with pytest.raises(ValueError):
        record_heartbeat(database, "anything", "instance", "2026-01-01T00:00:00Z", "idle")


def test_a_busy_database_skips_the_beat_instead_of_stopping_the_worker(app, tmp_path):
    holder = sqlite3.connect(app.config["DATABASE"], isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    worker = sqlite3.connect(app.config["DATABASE"], isolation_level=None, timeout=0)
    try:
        assert record_heartbeat(worker, "import-worker", "instance", "2026-01-01T00:00:00Z", "idle") is False
    finally:
        holder.rollback()
        holder.close()
        worker.close()


def test_health_accepts_a_recent_beat_or_a_live_lease_and_refuses_a_stale_one(database, user_ids):
    record_heartbeat(database, "import-worker", "import-test-instance", "2026-01-01T00:00:00Z", "active")
    assert worker_healthy(database, "import-worker", 120)
    _age(database, "import-worker", 600)
    assert not worker_healthy(database, "import-worker", 120)
    job = database.execute(
        """INSERT INTO ingestion_jobs (job_id, workspace_id, filename, format, content_hash, status, parser_version, created_by, worker_id, lease_expires_at, created_at)
        VALUES ('heartbeat-lease-job', 1, 'large.csv', 'csv', ?, 'processing', 'socify-1', ?, 'import-test-instance', ?, ?)""",
        ("0" * 64, user_ids["analyst"], _stamp(utc_now() + timedelta(seconds=60)), _stamp(utc_now())),
    ).lastrowid
    assert worker_healthy(database, "import-worker", 120)
    database.execute("UPDATE ingestion_jobs SET lease_expires_at = ? WHERE id = ?", (_stamp(utc_now() - timedelta(seconds=1)), job))
    assert not worker_healthy(database, "import-worker", 120)
    assert not worker_healthy(database, "autopsy-worker", 120)


def test_healthcheck_script_exit_status_follows_the_heartbeat(app, database, monkeypatch):
    monkeypatch.setenv("SOCIFY_DATABASE", app.config["DATABASE"])
    assert healthcheck.main(["worker", "--name", "import-worker"]) == 1
    record_heartbeat(database, "import-worker", "instance", "2026-01-01T00:00:00Z", "idle")
    assert healthcheck.main(["worker", "--name", "import-worker", "--max-age", "120"]) == 0
    _age(database, "import-worker", 300)
    assert healthcheck.main(["worker", "--name", "import-worker", "--max-age", "120"]) == 1
    monkeypatch.setenv("SOCIFY_DATABASE", str(Path(app.config["DATABASE"]).with_name("missing.db")))
    assert healthcheck.main(["worker", "--name", "import-worker"]) == 1


def test_ping_reports_an_absent_service_as_unavailable(tmp_path):
    assert ping(str(tmp_path / "absent.sock"), 0.5) is None
    assert healthcheck.main(["analysis", "--socket", str(tmp_path / "absent.sock"), "--timeout", "0.5"]) == 1


@linux_only
def test_ping_returns_the_service_version_without_work(tmp_path):
    path = str(tmp_path / "analysis.sock")
    received = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(path)
        server.listen(1)

        def answer():
            stream, _ = server.accept()
            with stream:
                received.append(receive(stream, MAX_REQUEST))
                send(stream, {"version": "9.9.9"}, MAX_RESPONSE)

        thread = threading.Thread(target=answer)
        thread.start()
        assert ping(path, 2) == "9.9.9"
        thread.join(2)
    assert received == [{"operation": "ping", "payload": {}}]


def test_metrics_and_health_api_report_heartbeat_ages(app, client, database, login_as):
    record_heartbeat(database, "import-worker", "instance", "2026-01-01T00:00:00Z", "idle")
    record_heartbeat(database, "autopsy-worker", "instance", "2026-01-01T00:00:00Z", "idle")
    _age(database, "autopsy-worker", 90)
    with app.app_context():
        from socify.db import get_db

        ages = heartbeat_ages(get_db())
    assert ages["import-worker"] < 30 and 85 <= ages["autopsy-worker"] < 120
    app.config.update(METRICS_TOKEN="m" * 32)
    metrics = client.get("/health/metrics", headers={"Authorization": "Bearer " + "m" * 32}).get_data(as_text=True)
    assert "# TYPE socify_worker_heartbeat_age_seconds gauge" in metrics
    assert 'socify_worker_heartbeat_age_seconds{worker="import-worker"}' in metrics
    assert 'socify_worker_heartbeat_age_seconds{worker="autopsy-worker"}' in metrics
    login_as("analyst")
    workers = client.get("/api/health").json["workers"]
    assert set(workers) == {"import-worker", "autopsy-worker"} and workers["autopsy-worker"]["heartbeat_age_seconds"] >= 85
    assert workers["import-worker"]["healthy"] and workers["autopsy-worker"]["healthy"]
    _age(database, "autopsy-worker", 600)
    assert client.get("/api/health").json["workers"]["autopsy-worker"]["healthy"] is False
