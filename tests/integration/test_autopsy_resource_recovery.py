import json
import socket

from socify.autopsy_worker import run_autopsy_worker_once
from socify.db import get_db
from socify.import_worker import run_import_worker_once
from socify.timeutils import iso_now


def test_import_quota_cancel_then_resume_after_worker_restart_preserves_evidence(autopsy_case, app, client):
    app.config.update(IMPORT_INLINE_EXECUTION=False, MAX_PENDING_IMPORT_JOBS=1)
    base = f"/api/cases/{autopsy_case}"
    first = client.post(base + "/imports", json={"filename": "first.json", "content": '[{"title":"Cancelled original still retained"}]'})
    assert first.status_code == 202
    content = json.dumps([{"title": "Recovered bounded queue event", "source_ip": "192.0.2.80"}])
    assert client.post(base + "/imports", json={"filename": "second.json", "content": content}).status_code == 429
    assert client.get(base + "/logs").status_code == 200
    assert client.post(base + f"/imports/{first.json['id']}/cancel").status_code == 200
    second = client.post(base + "/imports", json={"filename": "second.json", "content": content})
    assert second.status_code == 202
    with app.app_context():
        assert run_import_worker_once(get_db(), "new-worker-after-interruption") is not None
    state = client.get(base + f"/imports/{second.json['id']}").json
    assert state["status"] == "completed" and state["accepted"] == 1
    assert client.get(base + "/logs").json["total"] == 1
    assert client.get(base + "/custody").json["integrity_valid"] is True
    assert client.get(base + f"/imports/{first.json['id']}").json["raw_evidence"]["available"] is True


def test_observable_url_is_preserved_as_data_without_network_or_dns(autopsy_case, client, monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("User-controlled observable triggered network or DNS")

    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    base = f"/api/cases/{autopsy_case}"
    url = "https://malicious.invalid/collect?case=synthetic"
    created = client.post(
        base + "/records/indicator",
        json={
            "type": "url",
            "value": url,
            "classification": "observable",
            "confidence": 20,
            "source": "Retained synthetic log",
            "description": "Unvisited URL",
        },
    )
    assert created.status_code == 201, created.json
    assert client.get(base + "/records?kind=indicator").json["items"][0]["payload"]["value"] == url


def test_analysis_restart_backoff_preserves_snapshot_then_recovers_without_manual_retry(autopsy_case, app, client, database, monkeypatch, tmp_path):
    base = f"/api/cases/{autopsy_case}"
    queued = client.post(base + "/reports", json={"version": client.get(base).json["version"]}).json
    path = base + f"/jobs/{queued['job_id']}"
    with monkeypatch.context() as unavailable:
        unavailable.setenv("SOCIFY_ANALYSIS_SOCKET", str(tmp_path / "not-started.sock"))
        with app.app_context():
            assert run_autopsy_worker_once("restart-before-service-ready") == queued["job_id"]
            assert run_autopsy_worker_once("must-respect-backoff") is None
    state = client.get(path).json
    assert state["state"] == "queued" and state["attempts"] == 1
    assert state["error_code"] == "ANALYSIS_UNAVAILABLE" and state["available_at"] > iso_now()
    assert database.execute("SELECT COUNT(*) FROM autopsy_report_files WHERE report_id=?", (queued["id"],)).fetchone()[0] == 0
    database.execute("UPDATE autopsy_jobs SET available_at='2000-01-01T00:00:00Z' WHERE id=?", (queued["job_id"],))
    with app.app_context():
        assert run_autopsy_worker_once("service-recovered") == queued["job_id"]
    assert client.get(path).json["state"] == "completed"
    assert client.get(path).json["attempts"] == 2
    assert client.get(base + f"/reports/{queued['id']}/files/pdf").data.startswith(b"%PDF-")


def test_analysis_unavailability_has_finite_attempts_and_never_hides_access_revocation(autopsy_case, app, client, database, monkeypatch, tmp_path, login_as):
    base = f"/api/cases/{autopsy_case}"
    queued = client.post(base + "/reports", json={"version": client.get(base).json["version"]}).json
    monkeypatch.setenv("SOCIFY_ANALYSIS_SOCKET", str(tmp_path / "absent.sock"))
    for attempt in range(1, 4):
        database.execute("UPDATE autopsy_jobs SET available_at=NULL WHERE id=?", (queued["job_id"],))
        with app.app_context():
            assert run_autopsy_worker_once("bounded-recovery") == queued["job_id"]
        state = client.get(base + f"/jobs/{queued['job_id']}").json
        assert state["attempts"] == attempt
        assert state["state"] == ("queued" if attempt < 3 else "failed")
    assert state["error_code"] == "ANALYSIS_UNAVAILABLE"
    assert client.get(base + f"/reports/{queued['id']}/files/pdf").status_code == 404
    next_job = client.post(base + "/reports", json={"version": client.get(base).json["version"]}).json
    login_as("soc_manager")
    assert client.put("/api/team/roles/analyst", json={"permissions": ["cases.read"]}).status_code == 200
    with app.app_context():
        run_autopsy_worker_once("must-not-retry-revoked-actor")
    assert client.get(base + f"/jobs/{next_job['job_id']}").json["error_code"] == "ACCESS_REVOKED"
