import hashlib
import json
import sqlite3
from collections.abc import Callable

from flask.testing import FlaskClient

from socify.db import get_db, transaction
from socify.events import ingest_event
from socify.schema import ensure_schema


def failed_login(client: FlaskClient, number: int, source_ip: str = "198.51.100.20", prefix: str = "login") -> tuple[int, list[int], bool]:
    """Store one failed login the way every producer does and return (event id, alert ids, duplicate)."""
    with client.application.app_context(), transaction():
        return ingest_event(
            get_db(),
            {
                "idempotency_key": f"{prefix}-{source_ip}-{number}",
                "source": "integration-auth",
                "source_type": "training",
                "severity": "medium",
                "category": "authentication",
                "event_type": "failed_login",
                "title": "Synthetic failed login",
                "description": "Isolated integration event",
                "event_time": f"2026-10-19T10:0{number}:00Z",
                "source_ip": source_ip,
                "username": "amina",
                "hostname": "idp-training-01",
                "action": "login",
                "outcome": "failed",
                "raw_payload": {"synthetic": True, "sequence": number},
            },
            None,
            1,
        )


def generated_alert(client: FlaskClient, prefix: str = "alert") -> int:
    alert_ids = [failed_login(client, index, prefix=prefix) for index in range(1, 6)][-1][1]
    assert len(alert_ids) == 1
    return int(alert_ids[0])


def complete_case_tasks(client: FlaskClient, case_id: int) -> None:
    detail = client.get(f"/api/incidents/{case_id}").json
    for task in detail["tasks"]:
        response = client.patch(f"/api/incidents/{case_id}/tasks/{task['id']}", json={"status": "completed"})
        assert response.status_code == 200


def transition(client: FlaskClient, case_id: int, status: str, **extra: object):
    detail = client.get(f"/api/incidents/{case_id}").json
    return client.post(
        f"/api/incidents/{case_id}/transitions",
        json={"status": status, "reason": f"Acceptance transition to {status}", "version": detail["version"], **extra},
    )


def test_e2e_20_empty_cases_support_persistent_manual_creation(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("analyst")
    assert client.get("/api/incidents").json["total"] == 0
    created = client.post(
        "/api/incidents",
        json={"title": "Manual acceptance investigation", "description": "Created from the empty state", "severity": "medium", "priority": "medium"},
    )
    assert created.status_code == 201
    case_id = created.json["id"]
    assert client.get("/api/incidents").json["total"] == 1
    assert client.get(f"/api/incidents/{case_id}").json["title"] == "Manual acceptance investigation"


def test_e2e_21_to_25_full_case_lifecycle_and_reports(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("analyst")
    alert_id = generated_alert(client, "case-flow")
    created = client.post(f"/api/alerts/{alert_id}/case", json={})
    assert created.status_code == 201
    case_id = created.json["id"]
    detail = client.get(f"/api/incidents/{case_id}").json
    assert len(detail["alerts"]) == 1
    assert len(detail["events"]) == 5
    assert len(detail["evidence"]) == 6
    note = client.post(f"/api/incidents/{case_id}/notes", json={"body": "Reviewed <img src=x onerror=alert(1)>", "visibility": "team"})
    assert note.status_code == 201
    ioc_content = "198.51.100.20"
    evidence = client.post(
        f"/api/incidents/{case_id}/evidence",
        json={"type": "ioc", "reference_id": ioc_content, "title": "Synthetic source IP", "content": ioc_content},
    )
    assert evidence.status_code == 201
    assert evidence.json["sha256"] == hashlib.sha256(ioc_content.encode()).hexdigest()
    complete_case_tasks(client, case_id)
    assert transition(client, case_id, "investigating").status_code == 200
    assert transition(client, case_id, "contained").status_code == 200
    assert transition(client, case_id, "recovered").status_code == 200
    login_as("soc_manager")
    closure = transition(
        client,
        case_id,
        "closed",
        disposition="true_positive",
        root_cause="Simulated credential abuse",
        impact="Training identity exposure",
        response_summary="Contained the synthetic source",
        evidence_summary="Linked alerts and raw events confirm the finding",
        lessons_learned="Tune identity detections",
        validation="Verified containment and reviewed the evidence hashes",
    )
    assert closure.status_code == 200
    report_json = client.get(f"/api/incidents/{case_id}/report?format=json")
    report_html = client.get(f"/api/incidents/{case_id}/report?format=html")
    assert report_json.status_code == 200
    assert report_html.status_code == 200
    assert report_json.headers["X-Report-SHA256"]
    assert b"<img src=x" not in report_html.data
    reopened = transition(client, case_id, "reopened")
    assert reopened.status_code == 200
    after = client.get(f"/api/incidents/{case_id}").json
    assert after["status"] == "reopened"
    assert len(after["reports"]) == 2
    assert len(after["history"]) >= 8


def test_e2e_24_case_closure_requires_evidence_tasks_and_report(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("soc_manager")
    case = client.post("/api/incidents", json={"title": "Incomplete closure case"})
    case_id = case.json["id"]
    assert transition(client, case_id, "investigating").status_code == 200
    assert transition(client, case_id, "contained").status_code == 200
    assert transition(client, case_id, "recovered").status_code == 200
    rejected = transition(client, case_id, "closed", disposition="true_positive")
    assert rejected.status_code == 409
    assert rejected.json["error"]["code"] == "CASE_CLOSURE_INCOMPLETE"


def test_e2e_26_optimistic_lock_detects_concurrent_case_update(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("analyst")
    created = client.post("/api/incidents", json={"title": "Concurrent acceptance case"}).json
    version = created["version"]
    first = client.patch(f"/api/incidents/{created['id']}", json={"version": version, "title": "First accepted title"})
    second = client.patch(f"/api/incidents/{created['id']}", json={"version": version, "title": "Stale rejected title"})
    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json["error"]["code"] == "CASE_VERSION_CONFLICT"


def test_e2e_13_csv_import_pipeline_and_duplicate_retry(autopsy_case: int, client: FlaskClient, login_as: Callable[[str], None]) -> None:
    content = "source,event_time,event_type,category,severity,title,source_ip,username,action,outcome\nfixture,2026-10-19T10:00:00Z,failed_login,authentication,medium,Failure one,198.51.100.20,amina,login,failed\nfixture,2026-10-19T10:01:00Z,failed_login,authentication,medium,Failure two,198.51.100.20,amina,login,failed\n"
    preview = client.post(f"/api/cases/{autopsy_case}/imports/preview", json={"filename": "events.csv", "format": "auto", "content": content})
    assert preview.status_code == 200
    assert preview.json["format"] == "csv"
    assert len(preview.json["preview"]) == 2
    imported = client.post(f"/api/cases/{autopsy_case}/imports", json={"filename": "events.csv", "format": "auto", "content": content})
    assert imported.status_code == 201
    assert imported.json["accepted"] == 2
    assert imported.json["accepted"] + imported.json["rejected"] + imported.json["skipped"] == imported.json["total"]
    duplicate = client.post(f"/api/cases/{autopsy_case}/imports", json={"filename": "events.csv", "format": "auto", "content": content})
    assert duplicate.status_code == 200
    assert duplicate.json["duplicate"] is True


def test_e2e_14_json_import_counts_rejected_rows(autopsy_case: int, client: FlaskClient, login_as: Callable[[str], None]) -> None:
    content = json.dumps(
        [
            {"source": "json-fixture", "event_time": "2026-10-19T10:00:00Z", "event_type": "routine_activity", "severity": "low", "title": "Valid"},
            {"source": "json-fixture", "event_time": "not-a-date", "event_type": "routine_activity", "severity": "low", "title": "Invalid"},
        ]
    )
    imported = client.post(f"/api/cases/{autopsy_case}/imports", json={"filename": "events.json", "format": "json", "content": content})
    assert imported.status_code == 201
    assert imported.json["accepted"] == 1
    assert imported.json["rejected"] == 1
    detail = client.get(f"/api/cases/{autopsy_case}/imports/{imported.json['id']}").json
    assert detail["status"] == "completed_with_errors"
    assert detail["errors"][0]["error_code"] == "VALIDATION_ERROR"


def test_import_evidence_is_encrypted_recoverable_and_cancellable(
    autopsy_case: int, client: FlaskClient, login_as: Callable[[str], None], database: sqlite3.Connection
) -> None:
    content = '{"source":"recovery-fixture","event_type":"recovered_event","severity":"low","title":"Recovered import"}'
    queued = client.post(f"/api/cases/{autopsy_case}/imports?defer=1", json={"filename": "recovery.jsonl", "format": "jsonl", "content": content})
    assert queued.status_code == 202
    assert queued.json["status"] == "queued"
    assert queued.json["raw_evidence"] == {"available": True, "sha256": hashlib.sha256(content.encode()).hexdigest(), "size": len(content)}
    assert "evidence_ciphertext" not in queued.json
    stored = database.execute("SELECT evidence_ciphertext FROM ingestion_jobs WHERE id = ?", (queued.json["id"],)).fetchone()[0]
    assert content not in stored
    database.execute("UPDATE ingestion_jobs SET status = 'processing' WHERE id = ?", (queued.json["id"],))
    ensure_schema(database)
    assert database.execute("SELECT status FROM ingestion_jobs WHERE id = ?", (queued.json["id"],)).fetchone()[0] == "interrupted"
    resumed = client.post(f"/api/cases/{autopsy_case}/imports/{queued.json['id']}/resume")
    assert resumed.status_code == 200
    assert resumed.json["status"] == "completed"
    assert resumed.json["accepted"] == 1
    assert resumed.json["checkpoint"] == 1
    assert resumed.json["retry_count"] == 1
    evidence = client.get(f"/api/cases/{autopsy_case}/imports/{queued.json['id']}/original")
    assert evidence.status_code == 200
    assert evidence.data == content.encode()
    assert evidence.headers["X-Evidence-SHA256"] == hashlib.sha256(content.encode()).hexdigest()
    cancelled_content = content.replace("Recovered", "Cancelled").replace("recovered_event", "cancelled_event")
    cancellable = client.post(f"/api/cases/{autopsy_case}/imports?defer=1", json={"filename": "cancel.jsonl", "format": "jsonl", "content": cancelled_content})
    cancelled = client.post(f"/api/cases/{autopsy_case}/imports/{cancellable.json['id']}/cancel")
    assert cancelled.status_code == 200
    assert cancelled.json["status"] == "cancelled"
    assert client.post(f"/api/cases/{autopsy_case}/imports/{cancellable.json['id']}/resume").status_code == 409


def test_e2e_18_and_19_source_credentials_are_redacted_and_health_is_truthful(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("admin")
    created = client.post(
        "/api/sources",
        json={"name": "Local acceptance fixture", "type": "file", "endpoint": None, "credential": "never-return-this-secret", "is_active": True},
    )
    assert created.status_code == 201
    serialized = created.get_data(as_text=True)
    assert "never-return-this-secret" not in serialized
    assert "credential_ciphertext" not in serialized
    assert created.json["credentials_stored"] is True
    tested = client.post(f"/api/sources/{created.json['id']}/test", json={})
    assert tested.status_code == 200
    assert tested.json["status"] == "connected"
    http_source = client.post(
        "/api/sources",
        json={"name": "Unconfigured HTTP fixture", "type": "http", "endpoint": "https://sandbox.example", "is_active": True},
    )
    tested_http = client.post(f"/api/sources/{http_source.json['id']}/test", json={})
    assert tested_http.json["status"] == "not_configured"
    assert tested_http.json["status"] != "connected"
