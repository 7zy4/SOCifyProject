import hashlib
import json
import sqlite3
from collections.abc import Callable

from flask.testing import FlaskClient


def failed_login(client: FlaskClient, number: int, source_ip: str = "198.51.100.20", prefix: str = "login"):
    return client.post(
        "/api/events",
        headers={"Idempotency-Key": f"{prefix}-{source_ip}-{number}"},
        json={
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
    )


def generated_alert(client: FlaskClient, prefix: str = "alert") -> int:
    responses = [failed_login(client, index, prefix=prefix) for index in range(1, 6)]
    assert all(response.status_code == 201 for response in responses)
    alert_ids = responses[-1].json["detections"]
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


def test_e2e_06_dashboard_matches_database(
    client: FlaskClient,
    login_as: Callable[[str], None],
    database: sqlite3.Connection,
) -> None:
    login_as("analyst")
    generated_alert(client, "dashboard")
    case = client.post("/api/incidents", json={"title": "Dashboard count case", "severity": "high"})
    assert case.status_code == 201
    dashboard = client.get("/api/dashboard")
    assert dashboard.status_code == 200
    payload = dashboard.json
    assert payload["counts"]["events"] == database.execute("SELECT COUNT(*) FROM security_events WHERE source != 'rules_engine'").fetchone()[0]
    assert payload["counts"]["open_alerts"] == database.execute("SELECT COUNT(*) FROM alerts WHERE status NOT IN ('closed', 'false_positive', 'suppressed')").fetchone()[0]
    assert payload["counts"]["active_cases"] == database.execute("SELECT COUNT(*) FROM incident_cases WHERE status NOT IN ('closed', 'cancelled', 'false_positive')").fetchone()[0]


def test_e2e_07_empty_dashboard_and_case_state_are_truthful(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("analyst")
    dashboard = client.get("/api/dashboard").json
    cases = client.get("/api/incidents").json
    assert dashboard["counts"]["events"] == 0
    assert dashboard["counts"]["open_alerts"] == 0
    assert cases["items"] == []
    assert cases["total"] == 0


def test_e2e_09_rule_crud_test_version_rollback_clone_archive(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("admin")
    event = client.post(
        "/api/events",
        json={
            "source": "rule-test",
            "severity": "high",
            "category": "system",
            "event_type": "critical_error",
            "title": "Synthetic critical error",
            "raw_payload": {"synthetic": True},
        },
    )
    assert event.status_code == 201
    payload = {
        "name": "Acceptance critical rule",
        "description": "Detect the isolated critical error fixture",
        "dsl": {"condition": {"field": "event_type", "operator": "equals", "value": "critical_error"}},
        "action": {"severity": "critical", "confidence": 0.99},
        "active": False,
        "change_summary": "Acceptance version one",
    }
    created = client.post("/api/rules", json=payload)
    assert created.status_code == 201
    rule_id = created.json["id"]
    preview = client.post(f"/api/rules/{rule_id}/test", json={"event_id": event.json["id"]})
    assert preview.status_code == 200
    assert preview.json["matched"] is True
    assert preview.json["persisted_alert"] is False
    payload["description"] = "Updated acceptance description"
    payload["active"] = True
    payload["change_summary"] = "Acceptance version two"
    updated = client.put(f"/api/rules/{rule_id}", json=payload)
    assert updated.status_code == 200
    assert updated.json["version"] == 2
    assert updated.json["is_active"] == 1
    versions = client.get(f"/api/rules/{rule_id}/versions").json["items"]
    assert [item["version"] for item in versions] == [2, 1]
    rolled_back = client.post(f"/api/rules/{rule_id}/rollback", json={"version": 1})
    assert rolled_back.status_code == 200
    assert rolled_back.json["version"] == 3
    cloned = client.post(f"/api/rules/{rule_id}/clone", json={"name": "Cloned acceptance rule"})
    assert cloned.status_code == 201
    assert cloned.json["deployment_state"] == "draft"
    assert client.delete(f"/api/rules/{cloned.json['id']}").status_code == 204
    archived = client.get("/api/rules?archived=1").json["items"]
    assert any(item["id"] == cloned.json["id"] and item["archived_at"] for item in archived)


def test_e2e_10_failed_login_window_creates_one_explainable_alert(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("analyst")
    first_four = [failed_login(client, index, prefix="threshold") for index in range(1, 5)]
    assert all(response.json["detections"] == [] for response in first_four)
    fifth = failed_login(client, 5, prefix="threshold")
    assert len(fifth.json["detections"]) == 1
    alert = client.get(f"/api/alerts/{fifth.json['detections'][0]}")
    assert alert.status_code == 200
    assert len(alert.json["events"]) == 5
    assert alert.json["rule_version"] == 1
    assert alert.json["mitre_technique_ids"] == ["T1110"]
    assert alert.json["trace"]["condition"]["matched"] is True


def test_e2e_11_grouping_does_not_mix_source_ips(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("analyst")
    for index in range(1, 5):
        assert failed_login(client, index, "198.51.100.20", "group").json["detections"] == []
    different = failed_login(client, 5, "203.0.113.40", "group")
    assert different.json["detections"] == []


def test_e2e_12_event_and_alert_idempotency(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("analyst")
    for index in range(1, 5):
        failed_login(client, index, prefix="dedup")
    fifth = failed_login(client, 5, prefix="dedup")
    replay = failed_login(client, 5, prefix="dedup")
    assert fifth.status_code == 201
    assert replay.status_code == 200
    assert replay.json["duplicate"] is True
    assert replay.json["id"] == fifth.json["id"]
    assert client.get("/api/alerts").json["total"] == 1


def test_rule_disable_prevents_detection_and_invalid_dsl_is_rejected(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("admin")
    rules = client.get("/api/rules").json["items"]
    threshold = next(item for item in rules if item["name"] == "Five failed logins in ten minutes")
    assert client.post(f"/api/rules/{threshold['id']}/toggle", json={"active": False}).status_code == 200
    login_as("analyst")
    for index in range(1, 6):
        assert failed_login(client, index, prefix="disabled").json["detections"] == []
    login_as("admin")
    malicious = client.post(
        "/api/rules",
        json={
            "name": "Unsafe expression",
            "description": "Must be rejected",
            "dsl": {"condition": {"field": "event_type", "operator": "eval", "value": "__import__('os')"}},
        },
    )
    assert malicious.status_code == 422
    assert malicious.json["error"]["code"] == "INVALID_RULE"


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
        lessons_learned="Tune identity detections",
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


def test_e2e_13_csv_import_pipeline_and_duplicate_retry(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("analyst")
    content = "source,event_time,event_type,category,severity,title,source_ip,username,action,outcome\nfixture,2026-10-19T10:00:00Z,failed_login,authentication,medium,Failure one,198.51.100.20,amina,login,failed\nfixture,2026-10-19T10:01:00Z,failed_login,authentication,medium,Failure two,198.51.100.20,amina,login,failed\n"
    preview = client.post("/api/imports/preview", json={"filename": "events.csv", "format": "auto", "content": content})
    assert preview.status_code == 200
    assert preview.json["format"] == "csv"
    assert len(preview.json["preview"]) == 2
    imported = client.post("/api/imports", json={"filename": "events.csv", "format": "auto", "content": content})
    assert imported.status_code == 201
    assert imported.json["accepted"] == 2
    assert imported.json["accepted"] + imported.json["rejected"] + imported.json["skipped"] == imported.json["total"]
    duplicate = client.post("/api/imports", json={"filename": "events.csv", "format": "auto", "content": content})
    assert duplicate.status_code == 200
    assert duplicate.json["duplicate"] is True
    result = client.post("/api/hunt/query", json={"query": "source=fixture AND event_type=failed_login"})
    assert result.status_code == 200
    assert result.json["total"] == 2


def test_e2e_14_json_import_counts_rejected_rows(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("analyst")
    content = json.dumps([
        {"source": "json-fixture", "event_time": "2026-10-19T10:00:00Z", "event_type": "routine_activity", "severity": "low", "title": "Valid"},
        {"source": "json-fixture", "event_time": "not-a-date", "event_type": "routine_activity", "severity": "low", "title": "Invalid"},
    ])
    imported = client.post("/api/imports", json={"filename": "events.json", "format": "json", "content": content})
    assert imported.status_code == 201
    assert imported.json["accepted"] == 1
    assert imported.json["rejected"] == 1
    detail = client.get(f"/api/imports/{imported.json['id']}").json
    assert detail["status"] == "completed_with_errors"
    assert detail["errors"][0]["error_code"] == "VALIDATION_ERROR"


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


def test_event_export_neutralizes_spreadsheet_formula(client: FlaskClient, login_as: Callable[[str], None], event_payload: dict[str, object]) -> None:
    login_as("analyst")
    payload = {**event_payload, "title": "=HYPERLINK(\"https://invalid.test\")", "idempotency_key": "csv-formula-test"}
    assert client.post("/api/events", json=payload).status_code == 201
    exported = client.get("/api/events/export")
    assert exported.status_code == 200
    assert "'=HYPERLINK" in exported.get_data(as_text=True)
