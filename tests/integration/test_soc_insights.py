import json
from datetime import timedelta

import pytest

from socify.autopsy_report_render import render_html
from socify.autopsy_reports import build_snapshot
from socify.cases import _case_row
from socify.quick_reports import QUICK_REPORT_QUESTIONS
from socify.timeutils import iso_now, utc_now


def upload(client, case_id, name="upload.json", command="powershell.exe -enc AAAA"):
    result = client.post(
        f"/api/cases/{case_id}/imports",
        json={
            "filename": name,
            "content": json.dumps([{"title": name, "hostname": "workstation-23", "process_name": "powershell.exe", "command_line": command}]),
        },
    )
    assert result.status_code == 201, result.json
    return client.get(f"/api/cases/{case_id}/alerts").json["items"]


def test_real_upload_alert_decisions_and_report_snapshots(autopsy_case, app, client, database, login_as):
    base = f"/api/cases/{autopsy_case}"
    assert client.get(base + "/quick-report").json["default_answers"] == {}
    assert all(question["default"] == "" for question in client.get(base + "/quick-report").json["questions"])
    assert client.put(base + "/quick-report", json={"answers": {}}).status_code == 422
    alerts = upload(client, autopsy_case)
    assert alerts
    alert = alerts[0]
    reviewed = client.patch(
        base + f"/alerts/{alert['id']}",
        json={
            "version": 0,
            "verdict": "malicious",
            "attack_outcome": "blocked",
            "group": "PowerShell",
            "suppressed_until": None,
            "reason": "Execution blocked by endpoint policy",
        },
    )
    assert reviewed.status_code == 200, reviewed.json
    answers = {question["id"]: question["options"][0]["value"] for question in QUICK_REPORT_QUESTIONS}
    answers["incident_classification"] = "malware_execution"
    assert client.put(base + "/quick-report", json={"answers": answers, "executive_note": "Retained investigation conclusion"}).status_code == 200
    dossier = client.get(base + f"/alerts/{alert['id']}/dossier")
    assert dossier.status_code == 200, dossier.json
    assert dossier.json["events"][0]["hostname"] == "workstation-23"
    assert dossier.json["review"]["attack_outcome"] == "blocked"
    assert dossier.json["assessment"]["answers"] == answers
    # A second investigation starts empty and receives only its own uploaded logs.
    second = client.post("/api/cases", json={"title": "Independent upload"}).json["id"]
    assert client.get(f"/api/cases/{second}/logs").json["total"] == 0
    assert client.get(f"/api/cases/{second}/quick-report").json["report"] is None
    assert client.get(f"/api/cases/{second}/alerts/{alert['id']}/dossier").status_code == 404
    login_as("soc_manager")
    with app.test_request_context():
        from flask import session

        with client.session_transaction() as saved:
            session.update(dict(saved))
        snapshot = build_snapshot(_case_row(autopsy_case), 1, "full")
        redacted = build_snapshot(_case_row(autopsy_case), 1, "metadata_only_v1")
    assert snapshot["investigation_assessment"]["answers"] == answers
    assert snapshot["alerts"][0]["review"]["verdict"] == "malicious"
    assert "investigation_assessment" not in redacted
    rendered = render_html(snapshot)
    assert "Retained investigation conclusion" in rendered
    answers["incident_classification"] = "unauthorized_access"
    assert client.put(base + "/quick-report", json={"answers": answers}).status_code == 200
    assert snapshot["investigation_assessment"]["answers"]["incident_classification"] == "malware_execution"
    assert client.get(base + f"/alerts/{alert['id']}/dossier").json["assessment"]["answers"]["incident_classification"] == "unauthorized_access"


def test_performance_period_ownership_tasks_and_missing_times(autopsy_case, client, login_as, database, user_ids):
    now = iso_now()
    old = (utc_now() - timedelta(days=45)).isoformat()
    database.execute("UPDATE incident_cases SET assignee=?,sla_due_at=?,created_at=? WHERE id=?", (user_ids["analyst"], old, old, autopsy_case))
    upload(client, autopsy_case)
    data = client.get("/api/soc/performance?member=me&days=7").json
    assert data["counts"]["open"] == data["counts"]["overdue"] == 1
    assert data["counts"]["unreviewed_alerts"] > 0
    assert data["trend"] == []  # Current backlog survives period filtering.
    assert all(metric["median_seconds"] is None for metric in data["metrics"].values())
    database.execute(
        "INSERT INTO case_tasks(case_id,title,status,assignee,completed_by,completed_at,created_at) VALUES (?,'Evidence review','completed',?,?,?,?)",
        (autopsy_case, user_ids["analyst"], user_ids["analyst"], now, old),
    )
    database.execute("UPDATE incident_cases SET status='closed',closed_at=? WHERE id=?", (now, autopsy_case))
    data = client.get("/api/soc/performance?days=7").json
    assert data["counts"]["closed"] == 1 and data["counts"]["open"] == 0
    assert data["members"][0]["tasks_completed"] == 1
    assert data["metrics"]["closure_delay_seconds"] == {"median_seconds": None, "included": 0, "excluded": 1}
    assert client.get("/api/soc/performance?member=team").status_code == 403
    assert client.get(f"/api/soc/performance?member={user_ids['soc_manager']}").status_code == 403
    login_as("soc_manager")
    assert client.get("/api/soc/performance?member=team").status_code == 200
    assert client.get(f"/api/soc/performance?member={user_ids['analyst']}").json["counts"]["closed"] == 1


def test_performance_and_dossier_obey_membership_selection_approval(autopsy_case, app, client, login_as, database, user_ids):
    alert = upload(client, autopsy_case)[0]
    login_as("soc_manager")
    private = client.post("/api/cases", json={"title": "Restricted case title"}).json["id"]
    upload(client, private)
    login_as("analyst")
    assert "Restricted case title" not in client.get("/api/soc/performance").text
    database.execute("DELETE FROM autopsy_case_members WHERE case_id=?", (autopsy_case,))
    assert client.get("/api/soc/performance").json["counts"]["open"] == 0
    path = f"/api/cases/{autopsy_case}/alerts/{alert['id']}/dossier"
    assert client.get(path).status_code in {403, 404, 409}
    login_as("soc_manager")
    app.config["REQUIRE_INVESTIGATION_SELECTION"] = True
    assert client.get("/api/soc/performance").json["counts"]["open"] == 0
    assert client.get(path).status_code in {403, 404, 409}
    app.config["REQUIRE_INVESTIGATION_SELECTION"] = False
    app.config["REQUIRE_CASE_APPROVAL"] = True
    database.execute("UPDATE case_approvals SET state='pending' WHERE case_id=?", (autopsy_case,))
    assert client.get(path).status_code in {403, 404, 409}


@pytest.mark.parametrize("query", ["days=0", "days=-1", "days=1&days=7", "member=no", "member=0", "member=-1", "unknown=1", "member=9999999999999999999999"])
def test_performance_rejects_bad_filters(autopsy_case, client, query):
    assert client.get("/api/soc/performance?" + query).status_code == 422


def test_observed_hosts_are_derived_from_active_case_logs(autopsy_case, client, database, login_as):
    upload(client, autopsy_case)
    path = f"/api/cases/{autopsy_case}/observed-hosts"
    data = client.get(path + "?host=workstation-23").json
    assert data["total"] == 1
    assert data["items"][0]["first_seen"] is None
    assert data["events"][0]["process_name"] == "powershell.exe"
    assert data["events"][0]["command_line"] == "powershell.exe -enc AAAA"
    assert client.get(path + "?q=station").json["total"] == 1
    assert client.get(path + "?q=%25").json["total"] == 0
    assert client.get(path + "?page=2").json["items"] == []
    for query in ("page=0", "page=x", "page=1&page=2", "wrong=1", "host=" + "x" * 513):
        assert client.get(path + "?" + query).status_code == 422
    database.execute("UPDATE security_events SET autopsy_active=0 WHERE owner_case_id=?", (autopsy_case,))
    assert client.get(path).json["total"] == 0
    database.execute("DELETE FROM autopsy_case_members WHERE case_id=?", (autopsy_case,))
    assert client.get(path).status_code in {403, 404}


def test_evidenced_performance_durations_do_not_use_import_times(autopsy_case, client, database):
    now = utc_now()
    created = (now - timedelta(hours=5)).isoformat()
    closed = (now - timedelta(hours=1)).isoformat()
    database.execute("UPDATE incident_cases SET created_at=?,closed_at=?,status='closed' WHERE id=?", (created, closed, autopsy_case))
    owner = database.execute("SELECT creator FROM incident_cases WHERE id=?", (autopsy_case,)).fetchone()[0]
    for phase, hours in (("detection", 4), ("acknowledgement", 3), ("containment", 2), ("recovery", 1)):
        payload = json.dumps({"phase": phase, "performed_at": (now - timedelta(hours=hours)).isoformat(), "status": "succeeded", "evidence_id": 1})
        database.execute(
            "INSERT INTO autopsy_records(case_id,kind,payload,created_by,updated_by,created_at,updated_at) VALUES (?,'response',?,?,?,?,?)",
            (autopsy_case, payload, owner, owner, created, created),
        )
    metrics = client.get("/api/soc/performance?member=me").json["metrics"]
    assert metrics["acknowledgement_delay_seconds"]["median_seconds"] == 3600
    assert metrics["closure_delay_seconds"]["median_seconds"] == 10800
    assert metrics["detection_delay_seconds"]["median_seconds"] is None
    assert client.get("/api/soc/performance?days=all").status_code == 200


def test_normal_startup_never_populates_operational_evidence(tmp_path):
    from socify import create_app
    from socify.db import get_db

    config = {
        "DATABASE": str(tmp_path / "blank.db"),
        "TESTING": True,
        "LEGACY_TRAINING_TESTS": False,
        "SECRET_KEY": "test-only-startup",
        "CREDENTIAL_KEY": "test-only-startup",
    }
    for _ in range(2):
        app = create_app(config)
        with app.app_context():
            for table in ("incident_cases", "security_events", "alerts", "autopsy_reports", "case_quick_reports"):
                assert get_db().execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
