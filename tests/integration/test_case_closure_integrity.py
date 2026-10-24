import hashlib
import json
import sqlite3

import pytest

from socify import cases


def prepared_case(client, login_as):
    login_as("soc_manager")
    created = client.post("/api/incidents", json={"title": "Closure integrity exercise"})
    assert created.status_code == 201
    case_id = created.json["id"]
    url = f"/api/incidents/{case_id}"
    evidence = client.post(
        url + "/evidence",
        json={"type": "raw_log", "reference_id": "closure-log", "title": "Synthetic log", "content": "Training evidence"},
    )
    assert evidence.status_code == 201
    for task in client.get(url).json["tasks"]:
        assert client.patch(f"{url}/tasks/{task['id']}", json={"status": "completed"}).status_code == 200
    for status in ("investigating", "contained", "recovered"):
        assert client.post(url + "/transitions", json={"status": status, "reason": "Reviewed exercise transition"}).status_code == 200
    return case_id, evidence.json["id"]


def closure_payload():
    return {
        "status": "closed",
        "reason": "Validated exercise closure",
        "disposition": "true_positive",
        "root_cause": "Synthetic credential abuse",
        "impact": "Training identity exposure",
        "response_summary": "Contained simulated source",
        "evidence_summary": "Reviewed original log and digest",
        "lessons_learned": "Improve detection review",
        "validation": "Verified containment and hashes",
    }


@pytest.mark.parametrize("field", ["evidence_summary", "validation"])
def test_closure_requires_evidence_summary_and_validation(client, login_as, field):
    case_id, _ = prepared_case(client, login_as)
    payload = closure_payload()
    payload.pop(field)
    response = client.post(f"/api/incidents/{case_id}/transitions", json=payload)
    assert response.status_code == 409
    assert field in response.json["error"]["details"]["missing_fields"]
    assert client.get(f"/api/incidents/{case_id}").json["status"] == "recovered"


def test_report_failure_rolls_back_closure_and_partial_report(client, login_as, database, monkeypatch):
    case_id, _ = prepared_case(client, login_as)
    generate = cases._generate_reports

    def fail_after_reports(identifier):
        generate(identifier)
        raise RuntimeError("Injected report persistence failure")

    monkeypatch.setattr(cases, "_generate_reports", fail_after_reports)
    with pytest.raises(RuntimeError, match="Injected report"):
        client.post(f"/api/incidents/{case_id}/transitions", json=closure_payload())
    assert database.execute("SELECT status FROM incident_cases WHERE id = ?", (case_id,)).fetchone()[0] == "recovered"
    assert database.execute("SELECT COUNT(*) FROM case_reports WHERE case_id = ?", (case_id,)).fetchone()[0] == 0
    assert database.execute("SELECT COUNT(*) FROM case_history WHERE case_id = ? AND new_value = ?", (case_id, '"closed"')).fetchone()[0] == 0


def test_closure_reports_preserve_fields_hashes_and_old_revision(client, login_as, database):
    case_id, _ = prepared_case(client, login_as)
    url = f"/api/incidents/{case_id}"
    payload = closure_payload()
    payload["validation"] = "Reviewed <script>alert(1)</script> safely"
    assert client.post(url + "/transitions", json=payload).status_code == 200
    first = client.get(url + "/report?format=json")
    assert first.headers["X-Report-SHA256"] == hashlib.sha256(first.data).hexdigest()
    for field in ("evidence_summary", "validation", "lessons_learned", "disposition"):
        assert first.json["case"][field] == payload[field]
    report = client.get(url + "/report?format=html")
    assert b"<script>" not in report.data
    assert b"&lt;script&gt;" in report.data
    for status in ("reopened", "contained", "recovered"):
        assert client.post(url + "/transitions", json={"status": status, "reason": "Additional evidence review"}).status_code == 200
    payload["validation"] = "Second validated review"
    assert client.post(url + "/transitions", json=payload).status_code == 200
    rows = database.execute("SELECT revision, content FROM case_reports WHERE case_id = ? AND format = 'json' ORDER BY revision", (case_id,)).fetchall()
    assert [row["revision"] for row in rows] == [1, 2]
    assert rows[0]["content"].encode() == first.data
    assert json.loads(rows[1]["content"])["case"]["validation"] == "Second validated review"
    assert client.get(url + "/report?revision=1").data == first.data
    assert client.get(url + "/report?revision=999").status_code == 404
    assert client.get(url + "/report?revision=invalid").status_code == 422


def test_evidence_access_is_audited_and_content_cannot_be_replaced(client, login_as, database):
    case_id, evidence_id = prepared_case(client, login_as)
    url = f"/api/incidents/{case_id}/evidence/{evidence_id}"
    response = client.get(url)
    assert response.status_code == 200
    assert response.json["accessed_at"]
    assert response.json["sha256"] == hashlib.sha256(b"Training evidence").hexdigest()
    audit = database.execute(
        "SELECT * FROM security_audit_logs WHERE action = 'read' AND resource_type = 'case_evidence' AND resource_id = ?", (str(evidence_id),)
    ).fetchone()
    assert audit is not None
    for sql in ("UPDATE case_evidence SET sha256 = 'replacement' WHERE id = ?", "DELETE FROM case_evidence WHERE id = ?"):
        with pytest.raises(sqlite3.IntegrityError, match="immutable case evidence"):
            database.execute(sql, (evidence_id,))
    assert client.get(f"/api/incidents/{case_id + 999}/evidence/{evidence_id}").status_code == 404


def test_closure_override_records_reason(client, login_as, database):
    case_id, _ = prepared_case(client, login_as)
    response = client.post(
        f"/api/incidents/{case_id}/transitions",
        json={"status": "closed", "reason": "Manager exception", "override": True, "override_reason": "Approved documented training exception"},
    )
    assert response.status_code == 200
    row = database.execute(
        "SELECT details FROM security_audit_logs WHERE action = 'transition' AND resource_id = ? ORDER BY id DESC LIMIT 1", (str(case_id),)
    ).fetchone()
    assert json.loads(row["details"])["override_reason"] == "Approved documented training exception"


def test_private_case_subresources_deny_other_trainee(client, login_as, database):
    case_id, evidence_id = prepared_case(client, login_as)
    scenario = client.get("/api/scenarios").json["items"][0]["id"]
    run_id = client.post("/api/training/runs", json={"scenario_id": scenario}).json["id"]
    database.execute("UPDATE incident_cases SET training_run_id = ? WHERE id = ?", (run_id, case_id))
    url = f"/api/incidents/{case_id}"
    assert client.post(url + "/transitions", json=closure_payload()).status_code == 200
    login_as("analyst")
    for suffix in ("", "/report", "/report?format=html", f"/evidence/{evidence_id}"):
        response = client.get(url + suffix)
        assert response.status_code == 404
        assert "Training evidence" not in response.text
    assert client.get("/api/incidents").json["total"] == 0
    assert client.patch(url, json={"title": "Unauthorized replacement"}).status_code == 404
    assert client.post(url + "/notes", json={"body": "Unauthorized note"}).status_code == 404
    assert client.post(url + "/transitions", json={"status": "reopened", "reason": "Unauthorized reopen"}).status_code == 404
