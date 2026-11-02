"""Review decisions must obey the same evidence and state gates as case closure."""

import json

import pytest

from socify.quick_reports import QUICK_REPORT_QUESTIONS

ANSWERS = {q["id"]: q["options"][0]["value"] for q in QUICK_REPORT_QUESTIONS}


@pytest.mark.parametrize("note", ["", "   ", None])
def test_explicitly_cleared_note_is_not_restored_when_escalating(autopsy_case, client, note):
    base = f"/api/cases/{autopsy_case}"
    assert client.put(base + "/quick-report", json={"answers": ANSWERS, "executive_note": "Withdrawn finding"}).status_code == 200
    assert client.post(base + "/quick-report/escalate", json={"answers": ANSWERS}).json["report"]["executive_note"] == "Withdrawn finding"
    response = client.post(base + "/quick-report/escalate", json={"answers": ANSWERS, "executive_note": note})
    assert response.status_code == 200 and response.json["report"]["executive_note"] == ""
    assert "Withdrawn finding" not in client.get(f"/cases/{autopsy_case}/quick-report/print").text


def test_manager_close_cannot_bypass_case_requirements(autopsy_case, client, login_as, database):
    base = f"/api/cases/{autopsy_case}"
    assert client.post(base + "/quick-report/escalate", json={"answers": ANSWERS}).status_code == 200
    login_as("soc_manager")
    before = client.get(base).json
    report = client.get(base + "/quick-report").json
    assert not report["closure"]["ready"]
    assert {entry["tab"] for entry in report["closure"]["missing"]} >= {"summary", "logs", "investigation", "response", "reports"}
    denied = client.post(base + "/quick-report/acknowledge", json={"decision": "closed", "case_version": before["version"]})
    assert denied.status_code == 409
    assert denied.json["error"]["code"] == "CASE_CLOSURE_INCOMPLETE"
    assert client.get(base).json["status"] == "escalated"
    assert client.get(base).json["version"] == before["version"]
    assert client.get(base + "/quick-report").json["report"]["manager_decision"] is None
    assert database.execute("SELECT COUNT(*) FROM case_history WHERE case_id=? AND new_value=?", (autopsy_case, '"closed"')).fetchone()[0] == 0


@pytest.mark.parametrize("action", ["save", "escalate", "approve"])
def test_stale_review_cannot_replace_newer_case_work(autopsy_case, client, login_as, action):
    base = f"/api/cases/{autopsy_case}"
    assert client.put(base + "/quick-report", json={"answers": ANSWERS, "executive_note": "First review"}).status_code == 200
    version = client.get(base).json["version"]
    assert client.put(base + "/quick-report", json={"answers": ANSWERS, "executive_note": "Newer retained assessment"}).status_code == 200
    body = {"answers": ANSWERS, "case_version": version, "executive_note": "Stale replacement"}
    if action == "approve":
        login_as("soc_manager")
        result = client.post(base + "/quick-report/acknowledge", json={"decision": "approved", "case_version": version})
    elif action == "escalate":
        result = client.post(base + "/quick-report/escalate", json=body)
    else:
        result = client.put(base + "/quick-report", json=body)
    assert result.status_code == 409
    saved = client.get(base + "/quick-report").json["report"]
    assert saved["executive_note"] == "Newer retained assessment" and saved["manager_decision"] is None


def test_review_updates_invalidate_old_snapshot_and_closed_reviews_are_read_only(autopsy_case, client, login_as, database):
    base = f"/api/cases/{autopsy_case}"
    assert client.post(base + "/quick-report/escalate", json={"answers": ANSWERS}).status_code == 200
    first = client.get(base).json["version"]
    assert client.post(base + "/quick-report/escalate", json={"answers": ANSWERS}).status_code == 200
    assert client.get(base).json["version"] > first
    login_as("soc_manager")
    second = client.get(base).json["version"]
    assert client.post(base + "/quick-report/acknowledge", json={"decision": "approved", "case_version": second}).status_code == 200
    assert client.get(base).json["version"] > second
    saved = client.get(base + "/quick-report").json["report"]
    database.execute("UPDATE incident_cases SET status='closed' WHERE id=?", (autopsy_case,))
    assert not client.get(base + "/quick-report").json["can_acknowledge_as_manager"]
    denied = client.post(base + "/quick-report/acknowledge", json={"decision": "needs_followup"})
    assert denied.status_code == 409 and denied.json["error"]["code"] == "CASE_CLOSED"
    assert client.get(base + "/quick-report").json["report"] == saved


def test_analyst_without_close_permission_cannot_close(autopsy_case, client, login_as, database, user_ids):
    base = f"/api/cases/{autopsy_case}"
    assert client.put(base + "/quick-report", json={"answers": ANSWERS}).status_code == 200
    workspace = database.execute("SELECT workspace_id FROM users WHERE id=?", (user_ids["analyst"],)).fetchone()[0]
    database.execute(
        "INSERT OR REPLACE INTO team_role_permissions(workspace_id,role,permissions) VALUES (?,?,?)",
        (workspace, "analyst", json.dumps(["cases.read", "cases.update"])),
    )
    report = client.get(base + "/quick-report").json
    assert not report["closure"]["can_close"]
    response = client.post(base + "/quick-report/acknowledge", json={"decision": "closed", "case_version": report["case_version"]})
    assert response.status_code == 403


def test_legacy_resolved_case_can_return_to_canonical_review(autopsy_case, client, login_as, database):
    base = f"/api/cases/{autopsy_case}"
    database.execute("UPDATE incident_cases SET status='resolved' WHERE id=?", (autopsy_case,))
    login_as("soc_manager")
    current = client.get(base).json
    response = client.post(
        base + "/transitions", json={"status": "awaiting_review", "version": current["version"], "reason": "Review outstanding closure requirements"}
    )
    assert response.status_code == 200 and response.json["status"] == "awaiting_review"
