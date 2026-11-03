"""Dashboard review counts reflect the retained review decision and visible case scope."""

import pytest

from socify.quick_reports import QUICK_REPORT_QUESTIONS


def escalate(client, case_id):
    answers = {question["id"]: question["options"][0]["value"] for question in QUICK_REPORT_QUESTIONS}
    response = client.post(
        f"/api/cases/{case_id}/quick-report/escalate", json={"answers": answers, "executive_note": "Evidence review ready for an independent decision"}
    )
    assert response.status_code == 200, response.json


def waiting(client):
    response = client.get("/api/soc/performance?member=team")
    assert response.status_code == 200, response.json
    return response.json["counts"]["awaiting_review"]


def test_pending_review_appears_once_and_clears_on_decision(autopsy_case, client, login_as, database):
    escalate(client, autopsy_case)
    login_as("soc_manager")
    assert waiting(client) == 1
    # The formal review stage and quick-report escalation refer to the same case.
    database.execute("UPDATE incident_cases SET status='awaiting_review' WHERE id=?", (autopsy_case,))
    assert waiting(client) == 1
    database.execute("UPDATE incident_cases SET status='escalated' WHERE id=?", (autopsy_case,))
    response = client.post(f"/api/cases/{autopsy_case}/quick-report/acknowledge", json={"decision": "approved", "comment": "Review complete"})
    assert response.status_code == 200, response.json
    assert waiting(client) == 0
    escalate(client, autopsy_case)
    assert waiting(client) == 1


@pytest.mark.parametrize("state", ["closed", "cancelled"])
def test_inactive_case_does_not_create_pending_review_work(autopsy_case, client, login_as, database, state):
    escalate(client, autopsy_case)
    database.execute("UPDATE incident_cases SET status=? WHERE id=?", (state, autopsy_case))
    login_as("soc_manager")
    assert waiting(client) == 0


def test_member_and_selected_scope_limit_pending_review(autopsy_case, app, client, login_as, user_ids):
    escalate(client, autopsy_case)
    login_as("soc_manager")
    assert client.get(f"/api/soc/performance?member={user_ids['analyst']}").json["counts"]["awaiting_review"] == 1
    assert client.get("/api/soc/performance?member=me").json["counts"]["awaiting_review"] == 0
    app.config["REQUIRE_INVESTIGATION_SELECTION"] = True
    assert waiting(client) == 0
