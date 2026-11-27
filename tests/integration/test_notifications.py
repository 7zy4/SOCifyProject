"""In-app notifications reach the people who must act, once, only while they can see the case, and never carry case text."""

import hashlib
import hmac
import json
import time
from datetime import timedelta

from socify.quick_reports import QUICK_REPORT_QUESTIONS
from socify.timeutils import utc_now

ANSWERS = {q["id"]: q["options"][0]["value"] for q in QUICK_REPORT_QUESTIONS}


def _case(client, **extra):
    made = client.post("/api/cases", json={"title": "Credential stuffing on the portal", "reason": "alert_review", "objective": "Contain and scope", **extra})
    assert made.status_code == 201, made.json
    return made.json


def _inbox(client):
    answer = client.get("/api/notifications")
    assert answer.status_code == 200
    return answer.json


def _move(client, case_id, *states):
    for state in states:
        version = client.get(f"/api/cases/{case_id}").json["version"]
        moved = client.post(f"/api/cases/{case_id}/transitions", json={"status": state, "reason": f"Moving to {state}", "version": version})
        assert moved.status_code in {200, 201}, moved.json


def test_an_assigned_case_reaches_its_analyst_and_not_the_person_who_assigned_it(client, database, login_as, user_ids):
    login_as("soc_manager")
    case = _case(client, assignee=user_ids["analyst"])
    assert _inbox(client)["unread"] == 0
    login_as("analyst")
    inbox = _inbox(client)
    assert inbox["unread"] == 1 and client.get("/api/notifications/unread").json["unread"] == 1
    [item] = inbox["items"]
    assert item["kind"] == "case_assigned" and item["case"]["reference"] == case["reference"] and item["actor_name"] and not item["read"]
    stored = database.execute("SELECT * FROM notifications").fetchone()
    assert set(dict(stored)) == {"id", "workspace_id", "user_id", "kind", "case_id", "intake_alert_id", "actor_id", "dedup_key", "created_at", "read_at"}
    assert client.post(f"/api/notifications/{item['id']}/read").status_code == 200
    assert _inbox(client)["unread"] == 0
    login_as("instructor")
    assert client.post(f"/api/notifications/{item['id']}/read").status_code == 404


def test_reassigning_notifies_the_new_analyst_and_read_all_clears_the_count(client, login_as, user_ids):
    login_as("soc_manager")
    case = _case(client)
    version = client.get(f"/api/cases/{case['id']}").json["version"]
    assert client.patch(f"/api/incidents/{case['id']}", json={"version": version, "assignee": user_ids["analyst"]}).status_code == 200
    login_as("analyst")
    assert [item["kind"] for item in _inbox(client)["items"]] == ["case_assigned"]
    assert client.post("/api/notifications/read-all", json={"unexpected": 1}).status_code == 422
    assert client.post("/api/notifications/read-all").json["marked"] == 1
    assert _inbox(client)["unread"] == 0


def test_a_notification_disappears_when_its_case_is_no_longer_visible(client, database, login_as, user_ids):
    login_as("soc_manager")
    case = _case(client, assignee=user_ids["analyst"])
    login_as("analyst")
    assert _inbox(client)["unread"] == 1
    database.execute("UPDATE incident_cases SET assignee = NULL, creator = ? WHERE id = ?", (user_ids["soc_manager"], case["id"]))
    database.execute("DELETE FROM autopsy_case_members WHERE case_id = ? AND user_id = ?", (case["id"], user_ids["analyst"]))
    assert _inbox(client) == {"items": [], "unread": 0}


def test_a_case_waiting_for_review_reaches_the_reviewers_and_returns_to_the_analyst(client, login_as, user_ids):
    login_as("analyst")
    case = _case(client, assignee=user_ids["analyst"])
    _move(client, case["id"], "investigating", "awaiting_review")
    login_as("soc_manager")
    assert [item["kind"] for item in _inbox(client)["items"]] == ["review_requested"]
    _move(client, case["id"], "investigating")
    login_as("analyst")
    assert "case_returned" in [item["kind"] for item in _inbox(client)["items"]]


def test_an_escalation_reaches_the_managers_and_the_decision_comes_back(client, login_as):
    login_as("analyst")
    case = _case(client)
    assert client.post(f"/api/cases/{case['id']}/quick-report/escalate", json={"answers": ANSWERS}).status_code == 200
    login_as("soc_manager")
    assert [item["kind"] for item in _inbox(client)["items"]] == ["escalated"]
    decided = client.post(f"/api/cases/{case['id']}/quick-report/acknowledge", json={"decision": "needs_followup", "comment": "Check the VPN logs"})
    assert decided.status_code == 200, decided.json
    login_as("analyst")
    assert "escalation_decided" in [item["kind"] for item in _inbox(client)["items"]]


def test_severe_incoming_alerts_reach_triagers_once(client, database, login_as):
    login_as("soc_manager")
    created = client.post("/api/intake/integrations", json={"kind": "generic", "name": "Lab SIEM", "auth_mode": "hmac"}).json
    with client.session_transaction() as state:
        state.clear()
    body = json.dumps(
        {"alerts": [{"id": "n-1", "title": "Ransomware behaviour", "severity": "critical"}, {"id": "n-2", "title": "Port scan", "severity": "low"}]}
    ).encode()
    stamp = str(int(time.time()))
    signature = hmac.new(created["hmac_secret"].encode(), stamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    headers = {"X-SOCify-Timestamp": stamp, "X-SOCify-Signature": f"sha256={signature}", "Content-Type": "application/json"}
    assert client.post(created["item"]["endpoint"], data=body, headers=headers).status_code == 202
    login_as("analyst")
    [item] = _inbox(client)["items"]
    assert item["kind"] == "intake_alert" and item["alert"]["severity"] == "critical" and item["case"] is None
    login_as("auditor")
    assert _inbox(client)["items"] == []
    from socify.intake import _notify_severe

    login_as("analyst")
    with client.application.test_request_context():
        integration = database.execute("SELECT * FROM intake_integrations").fetchone()
        _notify_severe(integration, [item["alert"]["id"]])
    assert len(_inbox(client)["items"]) == 1


def test_the_sla_check_warns_at_eighty_percent_and_reports_a_breach_once(app, client, database, login_as, user_ids):
    from socify.notifications import check_sla_deadlines

    login_as("soc_manager")
    assert (
        client.put(
            "/api/team/sla-policy", json={"minutes": {"critical": 10, "high": 100, "medium": 100, "low": 100}, "calendar": {"mode": "24x7", "timezone": "UTC"}}
        ).status_code
        == 200
    )
    warned = _case(client, severity="high", assignee=user_ids["analyst"])
    breached = _case(client, severity="critical", assignee=user_ids["analyst"])
    stamp = lambda minutes: (utc_now() - timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")  # noqa: E731
    database.execute("UPDATE incident_cases SET created_at = ? WHERE id = ?", (stamp(85), warned["id"]))
    database.execute("UPDATE incident_cases SET created_at = ? WHERE id = ?", (stamp(20), breached["id"]))
    with app.app_context():
        assert check_sla_deadlines() >= 3
        assert check_sla_deadlines() == 0
    login_as("analyst")
    kinds = {(item["kind"], item["case"]["id"]) for item in _inbox(client)["items"]}
    assert {("sla_warning", warned["id"]), ("sla_breached", breached["id"])} <= kinds
    login_as("soc_manager")
    kinds = {(item["kind"], item["case"]["id"]) for item in _inbox(client)["items"]}
    assert ("sla_breached", breached["id"]) in kinds and ("sla_warning", warned["id"]) not in kinds


def test_old_notifications_are_pruned(app, client, database, login_as, user_ids):
    from socify.notifications import check_sla_deadlines

    login_as("soc_manager")
    _case(client, assignee=user_ids["analyst"])
    database.execute("UPDATE notifications SET created_at = ?", ((utc_now() - timedelta(days=91)).isoformat().replace("+00:00", "Z"),))
    with app.app_context():
        check_sla_deadlines()
    assert database.execute("SELECT COUNT(*) FROM notifications").fetchone()[0] == 0


def test_only_a_manager_reassigns_a_case_and_the_new_analyst_can_open_it(client, login_as, user_ids):
    login_as("analyst")
    case = _case(client)
    version = client.get(f"/api/cases/{case['id']}").json["version"]
    refused = client.patch(f"/api/incidents/{case['id']}", json={"version": version, "assignee": user_ids["instructor"]})
    assert refused.status_code == 403
    login_as("soc_manager")
    assert client.patch(f"/api/incidents/{case['id']}", json={"version": version, "assignee": user_ids["instructor"]}).status_code == 200
    login_as("instructor")
    assert client.get(f"/api/cases/{case['id']}").status_code == 200
