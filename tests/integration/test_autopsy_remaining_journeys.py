import json
import threading
from concurrent.futures import ThreadPoolExecutor

from conftest import DEMO_LOGIN_VALUE
from test_autopsy_teams import new_member

from scripts.bootstrap_team import create_manager
from socify.timeutils import iso_now


def authenticated(app, email):
    browser = app.test_client()
    result = browser.post("/api/auth/login", json={"email": email, "password": DEMO_LOGIN_VALUE})
    assert result.status_code == 200, result.json
    return browser


def test_independent_teams_cannot_leak_duplicate_indicator_or_log_links(autopsy_case, app, client):
    first = f"/api/cases/{autopsy_case}"
    indicator = {"type": "ip", "value": "2001:0db8::40", "classification": "observable", "source": "Team-local retained source"}
    created_first = client.post(first + "/records/indicator", json=indicator)
    assert created_first.status_code == 201
    create_manager(app, "independent-team@example.test", "Independent manager", "Independent organization", DEMO_LOGIN_VALUE)
    other = authenticated(app, "independent-team@example.test")
    created = other.post(
        "/api/cases",
        json={
            "title": "Independent team investigation",
            "reason": "forensic_review",
            "objective": "Verify duplicate observables remain inside the owning team",
        },
    )
    assert created.status_code == 201
    second = f"/api/cases/{created.json['id']}"
    created_second = other.post(second + "/records/indicator", json=indicator)
    assert created_second.status_code == 201
    assert created_second.json["id"] != created_first.json["id"]
    duplicate = other.post(second + "/records/indicator", json={**indicator, "value": "2001:db8::40"})
    assert duplicate.status_code == 409
    assert duplicate.json["error"]["details"]["record_id"] == created_second.json["id"]
    assert other.get(first + "/records?kind=indicator").status_code == 404
    assert client.get(second + "/records?kind=indicator").status_code == 404
    assert other.post(first + "/records/indicator", json=indicator).status_code == 404
    assert all(row["id"] != autopsy_case for row in other.get("/api/cases").json["items"])
    for browser, base in ((client, first), (other, second)):
        imported = browser.post(
            base + "/imports", json={"filename": "team.json", "content": '[{"title":"Team-local observable link","source_ip":"2001:db8::40"}]'}
        )
        assert imported.status_code == 201
        observable = browser.get(base + "/observables").json["items"]
        assert len(observable) == 1 and observable[0]["occurrences"] == 1


def test_simultaneous_authenticated_writers_reject_stale_update_without_losing_winner(autopsy_case, app, client):
    base = f"/api/cases/{autopsy_case}"
    first, second = authenticated(app, "analyst@socify.local"), authenticated(app, "manager@socify.local")
    version = client.get(base).json["version"]
    custody_before = client.get(base + "/custody").json["total"]
    barrier = threading.Barrier(2)

    def save(browser, objective):
        barrier.wait(timeout=5)
        response = browser.patch(base + "/context", json={"version": version, "objective": objective})
        return objective, response.status_code, response.json

    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(save, first, "Independent analyst retains this scope")
        b = pool.submit(save, second, "Independent manager retains this scope")
        outcomes = [a.result(timeout=15), b.result(timeout=15)]
    assert sorted(item[1] for item in outcomes) == [200, 409]
    winner = next(item[0] for item in outcomes if item[1] == 200)
    loser = next(item[2] for item in outcomes if item[1] == 409)
    assert loser["error"]["code"] == "CASE_VERSION_CONFLICT"
    assert first.get(base).json["context"]["objective"] == winner
    assert second.get(base).json["context"]["objective"] == winner
    custody = first.get(base + "/custody").json
    assert custody["integrity_valid"] and custody["total"] == custody_before + 1


def test_monitoring_and_l1_responsibility_changes_retain_historical_assignment(autopsy_case, client, login_as, user_ids):
    base = f"/api/cases/{autopsy_case}"
    login_as("soc_manager")
    for responsibility in ("monitoring", "l1"):
        assert client.post(base + "/members", json={"user_id": user_ids["analyst"], "responsibility": responsibility}).status_code == 200
    current = next(member for member in client.get(base).json["members"] if member["user_id"] == user_ids["analyst"])
    assert current["responsibility"] == "l1"
    custody = client.get(base + "/custody").json
    assignments = []
    for entry in custody["items"]:
        details = entry["details"] if isinstance(entry["details"], dict) else json.loads(entry["details"])
        if entry["action"] == "member_assigned" and details["user_id"] == user_ids["analyst"]:
            assignments.append(details["responsibility"])
    assert set(assignments) == {"monitoring", "l1"}
    assert custody["integrity_valid"]


def test_real_l1_l2_and_investigator_handoff_keeps_separate_actors_evidence_and_response(autopsy_case, app, client, database, login_as, user_ids):
    people = {role: new_member(database, user_ids["analyst"], role, role + "-journey@example.test") for role in ("l1_analyst", "l2_responder", "investigator")}
    base = f"/api/cases/{autopsy_case}"
    login_as("soc_manager")
    assert client.post(base + "/members", json={"user_id": people["l1_analyst"], "responsibility": "l1"}).status_code == 200
    actors = {role: authenticated(app, role + "-journey@example.test") for role in people}
    assert actors["investigator"].get(base).status_code == 404
    imported = actors["l1_analyst"].post(base + "/imports", json={"filename": "handoff.json", "content": '[{"title":"Handoff response evidence"}]'})
    assert imported.status_code == 201
    evidence = client.get(base).json["evidence"][0]["id"]
    first_payload = {
        "to_user": people["l2_responder"],
        "from_level": "l1",
        "to_level": "l2",
        "reason": "Validate the retained evidence and document containment",
        "priority": "high",
        "status": "raised",
        "evidence_id": evidence,
    }
    first = actors["l1_analyst"].post(base + "/records/escalation", json=first_payload)
    assert first.status_code == 201
    first_path = base + f"/records/{first.json['id']}"
    assert actors["l1_analyst"].patch(first_path, json={"version": 1, "payload": {**first_payload, "status": "acknowledged"}}).status_code == 403
    acknowledged = actors["l2_responder"].patch(first_path, json={"version": 1, "payload": {**first_payload, "status": "acknowledged"}})
    assert acknowledged.status_code == 200 and acknowledged.json["payload"]["acknowledged_at"]
    response = actors["l2_responder"].post(
        base + "/records/response",
        json={
            "title": "Documented approved containment",
            "phase": "containment",
            "status": "succeeded",
            "performed_by": people["l2_responder"],
            "performed_at": iso_now(),
            "evidence_id": evidence,
            "details": "Synthetic authorized containment documented; no commands executed by the platform",
        },
    )
    assert response.status_code == 201
    resolved = actors["l2_responder"].patch(
        first_path,
        json={"version": 2, "payload": {**first_payload, "status": "resolved", "response": "Documented containment; request independent investigation"}},
    )
    assert resolved.status_code == 200
    second_payload = {
        "to_user": people["investigator"],
        "from_level": "l2",
        "to_level": "investigation",
        "reason": "Investigate root cause independently after documented containment",
        "priority": "high",
        "status": "raised",
        "evidence_id": evidence,
    }
    second = actors["l2_responder"].post(base + "/records/escalation", json=second_payload)
    assert second.status_code == 201 and second.json["id"] != first.json["id"]
    second_path = base + f"/records/{second.json['id']}"
    accepted = actors["investigator"].patch(second_path, json={"version": 1, "payload": {**second_payload, "status": "acknowledged"}})
    assert accepted.status_code == 200
    report = actors["investigator"].post(base + "/reports", json={"version": actors["investigator"].get(base).json["version"]})
    snapshot = actors["investigator"].get(base + f"/reports/{report.json['id']}").json["payload"]
    escalations = snapshot["records"]["escalation"]
    assert {row["payload"]["from_user"] for row in escalations} == {people["l1_analyst"], people["l2_responder"]}
    assert {row["payload"]["evidence_id"] for row in escalations} == {evidence}
    assert snapshot["records"]["response"][0]["payload"]["performed_by"] == people["l2_responder"]
    assert client.get(base + "/custody").json["integrity_valid"]


def test_supported_then_refuted_hypothesis_retains_opposing_exhibits_and_revision(autopsy_case, client, database):
    base = f"/api/cases/{autopsy_case}"
    assert (
        client.post(
            base + "/imports",
            json={"filename": "hypothesis.json", "content": '[{"title":"Initial supporting observation"},{"title":"Later contradictory observation"}]'},
        ).status_code
        == 201
    )
    events = client.get(base + "/logs").json["items"]
    exhibits = [client.post(base + f"/logs/{event['id']}/exhibit", json={}).json["id"] for event in events]
    payload = {
        "title": "Credential misuse hypothesis",
        "statement": "Initial evidence suggests credential misuse within the recorded scope",
        "assessment": "supported",
        "confidence": 60,
        "evidence_id": exhibits[0],
    }
    created = client.post(base + "/records/hypothesis", json=payload)
    assert created.status_code == 201
    revised = client.patch(
        base + f"/records/{created.json['id']}",
        json={
            "version": 1,
            "payload": {
                **payload,
                "assessment": "refuted",
                "evidence_id": exhibits[1],
                "statement": "Contradictory retained evidence refutes this hypothesis",
                "confidence": 80,
            },
        },
    )
    assert revised.status_code == 200
    revisions = database.execute("SELECT version,payload FROM autopsy_record_revisions WHERE record_id=? ORDER BY version", (created.json["id"],)).fetchall()
    assert [json.loads(row["payload"])["evidence_id"] for row in revisions] == exhibits
    assert [json.loads(row["payload"])["assessment"] for row in revisions] == ["supported", "refuted"]
    assert client.get(base + "/custody").json["integrity_valid"]
