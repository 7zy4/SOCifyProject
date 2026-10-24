import sqlite3

import pytest


@pytest.fixture
def autopsy_case(app, client, login_as):
    app.config["LEGACY_TRAINING_TESTS"] = False
    app.config["ALLOW_REGISTRATION"] = False
    login_as("analyst")
    response = client.post(
        "/api/cases", json={"title": "Internal incident review", "reason": "alert_review", "objective": "Establish impact from retained evidence"}
    )
    assert response.status_code == 201, response.json
    return response.json["id"]


def test_case_first_context_membership_and_retired_routes(autopsy_case, app, client, database, login_as):
    case = client.get(f"/api/cases/{autopsy_case}").json
    assert case["context"]["objective"] == "Establish impact from retained evidence"
    assert case["members"][0]["user_id"] == case["creator"]
    assert client.get("/api/cases").json["total"] >= 1
    for path in ["/api/training/runs", "/api/scenarios", "/api/scores", "/api/events", "/api/dashboard"]:
        assert client.get(path).status_code == 410
    assert client.get("/lab").status_code == 410
    assert client.get("/scores").status_code == 410
    assert client.get("/dashboard").headers["Location"] == "/cases"
    assert client.get("/health/ready").status_code == 200
    assert "SOCify Digital Autopsy" in client.get("/cases").text
    assert 'href="/lab"' not in client.get("/cases").text
    assert (
        client.post("/api/auth/register", json={"name": "Public User", "email": "public@example.test", "password": "Training-Safe-Password-2026!"}).status_code
        == 403
    )
    assert not any(permission.startswith(("training.", "scores.")) for permission in client.get("/api/auth/me").json["permissions"])
    assert client.post("/api/auth/register", json={"invitation_token": "", "email": "empty@example.test"}).status_code == 403
    assert database.execute("SELECT COUNT(*) FROM training_runs").fetchone()[0] >= 0
    login_as("auditor")
    assert client.get(f"/api/cases/{autopsy_case}").status_code == 404
    assert client.get(f"/cases/{autopsy_case}").status_code == 404
    assert not any(row["id"] == autopsy_case for row in client.get("/api/incidents").json["items"])
    login_as("soc_manager")
    assert client.get(f"/api/cases/{autopsy_case}").status_code == 200


@pytest.mark.parametrize("change", [{"objective": ""}, {"reason": []}, {"classification": []}, {"title": "\ud800"}, {"training_run_id": 1}, {"is_admin": True}])
def test_case_creation_rejects_invalid_or_unknown_fields(autopsy_case, client, change):
    body = {"title": "Valid case title", "reason": "alert_review", "objective": "Verify incident impact", **change}
    assert client.post("/api/cases", json=body).status_code == 422


def test_case_context_optimistic_version_and_legal_hold(autopsy_case, client, database, login_as):
    path = f"/api/cases/{autopsy_case}"
    version = client.get(path).json["version"]
    assert client.patch(path + "/context", json={"version": version, "attack_outcome": "blocked"}).status_code == 200
    assert client.patch(path + "/context", json={"version": version, "attack_outcome": "successful"}).status_code == 409
    current = client.get(path).json
    assert current["context"]["attack_outcome"] == "blocked"
    assert client.patch(path + "/context", json={"version": current["version"], "legal_hold": True}).status_code == 422
    login_as("soc_manager")
    assert client.patch(path + "/context", json={"version": current["version"], "legal_hold": True}).status_code == 200
    assert database.execute("SELECT legal_hold FROM autopsy_case_context WHERE case_id = ?", (autopsy_case,)).fetchone()[0] == 1
    assert client.patch(path + "/context", json={"unknown": "ignored"}).status_code == 422


@pytest.mark.parametrize(
    "kind,payload",
    [
        ("asset", {"name": "Defender workstation", "type": "workstation", "role": "defender", "assessment": "unexamined"}),
        ("indicator", {"type": "ip", "value": "2001:db8::1", "classification": "observable", "source": "Retained log", "confidence": 25}),
        (
            "timeline",
            {
                "title": "Observed login",
                "event_time": "2026-10-24T12:00:00+03:00",
                "category": "observed",
                "source": "Retained evidence",
                "tags": ["authentication"],
            },
        ),
        ("war_room", {"title": "Analyst decision", "body": "Retain uncertainty until more evidence arrives", "visibility": "private"}),
        ("hypothesis", {"title": "Credential misuse", "statement": "Account may be compromised", "assessment": "open", "confidence": 50}),
        ("response", {"title": "Containment planned", "phase": "containment", "status": "planned", "details": "Documented action, no remote command"}),
        (
            "root_cause",
            {
                "category": "unknown",
                "conclusion": "Evidence is currently incomplete",
                "whys": [{"question": "Why did detection occur?", "answer": "A retained event exceeded the local threshold"}],
            },
        ),
    ],
)
def test_structured_records_are_versioned_and_traceable(autopsy_case, client, database, kind, payload):
    path = f"/api/cases/{autopsy_case}/records"
    created = client.post(path + f"/{kind}", json=payload)
    assert created.status_code == 201, created.json
    item = created.json
    listed = client.get(path + f"?kind={kind}").json["items"]
    assert listed[0]["id"] == item["id"]
    assert client.patch(path + f"/{item['id']}", json={"version": 1, "payload": payload}).status_code == 200
    assert client.patch(path + f"/{item['id']}", json={"version": 1, "payload": payload}).status_code == 409
    assert database.execute("SELECT COUNT(*) FROM autopsy_record_revisions WHERE record_id = ?", (item["id"],)).fetchone()[0] == 2
    custody = client.get(f"/api/cases/{autopsy_case}/custody").json
    assert custody["integrity_valid"] is True
    assert custody["total"] == 2
    with pytest.raises(sqlite3.IntegrityError):
        database.execute("UPDATE autopsy_custody SET action = 'tampered' WHERE case_id = ?", (autopsy_case,))


@pytest.mark.parametrize(
    "kind,payload",
    [
        ("indicator", {"type": "ip", "value": "not-an-ip", "classification": "observable", "source": "test"}),
        ("indicator", {"type": "sha256", "value": "bad", "classification": "observable", "source": "test"}),
        ("indicator", {"type": "domain", "value": "bad..domain", "classification": "observable", "source": "test"}),
        ("indicator", {"type": "url", "value": "file:///etc/passwd", "classification": "observable", "source": "test"}),
        ("indicator", {"type": "email", "value": "invalid", "classification": "observable", "source": "test"}),
        ("indicator", {"type": "ip", "value": "192.0.2.1", "classification": "ioc", "source": "test"}),
        ("timeline", {"title": "No zone", "event_time": "2026-10-24T12:00:00", "category": "observed", "source": "test"}),
        ("response", {"title": "Unsupported success", "phase": "containment", "status": "succeeded", "details": "No evidence"}),
        ("asset", {"name": "x", "type": "workstation", "role": "defender", "is_admin": True}),
        ("root_cause", {"category": "unknown", "conclusion": "Unknown", "whys": [{"question": "Why?", "answer": "Unknown", "execute": "denied"}]}),
        ("hypothesis", {"title": "Invalid confidence", "statement": "test", "assessment": "open", "confidence": True}),
        ("unknown", {}),
    ],
)
def test_structured_input_validation(autopsy_case, client, kind, payload):
    response = client.post(f"/api/cases/{autopsy_case}/records/{kind}", json=payload)
    assert response.status_code == 422, response.json


def test_private_record_and_case_membership(autopsy_case, client, login_as, user_ids):
    created = client.post(
        f"/api/cases/{autopsy_case}/records/war_room", json={"title": "Private review", "body": "Do not leak private note", "visibility": "private"}
    )
    assert created.status_code == 201
    login_as("soc_manager")
    assert client.post(f"/api/cases/{autopsy_case}/members", json={"user_id": user_ids["auditor"], "responsibility": "reviewer"}).status_code == 200
    login_as("auditor")
    assert client.get(f"/api/cases/{autopsy_case}").status_code == 200
    assert client.get(f"/api/cases/{autopsy_case}/records?kind=war_room").json["items"] == []
    assert client.post(f"/api/cases/{autopsy_case}/records/asset", json={}).status_code == 403


def test_recipient_acknowledges_escalation_with_separate_response(autopsy_case, client, database, user_ids):
    recipient = database.execute(
        "INSERT INTO users(email, password_hash, name, role, workspace_id, is_active) SELECT 'responder@example.test', password_hash, 'Responder L2', 'l2_responder', 1, 1 FROM users WHERE id = ? RETURNING id",
        (user_ids["analyst"],),
    ).fetchone()[0]
    body = {"to_user": recipient, "from_level": "l1", "to_level": "l2", "reason": "Investigate network evidence", "priority": "high", "status": "raised"}
    created = client.post(f"/api/cases/{autopsy_case}/records/escalation", json=body)
    assert created.status_code == 201
    path = f"/api/cases/{autopsy_case}/records/{created.json['id']}"
    assert client.patch(path, json={"version": 1, "payload": {**body, "status": "acknowledged"}}).status_code == 403
    with client.session_transaction() as state:
        state["user_id"] = recipient
        state["workspace_id"] = 1
    acknowledged = client.patch(path, json={"version": 1, "payload": {**body, "status": "acknowledged"}})
    assert acknowledged.status_code == 200
    assert acknowledged.json["payload"]["acknowledged_at"]
    resolved = client.patch(path, json={"version": 2, "payload": {**body, "status": "resolved", "response": "Reviewed logs and handed to investigation"}})
    assert resolved.status_code == 200
    assert resolved.json["payload"]["from_user"] == user_ids["analyst"]
    assert resolved.json["payload"]["responded_at"]
