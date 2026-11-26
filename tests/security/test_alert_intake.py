"""Alert intake: authentication (token or HMAC), replay and skew, limits, de-duplication, encryption, isolation and triage."""

import hashlib
import hmac
import json
import time
from pathlib import Path

import pytest

from scripts.bootstrap_team import create_manager
from tests.conftest import DEMO_LOGIN_VALUE, issue_session

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "intake"


def _fixture(kind):
    return (FIXTURES / f"{kind}.json").read_bytes()


@pytest.fixture
def integration(client, login_as):
    def make(kind="generic", auth_mode="hmac", auto_case=None):
        login_as("soc_manager")
        body = {"kind": kind, "name": f"{kind} intake", "auth_mode": auth_mode}
        if auto_case is not None:
            body["auto_case"] = auto_case
        created = client.post("/api/intake/integrations", json=body)
        assert created.status_code == 201, created.json
        with client.session_transaction() as state:
            state.clear()
        return created.json

    return make


def _signed(secret, body, stamp=None):
    stamp = str(int(time.time()) if stamp is None else stamp)
    signature = hmac.new(secret.encode(), stamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return {"X-SOCify-Timestamp": stamp, "X-SOCify-Signature": f"sha256={signature}", "Content-Type": "application/json"}


def _post(client, created, body, headers):
    return client.post(created["item"]["endpoint"], data=body, headers=headers)


def test_a_signed_batch_is_accepted_normalised_and_encrypted(client, database, integration):
    created = integration()
    body = _fixture("generic")
    accepted = _post(client, created, body, _signed(created["hmac_secret"], body))
    assert accepted.status_code == 202 and accepted.json["accepted"] == 1 and accepted.json["items"][0]["status"] == "created"
    row = database.execute("SELECT * FROM intake_alerts").fetchone()
    assert row["severity"] == "critical" and row["status"] == "new" and row["external_id"] == "edr-000123"
    assert "Ransomware" not in row["raw_ciphertext"] and len(row["raw_sha256"]) == 64
    secret_row = database.execute("SELECT hmac_secret_ciphertext FROM intake_integrations").fetchone()[0]
    assert created["hmac_secret"] not in secret_row


@pytest.mark.parametrize("change", ["wrong-secret", "old", "future", "missing", "tampered"])
def test_bad_signatures_are_refused(client, integration, change):
    created = integration()
    body = _fixture("generic")
    secret = "x" * 43 if change == "wrong-secret" else created["hmac_secret"]
    # Well outside the five-minute window, so a slow machine cannot bring the stamp back inside it.
    stamp = {"old": int(time.time()) - 400, "future": int(time.time()) + 400}.get(change)
    headers = _signed(secret, body, stamp)
    if change == "missing":
        headers.pop("X-SOCify-Signature")
    sent = body + b" " if change == "tampered" else body
    refused = _post(client, created, sent, headers)
    assert refused.status_code == 401


def test_a_replayed_signature_is_refused(client, integration):
    created = integration()
    body = _fixture("generic")
    headers = _signed(created["hmac_secret"], body)
    assert _post(client, created, body, headers).status_code == 202
    replayed = _post(client, created, body, headers)
    assert replayed.status_code == 409 and replayed.json["error"]["code"] == "INTAKE_REPLAYED"


def test_size_batch_and_shape_limits(client, integration):
    created = integration()
    big = json.dumps({"alerts": [{"id": "x", "description": "a" * 1024}] * 1100}).encode()
    assert _post(client, created, big, _signed(created["hmac_secret"], big)).status_code == 413
    many = json.dumps({"alerts": [{"id": str(n)} for n in range(101)]}).encode()
    assert _post(client, created, many, _signed(created["hmac_secret"], many)).status_code == 422
    for broken in (b"{not json", b'{"alerts": ["text"]}', b'{"alerts": []}'):
        assert _post(client, created, broken, _signed(created["hmac_secret"], broken)).status_code in {400, 422}


def test_the_same_alert_is_grouped_inside_the_window(app, client, database, integration):
    created = integration()
    body = _fixture("generic")
    for _ in range(3):
        sent = body + b"\n" * _  # a new body each time, so the signature is never a replay
        _post(client, created, sent, _signed(created["hmac_secret"], sent))
    row = database.execute("SELECT COUNT(*) AS rows, MAX(occurrence_count) AS seen FROM intake_alerts").fetchone()
    assert row["rows"] == 1 and row["seen"] == 3
    app.config.update(INTAKE_GROUP_SECONDS=0)
    sent = body + b"\n\n\n"
    _post(client, created, sent, _signed(created["hmac_secret"], sent))
    assert database.execute("SELECT COUNT(*) FROM intake_alerts").fetchone()[0] == 2


def test_tokens_need_the_intake_scope_and_the_right_team(app, client, database, integration, login_as):
    created = integration(auth_mode="token")
    login_as("soc_manager")
    writer = client.post("/api/tokens", json={"name": "Wazuh", "scopes": ["intake:write"]}).json["token"]
    reader = client.post("/api/tokens", json={"name": "Reader", "scopes": ["cases:read"]}).json["token"]
    with client.session_transaction() as state:
        state.clear()
    body = _fixture("generic")
    assert client.post(created["item"]["endpoint"], data=body, headers={"Authorization": f"Bearer {reader}"}).status_code == 403
    accepted = client.post(created["item"]["endpoint"], data=body, headers={"Authorization": f"Bearer {writer}"})
    assert accepted.status_code == 202
    hmac_integration = integration(auth_mode="hmac")
    assert client.post(hmac_integration["item"]["endpoint"], data=body, headers={"Authorization": f"Bearer {writer}"}).status_code == 404
    other = create_manager(app, "owner@other-intake.example.test", "Other", "Other Intake Team", DEMO_LOGIN_VALUE)
    workspace = database.execute("SELECT workspace_id FROM users WHERE id = ?", (other,)).fetchone()[0]
    with client.session_transaction() as state:
        state.update(user_id=other, workspace_id=workspace, user_role="soc_manager", session_id=issue_session(app, other, workspace))
    foreign = client.post("/api/tokens", json={"name": "Foreign", "scopes": ["intake:write"]}).json["token"]
    with client.session_transaction() as state:
        state.clear()
    assert client.post(created["item"]["endpoint"], data=body, headers={"Authorization": f"Bearer {foreign}"}).status_code == 404


def test_wrong_signatures_are_rate_limited(app, client, integration):
    app.config.update(RATE_LIMIT_SOURCE_KEY_ATTEMPTS=3)
    created = integration()
    body = _fixture("generic")
    for _ in range(3):
        assert _post(client, created, body, _signed("y" * 43, body)).status_code == 401
    assert _post(client, created, body, _signed(created["hmac_secret"], body)).status_code == 429


def test_only_managers_manage_integrations_and_analysts_cannot_read_secrets(client, integration, login_as):
    created = integration()
    login_as("analyst")
    assert client.post("/api/intake/integrations", json={"kind": "generic", "name": "Mine", "auth_mode": "hmac"}).status_code == 403
    listed = client.get("/api/intake/integrations").json
    assert listed["items"][0]["id"] == created["item"]["id"] and "hmac_secret" not in json.dumps(listed) and not listed["can_manage"]


def _receive(client, created, kind):
    body = _fixture(kind)
    response = _post(client, created, body, _signed(created["hmac_secret"], body))
    assert response.status_code == 202, response.json
    return response.json["items"][0]["id"]


def test_creating_a_case_attaches_evidence_entities_and_the_detection_time(client, database, integration, login_as):
    created = integration(kind="elastic")
    alert_id = _receive(client, created, "elastic")
    login_as("auditor")
    assert "raw" not in client.get(f"/api/intake/alerts/{alert_id}").json
    assert client.post(f"/api/intake/alerts/{alert_id}/case", json={}).status_code == 403
    login_as("analyst")
    detail = client.get(f"/api/intake/alerts/{alert_id}").json
    assert detail["raw"]["alerts"] if "alerts" in detail["raw"] else detail["raw"]["kibana.alert.uuid"]
    made = client.post(f"/api/intake/alerts/{alert_id}/case", json={})
    assert made.status_code == 201, made.json
    case_id = made.json["case_id"]
    evidence = database.execute("SELECT * FROM case_evidence WHERE case_id = ?", (case_id,)).fetchone()
    alert = database.execute("SELECT * FROM intake_alerts WHERE id = ?", (alert_id,)).fetchone()
    assert evidence["sha256"] == alert["raw_sha256"] and evidence["evidence_type"] == "raw_log" and alert["status"] == "linked" and alert["case_id"] == case_id
    kinds = [row[0] for row in database.execute("SELECT kind FROM autopsy_records WHERE case_id = ?", (case_id,))]
    assert kinds.count("response") == 1 and kinds.count("asset") == 1 and kinds.count("indicator") >= 3
    detection = json.loads(database.execute("SELECT payload FROM autopsy_records WHERE case_id = ? AND kind = 'response'", (case_id,)).fetchone()[0])
    assert detection["phase"] == "detection" and detection["performed_at"] == alert["first_seen"] == "2026-11-20T08:59:41Z"
    assert database.execute("SELECT COUNT(*) FROM autopsy_custody WHERE case_id = ? AND action = 'intake_alert_attached'", (case_id,)).fetchone()[0] == 1
    assert client.post(f"/api/intake/alerts/{alert_id}/dismiss", json={"reason": "Too late now"}).status_code == 409


def test_link_and_dismiss(client, database, integration, login_as, autopsy_case):
    created = integration(kind="wazuh")
    first = _receive(client, created, "wazuh")
    login_as("analyst")
    assert client.post(f"/api/intake/alerts/{first}/link", json={"case_id": 999999}).status_code == 404
    linked = client.post(f"/api/intake/alerts/{first}/link", json={"case_id": autopsy_case})
    assert linked.status_code == 200 and database.execute("SELECT COUNT(*) FROM case_evidence WHERE case_id = ?", (autopsy_case,)).fetchone()[0] >= 1
    created_two = integration(kind="splunk")
    second = _receive(client, created_two, "splunk")
    login_as("analyst")
    assert client.post(f"/api/intake/alerts/{second}/dismiss", json={"reason": "no"}).status_code == 422
    assert client.post(f"/api/intake/alerts/{second}/dismiss", json={"reason": "Authorised penetration test"}).json["status"] == "dismissed"
    queue = client.get("/api/intake/alerts").json
    assert queue["total"] == 0
    assert {item["status"] for item in client.get("/api/intake/alerts?status=all").json["items"]} == {"linked", "dismissed"}
    assert client.get("/api/intake/alerts?severity=urgent").status_code == 422


def test_auto_case_rules_open_a_case_for_severe_alerts(client, database, integration, user_ids):
    created = integration(kind="generic", auto_case={"min_severity": "high", "assignee": user_ids["analyst"]})
    alert_id = _receive(client, created, "generic")
    alert = database.execute("SELECT status, case_id FROM intake_alerts WHERE id = ?", (alert_id,)).fetchone()
    assert alert["status"] == "linked" and alert["case_id"]
    case = database.execute("SELECT assignee, severity FROM incident_cases WHERE id = ?", (alert["case_id"],)).fetchone()
    assert case["assignee"] == user_ids["analyst"] and case["severity"] == "critical"
    low = integration(kind="sentinel", auto_case={"min_severity": "high"})
    medium_id = _receive(client, low, "sentinel")
    assert database.execute("SELECT status FROM intake_alerts WHERE id = ?", (medium_id,)).fetchone()[0] == "new"


def test_another_team_sees_none_of_the_queue(app, client, database, integration):
    created = integration()
    alert_id = _receive(client, created, "generic")
    other = create_manager(app, "owner@third-team.example.test", "Third", "Third Team", DEMO_LOGIN_VALUE)
    workspace = database.execute("SELECT workspace_id FROM users WHERE id = ?", (other,)).fetchone()[0]
    with client.session_transaction() as state:
        state.update(user_id=other, workspace_id=workspace, user_role="soc_manager", session_id=issue_session(app, other, workspace))
    assert client.get("/api/intake/alerts?status=all").json["total"] == 0
    assert client.get(f"/api/intake/alerts/{alert_id}").status_code == 404
    assert client.post(f"/api/intake/alerts/{alert_id}/dismiss", json={"reason": "Not ours to dismiss"}).status_code == 404
    assert client.get("/api/intake/integrations").json["items"] == []


def test_managers_update_integrations_and_bad_settings_are_refused(client, integration, login_as, user_ids):
    created = integration()
    path = f"/api/intake/integrations/{created['item']['id']}"
    login_as("analyst")
    assert client.patch(path, json={"enabled": False}).status_code == 403
    login_as("soc_manager")
    updated = client.patch(path, json={"enabled": False, "auto_case": {"min_severity": "critical", "assignee": user_ids["analyst"]}})
    assert (
        updated.status_code == 200
        and updated.json["enabled"] is False
        and updated.json["auto_case"] == {"min_severity": "critical", "assignee": user_ids["analyst"]}
    )
    for body in (
        {},
        {"enabled": "no"},
        {"name": "renamed"},
        {"auto_case": {"min_severity": "urgent"}},
        {"auto_case": {"assignee": 999999}},
        {"auto_case": {"extra": 1}},
    ):
        assert client.patch(path, json=body).status_code == 422, body
    assert client.patch("/api/intake/integrations/999999", json={"enabled": True}).status_code == 404
    for body in (
        {"kind": "qradar", "name": "Other", "auth_mode": "hmac"},
        {"kind": "generic", "name": "ab", "auth_mode": "hmac"},
        {"kind": "generic", "name": "Valid", "auth_mode": "basic"},
        {"kind": "generic", "name": "Valid", "auth_mode": "hmac", "secret": "x"},
    ):
        assert client.post("/api/intake/integrations", json=body).status_code == 422, body
    with client.session_transaction() as state:
        state.clear()
    body = _fixture("generic")
    assert _post(client, created, body, _signed(created["hmac_secret"], body)).status_code == 401


def test_queue_filters(client, integration, login_as):
    wazuh = integration(kind="wazuh")
    _receive(client, wazuh, "wazuh")
    generic = integration(kind="generic")
    _receive(client, generic, "generic")
    login_as("analyst")
    assert client.get(f"/api/intake/alerts?integration_id={wazuh['item']['id']}").json["total"] == 1
    assert client.get("/api/intake/alerts?severity=critical").json["total"] == 1
    assert client.get("/api/intake/alerts?status=new&since=2000-01-01T00:00:00Z&page=1").json["total"] == 2
    assert client.get("/api/intake/alerts?since=2999-01-01T00:00:00Z").json["total"] == 0
    for query in ("integration_id=x", "since=yesterday", "status=closed"):
        assert client.get(f"/api/intake/alerts?{query}").status_code == 422, query
    assert client.get("/api/intake/alerts/999999").status_code == 404


def test_a_repeat_after_dismissal_is_a_new_alert(client, database, integration, login_as):
    created = integration()
    first = _receive(client, created, "generic")
    login_as("analyst")
    assert client.post(f"/api/intake/alerts/{first}/dismiss", json={"reason": "Scanner noise this morning"}).status_code == 200
    with client.session_transaction() as state:
        state.clear()
    body = _fixture("generic") + b"\n"
    repeat = _post(client, created, body, _signed(created["hmac_secret"], body))
    assert repeat.json["items"][0]["status"] == "created" and repeat.json["items"][0]["id"] != first
    assert database.execute("SELECT occurrence_count FROM intake_alerts WHERE id = ?", (first,)).fetchone()[0] == 1


def test_an_auto_case_failure_keeps_the_delivery_accepted_and_is_audited(client, database, integration, monkeypatch):
    import socify.intake as intake
    from socify.validation import ValidationError

    created = integration(kind="generic", auto_case={"min_severity": "high"})

    def refuse(*_args, **_kwargs):
        raise ValidationError("refused by the case model")

    monkeypatch.setattr(intake, "create_case_from_alert", refuse)
    body = _fixture("generic")
    accepted = _post(client, created, body, _signed(created["hmac_secret"], body))
    assert accepted.status_code == 202
    assert database.execute("SELECT status FROM intake_alerts").fetchone()[0] == "new"
    assert database.execute("SELECT COUNT(*) FROM security_audit_logs WHERE action = 'auto_case_failed'").fetchone()[0] == 1


def test_auto_created_cases_name_the_member_the_integration_acts_for(client, database, integration, user_ids):
    created = integration(kind="generic", auto_case={"min_severity": "high"})
    _receive(client, created, "generic")
    row = database.execute("SELECT actor_id FROM security_audit_logs WHERE action = 'case_from_intake'").fetchone()
    assert row["actor_id"] == user_ids["soc_manager"]
