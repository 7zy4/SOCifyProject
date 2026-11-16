import time

import pytest

from socify.security import totp_code
from tests.conftest import DEMO_LOGIN_VALUE


@pytest.mark.parametrize("action", ["retry", "cancel"])
def test_response_mutations_require_object_access(client, login_as, database, action):
    login_as("admin")
    playbook = client.post("/api/playbooks", json={"name": "Private response", "publish": True, "steps": [{"action": "isolate_virtual_host"}]}).json["id"]
    login_as("instructor")
    run = client.post("/api/playbook-runs", json={"playbook_id": playbook, "idempotency_key": "private-response-key"}).json
    assert run["state"] == "failed"
    login_as("analyst")
    assert client.post(f"/api/playbook-runs/{run['id']}/{action}", json={}).status_code == 404
    assert client.post("/api/playbook-runs", json={"playbook_id": playbook, "idempotency_key": "private-response-key"}).status_code == 404
    assert database.execute("SELECT state FROM playbook_runs WHERE id = ?", (run["id"],)).fetchone()[0] == "failed"


def test_active_mfa_cannot_be_disabled_by_reenrollment(client, login_as):
    login_as("analyst")
    enrollment = client.post("/api/auth/mfa/enroll", json={}).json
    code = totp_code(enrollment["secret"], int(time.time()))
    assert client.post("/api/auth/mfa/verify", json={"code": code}).status_code == 200
    assert client.post("/api/auth/mfa/enroll", json={}).status_code == 409
    client.post("/api/auth/logout", json={})
    assert client.post("/api/auth/login", json={"email": "analyst@socify.local", "password": DEMO_LOGIN_VALUE}).status_code == 428


def test_closed_case_cannot_receive_new_event_or_alert_evidence(client, login_as, database):
    login_as("admin")
    case = client.post("/api/incidents", json={"title": "Locked evidence"}).json["id"]
    event = client.post("/api/events", json={"source": "lock-fixture"}).json["id"]
    database.execute("UPDATE incident_cases SET status = 'closed' WHERE id = ?", (case,))
    for suffix, payload in [("events", {"event_id": event}), ("alerts", {"alert_id": 99999})]:
        response = client.post(f"/api/incidents/{case}/{suffix}", json=payload)
        assert response.status_code == 409
        assert response.json["error"]["code"] == "CASE_EVIDENCE_LOCKED"
    assert database.execute("SELECT COUNT(*) FROM case_evidence WHERE case_id = ?", (case,)).fetchone()[0] == 0


def test_private_response_stream_is_not_visible_to_other_trainee(client, login_as):
    login_as("admin")
    playbook = client.post(
        "/api/playbooks",
        json={
            "name": "Private notification",
            "publish": True,
            "steps": [{"action": "notify_training_team", "parameters": {"message": "private-response-marker"}}],
        },
    ).json["id"]
    login_as("instructor")
    assert client.post("/api/playbook-runs", json={"playbook_id": playbook, "idempotency_key": "private-stream-key"}).status_code == 201
    login_as("analyst")
    stream = client.get("/api/stream/events?once=1").get_data(as_text=True)
    assert "private-response-marker" not in stream
    assert "playbook_run.updated" not in stream


def test_case_creation_with_missing_evidence_is_atomic_client_error(client, login_as, database):
    login_as("analyst")
    response = client.post("/api/incidents", json={"title": "Missing evidence", "event_ids": [99999]})
    assert response.status_code == 404
    assert database.execute("SELECT COUNT(*) FROM incident_cases").fetchone()[0] == 0


@pytest.mark.parametrize("password", ["aB9!" * 25, "أبجد12!" * 10])
def test_oversized_bcrypt_input_never_crashes_authentication(client, password):
    assert client.post("/api/auth/register", json={"email": "long@example.test", "name": "Long password", "password": password}).status_code == 422
    assert client.post("/api/auth/login", json={"email": "analyst@socify.local", "password": password}).status_code == 401


@pytest.mark.parametrize("field,value", [("field", []), ("operator", {}), ("logic", [])])
def test_rule_enums_reject_non_scalar_json(client, login_as, field, value):
    login_as("admin")
    condition = (
        {"field": "source", "operator": "equals", "value": "lab"}
        if field != "logic"
        else {"logic": "and", "conditions": [{"field": "source", "operator": "exists"}]}
    )
    condition[field] = value
    assert client.post("/api/rules", json={"name": "Invalid scalar", "dsl": {"condition": condition}}).status_code == 422


@pytest.mark.parametrize("field,value", [("timeout_seconds", "bad"), ("retry_limit", []), ("action", []), ("approval_role", []), ("position", True)])
def test_playbook_steps_validate_types_before_writing(client, login_as, field, value):
    login_as("admin")
    step = {"action": "notify_training_team", field: value}
    assert client.post("/api/playbooks", json={"name": "Invalid step", "steps": [step]}).status_code == 422


@pytest.mark.parametrize("action", ["collect_evidence", "escalate_to_manager"])
def test_response_cannot_mutate_closed_case(client, login_as, database, action):
    login_as("admin")
    case = client.post("/api/incidents", json={"title": "Closed response target"}).json["id"]
    database.execute("UPDATE incident_cases SET status = 'closed' WHERE id = ?", (case,))
    playbook = client.post("/api/playbooks", json={"name": "Closed case response", "publish": True, "steps": [{"action": action}]}).json["id"]
    result = client.post("/api/playbook-runs", json={"playbook_id": playbook, "case_id": case, "idempotency_key": f"closed-{action}"})
    assert result.json["state"] == "failed"
    assert database.execute("SELECT status FROM incident_cases WHERE id = ?", (case,)).fetchone()[0] == "closed"
    assert database.execute("SELECT COUNT(*) FROM case_evidence WHERE case_id = ?", (case,)).fetchone()[0] == 0


def test_stream_stops_after_account_revocation(app, client, login_as, database, user_ids, monkeypatch):
    login_as("analyst")
    monkeypatch.setattr("socify.visualization.time.sleep", lambda _: database.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_ids["analyst"],)))
    monkeypatch.setattr("socify.visualization.time.monotonic", iter([0, 16, 16]).__next__)
    result = client.get("/api/stream/events", buffered=False)
    assert next(result.response).startswith(b"event: heartbeat")
    assert list(result.response) == []


def test_scope_migration_is_repeatable_and_preserves_events(client, login_as, database):
    from socify.schema import ensure_schema

    login_as("admin")
    event = client.post("/api/events", json={"source": "migration-fixture", "source_ip": "192.0.2.234", "idempotency_key": "legacy-key"}).json["id"]
    indicator = client.post("/api/iocs/extract", json={"event_id": event}).json["items"][0]["id"]
    database.execute("DELETE FROM ioc_observations WHERE ioc_id = ?", (indicator,))
    database.execute("UPDATE ioc_indicators SET context = ? WHERE id = ?", (f'{{"event_id":{event}}}', indicator))
    database.execute("DROP INDEX idx_events_scope_idempotency")
    database.execute("CREATE UNIQUE INDEX idx_events_idempotency ON security_events(workspace_id, idempotency_key) WHERE idempotency_key IS NOT NULL")
    ensure_schema(database)
    ensure_schema(database)
    assert database.execute("SELECT COUNT(*) FROM security_events WHERE id = ?", (event,)).fetchone()[0] == 1
    assert database.execute("SELECT COUNT(*) FROM ioc_observations WHERE ioc_id = ?", (indicator,)).fetchone()[0] == 1
    assert database.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert not database.execute("PRAGMA foreign_key_check").fetchall()


def test_schema_failure_rolls_back_ddl_and_data(monkeypatch):
    import sqlite3

    from socify.schema import ensure_schema

    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.row_factory = sqlite3.Row

    def fail(_):
        raise RuntimeError("injected migration failure")

    monkeypatch.setattr("socify.schema.seed_reference_data", fail)
    with pytest.raises(RuntimeError, match="injected migration failure"):
        ensure_schema(connection)
    assert not connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    connection.close()


def test_openapi_operation_ids_and_error_contract():
    from scripts.generate_openapi import generate

    contract = generate()
    identifiers = [operation["operationId"] for path in contract["paths"].values() for operation in path.values()]
    assert len(identifiers) == len(set(identifiers))
    error = contract["components"]["schemas"]["Error"]
    assert set(error["required"]) == {"error", "correlation_id"}
    assert error["properties"]["error"]["type"] == "object"
    assert set(error["properties"]["error"]["required"]) == {"code", "message"}


@pytest.mark.parametrize("payload", [{"title": "Stale edit"}, {"status": "investigating", "reason": "Stale transition"}])
def test_case_compare_and_swap_preserves_interleaved_write(client, login_as, database, monkeypatch, payload):
    from contextlib import contextmanager

    from socify.db import transaction

    login_as("admin")
    case = client.post("/api/incidents", json={"title": "Concurrent case"}).json["id"]

    @contextmanager
    def interleave():
        database.execute("UPDATE incident_cases SET title = 'Concurrent winner', version = version + 1 WHERE id = ?", (case,))
        with transaction() as connection:
            yield connection

    monkeypatch.setattr("socify.cases.transaction", interleave)
    assert client.patch(f"/api/incidents/{case}", json={"version": 1, **payload}).status_code == 409
    row = database.execute("SELECT title, version, status FROM incident_cases WHERE id = ?", (case,)).fetchone()
    assert tuple(row) == ("Concurrent winner", 2, "new")


def test_mfa_enrollment_cannot_race_activation(client, login_as, database, user_ids, monkeypatch):
    from socify.security import generate_totp_secret

    login_as("analyst")
    assert client.post("/api/auth/mfa/enroll", json={}).status_code == 200
    original = database.execute("SELECT secret_ciphertext FROM mfa_enrollments WHERE user_id = ?", (user_ids["analyst"],)).fetchone()[0]

    def activate():
        database.execute("UPDATE mfa_enrollments SET enabled = 1 WHERE user_id = ?", (user_ids["analyst"],))
        return generate_totp_secret()

    monkeypatch.setattr("socify.auth.generate_totp_secret", activate)
    assert client.post("/api/auth/mfa/enroll", json={}).status_code == 409
    assert tuple(database.execute("SELECT enabled, secret_ciphertext FROM mfa_enrollments WHERE user_id = ?", (user_ids["analyst"],)).fetchone()) == (
        1,
        original,
    )
