import time

import pytest

from socify.security import totp_code
from tests.conftest import DEMO_LOGIN_VALUE


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


def test_scope_migration_is_repeatable_and_preserves_events(client, login_as, database):
    from socify.schema import ensure_schema

    login_as("admin")
    event = client.post("/api/events", json={"source": "migration-fixture", "source_ip": "192.0.2.234", "idempotency_key": "legacy-key"}).json["id"]
    # An indicator written before observations had their own table: the event it was seen in lives only in its context.
    indicator = database.execute(
        "INSERT INTO ioc_indicators (workspace_id, type, value, first_seen, last_seen, confidence, source, context, tags) VALUES (1, 'ip', '192.0.2.234', ?, ?, 0.5, 'SOCify extraction', ?, '[]')",
        ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", f'{{"event_id":{event}}}'),
    ).lastrowid
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
