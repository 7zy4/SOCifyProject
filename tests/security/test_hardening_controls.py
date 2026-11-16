import logging
import sqlite3
import time
from datetime import timedelta

import pytest
from flask import Flask

from socify import create_app
from socify.config import build_config
from socify.maintenance import prune, prune_if_due
from socify.security import totp_code
from socify.timeutils import utc_now
from tests.conftest import DEMO_LOGIN_VALUE

CREDENTIALS = {"email": "analyst@socify.local", "password": DEMO_LOGIN_VALUE}
WRONG = {"email": "analyst@socify.local", "password": "Incorrect-Password-2026!"}  # pragma: allowlist secret


def _variant(app: Flask, **overrides: object) -> Flask:
    base = {
        key: app.config[key]
        for key in ("DATABASE", "TESTING", "LEGACY_TRAINING_TESTS", "WTF_CSRF_ENABLED", "SECRET_KEY", "CREDENTIAL_KEY", "ALLOW_REGISTRATION")
    }
    return create_app({**base, **overrides})


def _attempt_addresses(database: sqlite3.Connection) -> list[str]:
    return [row[0] for row in database.execute("SELECT ip_address FROM login_attempts ORDER BY id")]


def test_client_address_comes_from_the_trusted_proxy_hop_only(app, database):
    direct = app.test_client()
    direct.post("/api/auth/login", json=WRONG, headers={"X-Forwarded-For": "203.0.113.9"})
    assert _attempt_addresses(database) == ["127.0.0.1"]

    proxied = _variant(app, TRUSTED_PROXY_HOPS=1).test_client()
    proxied.post("/api/auth/login", json=WRONG, headers={"X-Forwarded-For": "203.0.113.9"})
    proxied.post("/api/auth/login", json=WRONG, headers={"X-Forwarded-For": "198.51.100.77, 203.0.113.10"})
    assert _attempt_addresses(database)[1:] == ["203.0.113.9", "203.0.113.10"]
    audited = database.execute("SELECT ip_address FROM security_audit_logs WHERE action = 'login' ORDER BY id DESC LIMIT 1").fetchone()[0]
    assert audited == "203.0.113.10"


def test_account_limit_is_scoped_to_the_real_client_address(app):
    proxied = _variant(app, TRUSTED_PROXY_HOPS=1, RATE_LIMIT_LOGIN_ATTEMPTS=2).test_client()
    attacker = {"X-Forwarded-For": "203.0.113.50"}
    for _ in range(2):
        assert proxied.post("/api/auth/login", json=WRONG, headers=attacker).status_code == 401
    assert proxied.post("/api/auth/login", json=CREDENTIALS, headers=attacker).status_code == 429
    assert proxied.post("/api/auth/login", json=CREDENTIALS, headers={"X-Forwarded-For": "198.51.100.5"}).status_code == 200


def test_one_address_cannot_rotate_accounts_past_the_address_limit(app):
    limited = _variant(app, RATE_LIMIT_LOGIN_IP_ATTEMPTS=3).test_client()
    for index in range(3):
        assert limited.post("/api/auth/login", json={"email": f"user{index}@example.test", "password": WRONG["password"]}).status_code == 401
    assert limited.post("/api/auth/login", json=CREDENTIALS).status_code == 429
    unlimited = _variant(app, RATE_LIMIT_LOGIN_IP_ATTEMPTS=0).test_client()
    assert unlimited.post("/api/auth/login", json=CREDENTIALS).status_code == 200


def test_production_requires_an_explicit_credential_key(monkeypatch):
    monkeypatch.setenv("SOCIFY_ENV", "production")
    monkeypatch.setenv("SOCIFY_SECRET_KEY", "s" * 48)
    monkeypatch.delenv("SOCIFY_CREDENTIAL_KEY", raising=False)
    with pytest.raises(RuntimeError, match="SOCIFY_CREDENTIAL_KEY"):
        build_config()
    monkeypatch.setenv("SOCIFY_CREDENTIAL_KEY", "c" * 48)
    assert build_config()["CREDENTIAL_KEY"] == "c" * 48
    monkeypatch.setenv("SOCIFY_ENV", "development")
    monkeypatch.delenv("SOCIFY_CREDENTIAL_KEY")
    assert build_config()["CREDENTIAL_KEY"] == "s" * 48


def test_totp_code_opens_only_one_session(app, client, login_as):
    login_as("analyst")
    secret = client.post("/api/auth/mfa/enroll", json={}).json["secret"]
    assert client.post("/api/auth/mfa/verify", json={"code": totp_code(secret)}).status_code == 200
    code = totp_code(secret)
    assert app.test_client().post("/api/auth/login", json={**CREDENTIALS, "mfa_code": code}).status_code == 200
    replay = app.test_client().post("/api/auth/login", json={**CREDENTIALS, "mfa_code": code})
    assert replay.status_code == 401 and replay.json["error"]["code"] == "INVALID_MFA_CODE"
    following = totp_code(secret, int(time.time()) + 30)
    assert app.test_client().post("/api/auth/login", json={**CREDENTIALS, "mfa_code": following}).status_code == 200


def test_rejected_invitations_are_limited_without_counting_validation_mistakes(app):
    limited = _variant(app, RATE_LIMIT_REGISTER_ATTEMPTS=2).test_client()
    account = {"name": "Invited analyst", "email": "invited@example.test", "password": "Training-Safe-Password-2026!"}
    for _ in range(4):
        assert limited.post("/api/auth/register", json={**account, "password": "short"}).status_code == 422  # pragma: allowlist secret
    for _ in range(2):
        rejected = limited.post("/api/auth/register", json={**account, "invitation_token": "x" * 40})
        assert rejected.status_code == 422 and rejected.json["error"]["code"] == "INVALID_INVITATION"
    blocked = limited.post("/api/auth/register", json=account)
    assert blocked.status_code == 429 and blocked.json["error"]["code"] == "REGISTRATION_RATE_LIMITED"


def test_invalid_source_keys_are_limited_per_source(app):
    limited = _variant(app, RATE_LIMIT_SOURCE_KEY_ATTEMPTS=2).test_client()
    for _ in range(2):
        assert limited.post("/api/sources/1/ingest", data=b"{}", headers={"X-SOCify-Source-Key": "wrong-key"}).status_code == 401
    blocked = limited.post("/api/sources/1/ingest", data=b"{}", headers={"X-SOCify-Source-Key": "wrong-key"})
    assert blocked.status_code == 429 and blocked.json["error"]["code"] == "SOURCE_KEY_RATE_LIMITED"
    assert limited.post("/api/sources/2/ingest", data=b"{}", headers={"X-SOCify-Source-Key": "wrong-key"}).status_code == 401


def test_retention_removes_expired_bookkeeping_and_keeps_current_rows(app, database, user_ids):
    def stamp(days: int) -> str:
        return (utc_now() - timedelta(days=days)).isoformat().replace("+00:00", "Z")

    analyst = user_ids["analyst"]
    database.execute("DELETE FROM outbox_events")
    for name, days in (("old", 9), ("recent", 1)):
        database.execute("INSERT INTO login_attempts (identifier_hash, ip_address, succeeded, occurred_at) VALUES (?, '192.0.2.1', 0, ?)", (name, stamp(days)))
        database.execute("INSERT INTO outbox_events (workspace_id, event_type, payload, created_at) VALUES (1, ?, '{}', ?)", (name, stamp(days)))
    sessions = (("expired", stamp(60), stamp(40), None), ("revoked", stamp(60), stamp(-1), stamp(35)), ("active", stamp(1), stamp(-1), None))
    for name, created, expires, revoked in sessions:
        database.execute(
            "INSERT INTO auth_sessions (session_hash, user_id, workspace_id, created_at, last_seen_at, expires_at, revoked_at) VALUES (?, ?, 1, ?, ?, ?, ?)",
            (name, analyst, created, created, expires, revoked),
        )
    audit_rows = database.execute("SELECT COUNT(*) FROM security_audit_logs").fetchone()[0]

    assert prune(database) == {"login_attempts": 1, "auth_sessions": 2, "outbox_events": 1}
    assert [row[0] for row in database.execute("SELECT identifier_hash FROM login_attempts")] == ["recent"]
    assert [row[0] for row in database.execute("SELECT event_type FROM outbox_events")] == ["recent"]
    assert [row[0] for row in database.execute("SELECT session_hash FROM auth_sessions")] == ["active"]
    assert database.execute("SELECT COUNT(*) FROM security_audit_logs").fetchone()[0] == audit_rows
    assert prune_if_due(database) is None
    assert prune_if_due(database, utc_now() + timedelta(hours=2)) == {"login_attempts": 0, "auth_sessions": 0, "outbox_events": 0}


def test_operational_health_reports_queues_to_signed_in_users(autopsy_case, client):
    health = client.get("/api/health")
    assert health.status_code == 200
    assert {"import_jobs", "rule_evaluation_failures"} <= set(health.json)
    assert client.get("/api/dashboard").status_code == 410


def test_administrator_can_assign_every_defined_role(client, login_as, user_ids):
    login_as("admin")
    target = f"/api/admin/users/{user_ids['analyst']}"
    for role in ("reviewer", "l1_analyst", "l2_responder", "investigator"):
        updated = client.patch(target, json={"role": role})
        assert updated.status_code == 200 and updated.json["role"] == role
    for invalid in ("owner", ["admin"], None):
        assert client.patch(target, json={"role": invalid}).json["error"]["code"] == "INVALID_ROLE"


def test_request_log_records_outcome_without_query_or_credentials(app, client, caplog):
    with caplog.at_level(logging.INFO, logger=app.logger.name):
        client.post("/api/auth/login?trace=query-secret-value", json=WRONG, headers={"X-Correlation-ID": "hardening-test-0001"})
        client.get("/health/live")
    lines = [record.getMessage() for record in caplog.records if record.getMessage().startswith("request ")]
    assert len(lines) == 1
    assert "method=POST path=/api/auth/login status=401" in lines[0] and "correlation_id=hardening-test-0001" in lines[0]
    assert "query-secret-value" not in caplog.text and WRONG["password"] not in caplog.text and WRONG["email"] not in caplog.text
