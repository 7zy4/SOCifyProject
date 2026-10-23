import os
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path

import bcrypt
import pytest
from flask import Flask
from flask.testing import FlaskClient

from socify.config import build_config
from socify.security import totp_code
from socify.timeutils import iso_now
from tests.conftest import DEMO_LOGIN_VALUE

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_e2e_02_login_session_logout_and_expiry(client: FlaskClient, database: sqlite3.Connection) -> None:
    login = client.post("/api/auth/login", json={"email": "analyst@socify.local", "password": DEMO_LOGIN_VALUE})
    assert login.status_code == 200
    assert login.json["user"]["role"] == "analyst"
    assert client.get("/api/auth/me").status_code == 200
    sessions = client.get("/api/auth/sessions")
    assert sessions.status_code == 200
    assert len(sessions.json["items"]) == 1
    session_id = sessions.json["items"][0]["id"]
    database.execute("UPDATE auth_sessions SET expires_at = '2000-01-01T00:00:00Z' WHERE id = ?", (session_id,))
    assert client.get("/api/auth/me").status_code == 401
    assert client.post("/api/auth/login", json={"email": "analyst@socify.local", "password": DEMO_LOGIN_VALUE}).status_code == 200
    assert client.post("/api/auth/logout", json={}).status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_e2e_03_registration_cannot_elevate_role(client: FlaskClient, database: sqlite3.Connection) -> None:
    registered = client.post(
        "/api/auth/register",
        json={
            "email": "new.trainee@example.test",
            "name": "New Trainee",
            "password": "New-Training-Account-2026!",
            "role": "admin",
            "workspace_id": 999,
            "is_active": False,
        },
    )
    assert registered.status_code == 201
    row = database.execute("SELECT role, workspace_id, is_active FROM users WHERE email = 'new.trainee@example.test'").fetchone()
    assert dict(row) == {"role": "analyst", "workspace_id": 1, "is_active": 1}


def test_e2e_04_password_change_invalidates_old_value(
    client: FlaskClient,
    login_as: Callable[[str], None],
) -> None:
    login_as("analyst")
    assert (
        client.post(
            "/api/profile/password",
            json={"current_password": "Wrong-Training-Value!", "new_password": "Updated-Training-Value-2026!"},
        ).status_code
        == 403
    )
    changed = client.post(
        "/api/profile/password",
        json={"current_password": DEMO_LOGIN_VALUE, "new_password": "Updated-Training-Value-2026!"},
    )
    assert changed.status_code == 200
    client.post("/api/auth/logout", json={})
    assert client.post("/api/auth/login", json={"email": "analyst@socify.local", "password": DEMO_LOGIN_VALUE}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "analyst@socify.local", "password": "Updated-Training-Value-2026!"}).status_code == 200


def test_e2e_05_mfa_enrollment_login_backup_code_and_revoke(
    client: FlaskClient,
    login_as: Callable[[str], None],
) -> None:
    login_as("analyst")
    enrollment = client.post("/api/auth/mfa/enroll", json={})
    assert enrollment.status_code == 200
    code = totp_code(enrollment.json["secret"], int(time.time()))
    verified = client.post("/api/auth/mfa/verify", json={"code": code})
    assert verified.status_code == 200
    assert len(verified.json["backup_codes"]) == 10
    backup = verified.json["backup_codes"][0]
    client.post("/api/auth/logout", json={})
    required = client.post("/api/auth/login", json={"email": "analyst@socify.local", "password": DEMO_LOGIN_VALUE})
    assert required.status_code == 428
    assert required.json["error"]["code"] == "MFA_REQUIRED"
    with_backup = client.post("/api/auth/login", json={"email": "analyst@socify.local", "password": DEMO_LOGIN_VALUE, "mfa_code": backup})
    assert with_backup.status_code == 200
    client.post("/api/auth/logout", json={})
    assert client.post("/api/auth/login", json={"email": "analyst@socify.local", "password": DEMO_LOGIN_VALUE, "mfa_code": backup}).status_code == 401
    valid_code = totp_code(enrollment.json["secret"], int(time.time()))
    assert client.post("/api/auth/login", json={"email": "analyst@socify.local", "password": DEMO_LOGIN_VALUE, "mfa_code": valid_code}).status_code == 200
    disabled = client.delete("/api/auth/mfa", json={"current_password": DEMO_LOGIN_VALUE, "code": valid_code})
    assert disabled.status_code == 204


def test_login_rate_limit_is_deterministic(client: FlaskClient) -> None:
    for _ in range(3):
        assert client.post("/api/auth/login", json={"email": "analyst@socify.local", "password": "Invalid-Training-Value"}).status_code == 401
    limited = client.post("/api/auth/login", json={"email": "analyst@socify.local", "password": DEMO_LOGIN_VALUE})
    assert limited.status_code == 429
    assert limited.json["error"]["code"] == "LOGIN_RATE_LIMITED"


def test_csrf_is_enforced_and_valid_token_is_accepted(
    app: Flask,
    client: FlaskClient,
    login_as: Callable[[str], None],
) -> None:
    app.config["WTF_CSRF_ENABLED"] = True
    login_as("analyst")
    missing = client.post("/api/incidents", json={"title": "CSRF must reject this request"})
    assert missing.status_code == 400
    assert missing.json["error"]["code"] == "CSRF_VALIDATION_FAILED"
    token = client.get("/api/auth/csrf").json["csrf_token"]
    accepted = client.post("/api/incidents", headers={"X-CSRFToken": token}, json={"title": "CSRF protected request"})
    assert accepted.status_code == 201


def test_security_headers_and_standard_errors(client: FlaskClient) -> None:
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert "unsafe-inline" not in response.headers["Content-Security-Policy"]
    missing = client.get("/api/does-not-exist")
    assert missing.status_code == 404
    assert missing.json["error"]["code"] == "NOT_FOUND"
    assert missing.json["correlation_id"] == missing.headers["X-Correlation-ID"]


def test_production_requires_external_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOCIFY_ENV", "production")
    monkeypatch.delenv("SOCIFY_SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError, match="SOCIFY_SECRET_KEY"):
        build_config()


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("get", "/api/admin/users", None),
        ("get", "/api/audit", None),
        ("post", "/api/rules", {"name": "Denied", "dsl": {}}),
        ("post", "/api/sources", {"name": "Denied", "type": "file"}),
        ("post", "/api/playbooks", {"name": "Denied", "steps": []}),
    ],
)
def test_e2e_43_analyst_cannot_call_administrative_operations(
    client: FlaskClient,
    login_as: Callable[[str], None],
    method: str,
    path: str,
    payload: dict[str, object] | None,
) -> None:
    login_as("analyst")
    response = getattr(client, method)(path, json=payload) if payload is not None else getattr(client, method)(path)
    assert response.status_code == 403
    assert response.json["error"]["code"] == "PERMISSION_DENIED"


def test_e2e_44_cross_workspace_case_event_and_score_ids_are_hidden(
    client: FlaskClient,
    login_as: Callable[[str], None],
    database: sqlite3.Connection,
) -> None:
    database.execute("INSERT INTO training_workspaces (id, public_id, name, created_at) VALUES (2, 'workspace-two', 'Workspace Two', ?)", (iso_now(),))
    password_hash = bcrypt.hashpw(b"Isolated-Workspace-Password!", bcrypt.gensalt(rounds=4)).decode()
    database.execute(
        "INSERT INTO users (email, password_hash, name, role, workspace_id, created_at, is_active) VALUES ('other@example.test', ?, 'Other Analyst', 'analyst', 2, ?, 1)",
        (password_hash, iso_now()),
    )
    other_user = database.execute("SELECT id FROM users WHERE email = 'other@example.test'").fetchone()[0]
    database.execute(
        "INSERT INTO security_events (event_id, workspace_id, source, source_type, severity, category, event_type, title, event_time, ingested_at, timestamp, raw_data, normalized_fields, tags, mitre_ids, status, created_by, parser_version, raw_hash, provenance) VALUES ('EVT-OTHER', 2, 'fixture', 'training', 'low', 'test', 'test', 'Other event', ?, ?, ?, '{}', '{}', '[]', '[]', 'open', ?, 'test', 'hash', '{}')",
        (iso_now(), iso_now(), iso_now(), other_user),
    )
    other_event = database.execute("SELECT id FROM security_events WHERE event_id = 'EVT-OTHER'").fetchone()[0]
    database.execute(
        "INSERT INTO incident_cases (reference, workspace_id, title, description, severity, priority, status, creator, reporter, tags, mitre_ids, created_at, updated_at) VALUES ('CASE-OTHER', 2, 'Other case', '', 'low', 'low', 'new', ?, ?, '[]', '[]', ?, ?)",
        (other_user, other_user, iso_now(), iso_now()),
    )
    other_case = database.execute("SELECT id FROM incident_cases WHERE reference = 'CASE-OTHER'").fetchone()[0]
    login_as("admin")
    assert client.get(f"/api/events/{other_event}").status_code == 404
    assert client.get(f"/api/incidents/{other_case}").status_code == 404


def test_training_run_object_scope_hides_another_trainee(
    client: FlaskClient,
    login_as: Callable[[str], None],
    database: sqlite3.Connection,
    user_ids: dict[str, int],
) -> None:
    scenario_version = database.execute("SELECT id FROM scenario_versions LIMIT 1").fetchone()[0]
    database.execute(
        "INSERT INTO training_runs (run_id, workspace_id, scenario_version_id, user_id, difficulty, seed, state, current_step, playback_rate, started_at, snapshot) VALUES ('RUN-INSTRUCTOR', 1, ?, ?, 'beginner', 1, 'running', 0, 1, ?, '{}')",
        (scenario_version, user_ids["instructor"], iso_now()),
    )
    run_id = database.execute("SELECT id FROM training_runs WHERE run_id = 'RUN-INSTRUCTOR'").fetchone()[0]
    login_as("analyst")
    assert client.get(f"/api/training/runs/{run_id}").status_code == 404
    assert client.get(f"/api/training/runs/{run_id}/score").status_code == 404
    login_as("admin")
    created = client.post("/api/events", json={"source": "private-instructor-source", "title": "Private training event", "training_run_id": run_id})
    assert created.status_code == 201
    login_as("analyst")
    dashboard = client.get("/api/dashboard").json
    assert all(item["source"] != "private-instructor-source" for item in dashboard["top_sources"])
    assert all(item["source"] != "private-instructor-source" for item in client.get("/api/stats").json["top_sources"])
    login_as("admin")
    assert any(item["source"] == "private-instructor-source" for item in client.get("/api/dashboard").json["top_sources"])


def test_source_secret_is_encrypted_and_redacted_from_audit(
    client: FlaskClient,
    login_as: Callable[[str], None],
    database: sqlite3.Connection,
) -> None:
    login_as("admin")
    credential_value = "acceptance-private-credential"
    created = client.post("/api/sources", json={"name": "Secret source", "type": "file", "credential": credential_value})
    assert created.status_code == 201
    row = database.execute("SELECT api_key, credential_ciphertext FROM event_sources WHERE id = ?", (created.json["id"],)).fetchone()
    assert row["api_key"] is None
    assert row["credential_ciphertext"] != credential_value
    assert credential_value not in row["credential_ciphertext"]
    assert credential_value not in client.get("/api/sources").get_data(as_text=True)
    assert credential_value not in client.get("/api/audit").get_data(as_text=True)


def test_ssrf_local_endpoint_is_blocked_without_connecting(
    client: FlaskClient,
    login_as: Callable[[str], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOCIFY_SOURCE_ALLOWLIST", "localhost")
    login_as("admin")
    source = client.post("/api/sources", json={"name": "Blocked local target", "type": "http", "endpoint": "https://localhost/latest/meta-data"})
    assert source.status_code == 201
    tested = client.post(f"/api/sources/{source.json['id']}/test", json={})
    assert tested.status_code == 422
    assert tested.json["status"] == "failed"
    assert "محجوب" in tested.json["message"]


def test_xxe_binary_and_oversized_uploads_fail_safely(
    app: Flask,
    client: FlaskClient,
    login_as: Callable[[str], None],
) -> None:
    login_as("analyst")
    xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><Event>&xxe;</Event>'
    rejected = client.post("/api/imports/preview", json={"filename": "event.xml", "format": "sysmon_xml", "content": xml})
    assert rejected.status_code == 422
    assert "entities are not allowed" in rejected.json["error"]["message"]
    binary = client.post("/api/imports/preview", json={"filename": "events.csv", "format": "csv", "content": "header\u0000value"})
    assert binary.status_code == 422
    app.config["MAX_CONTENT_LENGTH"] = 128
    oversized = client.post("/api/imports", json={"filename": "events.json", "format": "json", "content": "x" * 1024})
    assert oversized.status_code == 413


def test_event_evidence_is_immutable_even_for_manager(
    client: FlaskClient,
    login_as: Callable[[str], None],
    event_payload: dict[str, object],
) -> None:
    login_as("soc_manager")
    event = client.post("/api/events", json={**event_payload, "idempotency_key": "immutable-event"})
    assert event.status_code == 201
    deleted = client.delete(f"/api/events/{event.json['id']}")
    assert deleted.status_code == 409
    assert deleted.json["error"]["code"] == "EVENT_IMMUTABLE"


def test_static_assets_and_generated_reports_contain_no_secret_material() -> None:
    static_text = "\n".join(path.read_text(encoding="utf-8") for path in (REPOSITORY_ROOT / "static").glob("*") if path.is_file())
    forbidden = ["SOCIFY_SECRET_KEY=", "BEGIN PRIVATE KEY", "ghp_", "sk-live-"]
    assert not any(value in static_text for value in forbidden)


def test_environment_file_is_not_tracked() -> None:
    assert not os.path.exists(".env")


def test_codespaces_generates_untracked_runtime_secrets() -> None:
    configuration = Path(".devcontainer/devcontainer.json").read_text(encoding="utf-8")
    assert "codespace-development-session-key" not in configuration
    assert "codespace-development-credential-key" not in configuration
    assert "scripts.prepare_codespace" in configuration
