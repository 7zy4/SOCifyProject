"""API tokens: shown once, stored hashed, limited to declared scopes and their team, revocable, and CSRF-safe."""

import hashlib
import json
from datetime import timedelta

import pytest

from scripts.bootstrap_team import create_manager
from socify.timeutils import utc_now
from tests.conftest import DEMO_LOGIN_VALUE, issue_session


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def make_token(client, login_as):
    def make(scopes, name="SIEM integration", days=90):
        login_as("soc_manager")
        created = client.post("/api/tokens", json={"name": name, "scopes": scopes, "expires_in_days": days})
        assert created.status_code == 201, created.json
        with client.session_transaction() as state:
            state.clear()
        return created.json

    return make


def test_the_token_is_shown_once_and_only_its_hash_is_stored(client, database, make_token):
    created = make_token(["cases:read"])
    token = created["token"]
    assert token.startswith("socify_pat_") and len(token) == len("socify_pat_") + 43
    row = database.execute("SELECT * FROM api_tokens WHERE id = ?", (created["item"]["id"],)).fetchone()
    assert row["token_hash"] == hashlib.sha256(token.encode()).hexdigest() and token not in json.dumps(dict(row))
    assert created["item"]["display_prefix"] == token[:17] and created["item"]["scopes"] == ["cases:read"]
    assert "token" not in json.dumps(created["item"]).replace("display_prefix", "")


def test_only_managers_manage_tokens(client, login_as):
    login_as("analyst")
    assert client.get("/api/tokens").status_code == 403
    assert client.post("/api/tokens", json={"name": "Mine", "scopes": ["cases:read"]}).status_code == 403
    assert client.delete("/api/tokens/1").status_code == 403


@pytest.mark.parametrize(
    "body",
    [
        {"name": "ab", "scopes": ["cases:read"]},
        {"name": "Valid name", "scopes": []},
        {"name": "Valid name", "scopes": ["cases:admin"]},
        {"name": "Valid name", "scopes": ["cases:read", "cases:read"]},
        {"name": "Valid name", "scopes": ["cases:read"], "expires_in_days": 0},
        {"name": "Valid name", "scopes": ["cases:read"], "expires_in_days": 400},
        {"name": "Valid name", "scopes": ["cases:read"], "role": "admin"},
    ],
)
def test_token_requests_are_validated(client, login_as, body):
    login_as("soc_manager")
    response = client.post("/api/tokens", json=body)
    assert response.status_code == 422 and response.json["error"]["code"] == "INVALID_TOKEN_REQUEST"


def test_a_token_reaches_only_endpoints_declaring_one_of_its_scopes(client, make_token, autopsy_case):
    reader = make_token(["cases:read"])["token"]
    assert client.get("/api/cases", headers=_bearer(reader)).status_code == 200
    assert client.get(f"/api/cases/{autopsy_case}", headers=_bearer(reader)).status_code == 200
    denied = client.get("/api/audit", headers=_bearer(reader))
    assert denied.status_code == 403 and denied.json["error"]["code"] == "TOKEN_SCOPE_DENIED"
    for path in ("/api/team", "/api/auth/me", "/api/tokens"):
        refused = client.get(path, headers=_bearer(reader))
        assert refused.status_code == 403 and refused.json["error"]["code"] == "TOKEN_NOT_ACCEPTED", path
    minted = client.post("/api/tokens", headers=_bearer(reader), json={"name": "Escalation", "scopes": ["audit:read"]})
    assert minted.status_code == 403


def test_bearer_requests_ignore_cookies_and_need_no_csrf_but_cookie_requests_still_do(app, client, database, make_token, login_as):
    writer = make_token(["cases:write"])
    app.config.update(WTF_CSRF_ENABLED=True)
    created = client.post(
        "/api/cases", headers=_bearer(writer["token"]), json={"title": "Raised by integration", "reason": "alert_review", "objective": "Triage the SIEM alert"}
    )
    assert created.status_code == 201, created.json
    audit = database.execute(
        "SELECT actor_id, details FROM security_audit_logs WHERE action = 'create' AND resource_type = 'case' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    manager = database.execute("SELECT id FROM users WHERE role = 'soc_manager'").fetchone()[0]
    assert audit["actor_id"] == manager and json.loads(audit["details"])["api_token_id"] == writer["item"]["id"]
    login_as("analyst")
    refused = client.post("/api/cases", json={"title": "Cookie without token", "reason": "alert_review", "objective": "Must carry CSRF"})
    assert refused.status_code == 400 and refused.json["error"]["code"] == "CSRF_VALIDATION_FAILED"
    last = database.execute("SELECT last_used_at, last_used_ip FROM api_tokens WHERE id = ?", (writer["item"]["id"],)).fetchone()
    assert last["last_used_at"] and last["last_used_ip"] == "127.0.0.1"


def test_revoked_expired_unknown_tokens_and_inactive_owners_are_refused(client, database, make_token, login_as):
    first, second, third = (make_token(["cases:read"], name=f"Token {index}") for index in range(3))
    login_as("soc_manager")
    assert client.delete(f"/api/tokens/{first['item']['id']}").status_code == 204
    assert client.delete(f"/api/tokens/{first['item']['id']}").status_code == 204
    database.execute(
        "UPDATE api_tokens SET expires_at = ? WHERE id = ?", ((utc_now() - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"), second["item"]["id"])
    )
    with client.session_transaction() as state:
        state.clear()
    for token in (first["token"], second["token"], "socify_pat_" + "A" * 43, "socify_pat_short"):
        refused = client.get("/api/cases", headers=_bearer(token))
        assert refused.status_code == 401 and refused.json["error"]["code"] == "TOKEN_INVALID"
        assert refused.headers["WWW-Authenticate"].startswith("Bearer")
    database.execute("UPDATE users SET is_active = 0 WHERE role = 'soc_manager'")
    assert client.get("/api/cases", headers=_bearer(third["token"])).status_code == 401


def test_wrong_tokens_are_rate_limited_per_address(app, client):
    app.config.update(RATE_LIMIT_SOURCE_KEY_ATTEMPTS=3)
    for _ in range(3):
        assert client.get("/api/cases", headers=_bearer("socify_pat_" + "B" * 43)).status_code == 401
    limited = client.get("/api/cases", headers=_bearer("socify_pat_" + "C" * 43))
    assert limited.status_code == 429 and limited.json["error"]["code"] == "TOKEN_RATE_LIMITED"


def test_a_token_stays_inside_its_team(app, client, database, make_token):
    other_manager = create_manager(app, "owner@other-team.example.test", "Other Owner", "Other Team", DEMO_LOGIN_VALUE)
    workspace = database.execute("SELECT workspace_id FROM users WHERE id = ?", (other_manager,)).fetchone()[0]
    with client.session_transaction() as state:
        state.update(user_id=other_manager, workspace_id=workspace, user_role="soc_manager", session_id=issue_session(app, other_manager, workspace))
    foreign_case = client.post("/api/cases", json={"title": "Other team case", "reason": "alert_review", "objective": "Not visible elsewhere"}).json["id"]
    foreign_token = client.post("/api/tokens", json={"name": "Other team token", "scopes": ["cases:read"]}).json["item"]["id"]
    with client.session_transaction() as state:
        state.clear()
    token = make_token(["cases:read"])["token"]
    assert client.get(f"/api/cases/{foreign_case}", headers=_bearer(token)).status_code == 404
    assert foreign_case not in [item["id"] for item in client.get("/api/cases", headers=_bearer(token)).json["items"]]
    manager = database.execute("SELECT id FROM users WHERE email = 'manager@socify.local'").fetchone()[0]
    with client.session_transaction() as state:
        state.update(user_id=manager, workspace_id=1, user_role="soc_manager", session_id=issue_session(app, manager, 1))
    assert client.delete(f"/api/tokens/{foreign_token}").status_code == 404
    assert foreign_token not in [item["id"] for item in client.get("/api/tokens").json["items"]]
