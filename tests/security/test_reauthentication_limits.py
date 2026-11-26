"""Password re-checks inside a session are limited, so a stolen session cannot guess the account password without end."""

import hashlib

import pytest

from tests.conftest import DEMO_LOGIN_VALUE

WRONG = "Wrong-Sample-Value-2026!"

# Synthetic values only; no real credential appears in these tests.
ENDPOINTS = {
    "password_change": ("post", "/api/profile/password", {"current_password": WRONG, "new_password": "Updated-Sample-Value-2026!"}),  # pragma: allowlist secret
    "mfa_enroll": ("post", "/api/auth/mfa/enroll", {"current_password": WRONG}),  # pragma: allowlist secret
    "mfa_disable": ("delete", "/api/auth/mfa", {"current_password": WRONG, "code": "000000"}),  # pragma: allowlist secret
}


def _current_session(client):
    with client.session_transaction() as state:
        return hashlib.sha256(state["session_id"].encode()).hexdigest()


def _guess(client, name):
    method, path, body = ENDPOINTS[name]
    return getattr(client, method)(path, json=body)


@pytest.mark.parametrize("name", list(ENDPOINTS))
def test_each_re_check_is_blocked_after_the_limit_and_ends_the_session(app, client, database, login_as, user_ids, name):
    assert app.config["RATE_LIMIT_REAUTH_ATTEMPTS"] == 5 and app.config["REAUTH_REVOKE_SESSION"]
    login_as("analyst")
    digest = _current_session(client)
    for _ in range(4):
        assert _guess(client, name).status_code == 403
    limited = _guess(client, name)
    assert limited.status_code == 429 and limited.json["error"]["code"] == "REAUTH_RATE_LIMITED"
    assert limited.json["error"]["details"] == {"session_ended": True}
    row = database.execute("SELECT revoked_at, revoked_reason FROM auth_sessions WHERE session_hash = ?", (digest,)).fetchone()
    assert row["revoked_at"] and row["revoked_reason"] == "reauthentication_limit"
    assert client.get("/api/auth/me").status_code == 401
    audit = database.execute(
        "SELECT actor_id, result, details FROM security_audit_logs WHERE action = 'reauthentication_limited' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert audit["actor_id"] == user_ids["analyst"] and audit["result"] == "denied"


def test_the_limit_counts_every_re_check_together_and_a_success_resets_it(client, login_as):
    login_as("analyst")
    for name in ("password_change", "mfa_enroll", "mfa_disable", "password_change"):
        assert _guess(client, name).status_code == 403
    assert client.post("/api/auth/mfa/enroll", json={"current_password": DEMO_LOGIN_VALUE}).status_code == 200
    for _ in range(4):
        assert _guess(client, "password_change").status_code == 403
    assert _guess(client, "password_change").status_code == 429


def test_without_ending_the_session_further_checks_are_refused_before_the_password_is_tried(app, client, login_as):
    app.config.update(REAUTH_REVOKE_SESSION=False)
    login_as("analyst")
    for _ in range(4):
        assert _guess(client, "mfa_enroll").status_code == 403
    limited = _guess(client, "mfa_enroll")
    assert limited.status_code == 429 and limited.json["error"]["details"] == {"session_ended": False}
    assert client.get("/api/auth/me").status_code == 200
    correct = client.post("/api/auth/mfa/enroll", json={"current_password": DEMO_LOGIN_VALUE})
    assert correct.status_code == 429 and correct.json["error"]["code"] == "REAUTH_RATE_LIMITED"


def test_another_account_is_not_affected(app, client, login_as):
    app.config.update(REAUTH_REVOKE_SESSION=False)
    login_as("analyst")
    for _ in range(5):
        _guess(client, "mfa_enroll")
    assert _guess(client, "mfa_enroll").status_code == 429
    login_as("soc_manager")
    assert client.post("/api/auth/mfa/enroll", json={"current_password": DEMO_LOGIN_VALUE}).status_code == 200
