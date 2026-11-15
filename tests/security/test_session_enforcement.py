"""Every request is authenticated against auth_sessions, including under TESTING."""

import hashlib
from datetime import timedelta

import pytest

from socify.timeutils import utc_now
from tests.conftest import issue_session


def _stamp(moment):
    return moment.isoformat().replace("+00:00", "Z")


def _browser(client, user_id, session_id=None):
    with client.session_transaction() as state:
        state.clear()
        state.update(user_id=user_id, workspace_id=1, user_role="analyst")
        if session_id is not None:
            state["session_id"] = session_id


def _row(database, raw):
    return database.execute("SELECT * FROM auth_sessions WHERE session_hash = ?", (hashlib.sha256(raw.encode()).hexdigest(),)).fetchone()


def test_testing_mode_is_not_an_authentication_bypass(app, client, user_ids):
    assert app.config["TESTING"]
    _browser(client, user_ids["analyst"])
    response = client.get("/api/auth/me")
    assert response.status_code == 401 and response.json["error"]["code"] == "AUTHENTICATION_REQUIRED"


def test_recorded_session_authenticates_and_records_activity(app, client, database, user_ids):
    raw = issue_session(app, user_ids["analyst"])
    stale = _stamp(utc_now() - timedelta(minutes=5))
    database.execute("UPDATE auth_sessions SET last_seen_at = ? WHERE session_hash = ?", (stale, hashlib.sha256(raw.encode()).hexdigest()))
    _browser(client, user_ids["analyst"], raw)
    response = client.get("/api/auth/me")
    assert response.status_code == 200 and response.json["user"]["id"] == user_ids["analyst"]
    assert _row(database, raw)["last_seen_at"] > stale


@pytest.mark.parametrize(
    "change",
    [
        ("revoked_at", lambda now: _stamp(now)),
        ("expires_at", lambda now: _stamp(now - timedelta(seconds=1))),
    ],
    ids=["revoked", "expired"],
)
def test_revoked_or_expired_session_is_refused(app, client, database, user_ids, change):
    column, value = change
    raw = issue_session(app, user_ids["analyst"])
    _browser(client, user_ids["analyst"], raw)
    assert client.get("/api/auth/me").status_code == 200
    database.execute(f"UPDATE auth_sessions SET {column} = ? WHERE session_hash = ?", (value(utc_now()), hashlib.sha256(raw.encode()).hexdigest()))
    response = client.get("/api/auth/me")
    assert response.status_code == 401 and response.json["error"]["code"] == "AUTHENTICATION_REQUIRED"


def test_session_issued_to_another_account_is_refused(app, client, user_ids):
    _browser(client, user_ids["analyst"], issue_session(app, user_ids["soc_manager"]))
    assert client.get("/api/auth/me").status_code == 401


def test_unknown_session_identifier_is_refused(client, user_ids):
    _browser(client, user_ids["analyst"], "not-a-recorded-session-identifier")
    assert client.get("/api/auth/me").status_code == 401


def test_logout_revokes_the_recorded_session(app, client, database, login_as, user_ids):
    login_as("analyst")
    with client.session_transaction() as state:
        raw = state["session_id"]
    assert client.post("/api/auth/logout").status_code == 200
    assert _row(database, raw)["revoked_at"]
    _browser(client, user_ids["analyst"], raw)
    assert client.get("/api/auth/me").status_code == 401
