"""A session ends after a period without activity; status polling is not activity, and the absolute lifetime still applies."""

import hashlib
from datetime import timedelta

import pytest

import socify.security
import socify.timeutils
from socify.config import build_config
from tests.conftest import issue_session

BACKGROUND = {"X-SOCify-Activity": "background"}


class Clock:
    """Moves the application's clock forward without waiting; real time keeps running underneath."""

    def __init__(self, monkeypatch):
        self.offset = timedelta()
        real = socify.timeutils.utc_now
        monkeypatch.setattr(socify.timeutils, "utc_now", lambda: real() + self.offset)
        monkeypatch.setattr(socify.security, "utc_now", lambda: real() + self.offset)

    def advance(self, **delta):
        self.offset += timedelta(**delta)


@pytest.fixture
def clock(monkeypatch):
    return Clock(monkeypatch)


@pytest.fixture
def signed_in(app, client, user_ids):
    raw = issue_session(app, user_ids["analyst"])
    with client.session_transaction() as state:
        state.update(user_id=user_ids["analyst"], workspace_id=1, user_role="analyst", session_id=raw)
    return hashlib.sha256(raw.encode()).hexdigest()


def _row(database, digest):
    return database.execute("SELECT last_seen_at, revoked_at, revoked_reason FROM auth_sessions WHERE session_hash = ?", (digest,)).fetchone()


def test_an_active_session_stays_valid_past_the_idle_limit(app, client, clock, signed_in):
    assert app.config["SESSION_IDLE_SECONDS"] == 3600
    for _ in range(3):
        clock.advance(minutes=50)
        assert client.get("/api/auth/me").status_code == 200


def test_an_idle_session_is_ended_and_says_why(client, database, clock, signed_in):
    clock.advance(minutes=61)
    response = client.get("/api/auth/me")
    assert response.status_code == 401
    assert response.json["error"]["code"] == "AUTHENTICATION_REQUIRED" and response.json["error"]["details"] == {"reason": "idle"}
    row = _row(database, signed_in)
    assert row["revoked_at"] and row["revoked_reason"] == "idle"


def test_an_idle_page_request_returns_to_sign_in_and_back(client, clock, signed_in):
    clock.advance(minutes=61)
    response = client.get("/cases/7?tab=logs")
    assert response.status_code == 302
    assert "/login?" in response.location and "reason=idle" in response.location and "next=/cases/7?tab%3Dlogs" in response.location
    page = client.get(response.location)
    assert "انتهت جلستك لعدم النشاط".encode() in page.data
    assert b'name="next" value="/cases/7?tab=logs"' in page.data


def test_background_requests_are_checked_but_do_not_extend_the_session(client, database, clock, signed_in):
    before = _row(database, signed_in)["last_seen_at"]
    clock.advance(minutes=40)
    assert client.get("/api/auth/me", headers=BACKGROUND).status_code == 200
    assert _row(database, signed_in)["last_seen_at"] == before
    clock.advance(minutes=21)
    refused = client.get("/api/auth/me", headers=BACKGROUND)
    assert refused.status_code == 401 and refused.json["error"]["details"] == {"reason": "idle"}


def test_the_absolute_lifetime_still_applies_to_an_active_session(client, database, clock, signed_in):
    for _ in range(9):
        clock.advance(minutes=50)
        assert client.get("/api/auth/me").status_code == 200
    clock.advance(minutes=50)
    response = client.get("/api/auth/me")
    assert response.status_code == 401 and "details" not in response.json["error"]
    assert _row(database, signed_in)["revoked_reason"] is None


def test_zero_disables_the_idle_limit(app, client, clock, signed_in):
    app.config.update(SESSION_IDLE_SECONDS=0)
    clock.advance(hours=7)
    assert client.get("/api/auth/me").status_code == 200


@pytest.mark.parametrize(("value", "accepted"), [("0", True), ("300", True), ("3600", True), ("299", False), ("1", False), ("-5", False)])
def test_the_idle_setting_is_validated_at_start_up(monkeypatch, value, accepted):
    monkeypatch.setenv("SOCIFY_SESSION_IDLE_SECONDS", value)
    if accepted:
        assert build_config()["SESSION_IDLE_SECONDS"] == int(value)
    else:
        with pytest.raises(RuntimeError, match="SOCIFY_SESSION_IDLE_SECONDS"):
            build_config()
