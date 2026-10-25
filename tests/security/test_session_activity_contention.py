import sqlite3
import time

import pytest
from conftest import DEMO_LOGIN_VALUE

from socify import security


def test_authenticated_reads_survive_an_import_writer_without_caching_revocation(app, client, database):
    database.execute("PRAGMA journal_mode=WAL")
    assert client.post("/api/auth/login", json={"email": "analyst@socify.local", "password": DEMO_LOGIN_VALUE}).status_code == 200
    session_id = client.get("/api/auth/sessions").json["items"][0]["id"]
    database.execute("UPDATE auth_sessions SET last_seen_at='2000-01-01T00:00:00Z' WHERE id=?", (session_id,))
    database.execute("BEGIN IMMEDIATE")
    try:
        started = time.monotonic()
        assert client.get("/api/auth/me").status_code == 200
        assert time.monotonic() - started < 1
        assert database.execute("SELECT last_seen_at FROM auth_sessions WHERE id=?", (session_id,)).fetchone()[0] == "2000-01-01T00:00:00Z"
    finally:
        database.rollback()
    assert client.get("/api/auth/me").status_code == 200
    touched = database.execute("SELECT last_seen_at FROM auth_sessions WHERE id=?", (session_id,)).fetchone()[0]
    assert touched != "2000-01-01T00:00:00Z"
    assert client.get("/api/auth/me").status_code == 200
    assert database.execute("SELECT last_seen_at FROM auth_sessions WHERE id=?", (session_id,)).fetchone()[0] == touched
    database.execute("UPDATE auth_sessions SET revoked_at=? WHERE id=?", (touched, session_id))
    assert client.get("/api/auth/me").status_code == 401


def test_session_activity_propagates_storage_errors_and_restores_timeout(app, monkeypatch):
    class BrokenStorage:
        restored = None

        def execute(self, query, parameters=()):
            if query == "PRAGMA busy_timeout":
                return self
            if query.startswith("UPDATE"):
                error = sqlite3.OperationalError("Fixture storage failure")
                error.sqlite_errorcode = sqlite3.SQLITE_FULL
                raise error
            self.restored = query
            return self

        def fetchone(self):
            return (10000,)

    connection = BrokenStorage()
    monkeypatch.setattr(security, "get_db", lambda: connection)
    with app.app_context(), pytest.raises(sqlite3.OperationalError):
        security._touch_session({"id": 1, "last_seen_at": "2000-01-01T00:00:00Z"}, "2026-10-25T10:00:00Z")
    assert connection.restored == "PRAGMA busy_timeout = 10000"
