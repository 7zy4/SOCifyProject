"""Bounded retention for operational bookkeeping; evidence, custody and audit records are never pruned here."""

import sqlite3
from datetime import datetime, timedelta

from .db import database_is_busy
from .timeutils import utc_now

LOGIN_ATTEMPT_DAYS = 7
ENDED_SESSION_DAYS = 30
PRUNE_INTERVAL = timedelta(hours=1)
MARKER = "maintenance_pruned_at"


def _stamp(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def prune(connection: sqlite3.Connection, now: datetime | None = None) -> dict[str, int]:
    """Delete rows whose only purpose has expired and record when that happened."""
    moment = now or utc_now()
    ended = _stamp(moment - timedelta(days=ENDED_SESSION_DAYS))
    removed = {
        "login_attempts": connection.execute(
            "DELETE FROM login_attempts WHERE occurred_at < ?", (_stamp(moment - timedelta(days=LOGIN_ATTEMPT_DAYS)),)
        ).rowcount,
        "auth_sessions": connection.execute(
            "DELETE FROM auth_sessions WHERE expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?)", (ended, ended)
        ).rowcount,
    }
    connection.execute(
        "INSERT INTO schema_meta (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (MARKER, _stamp(moment), _stamp(moment)),
    )
    return removed


def prune_if_due(connection: sqlite3.Connection, now: datetime | None = None) -> dict[str, int] | None:
    """Run at most once per interval; a busy database postpones the work instead of failing the caller."""
    moment = now or utc_now()
    try:
        marker = connection.execute("SELECT value FROM schema_meta WHERE key = ?", (MARKER,)).fetchone()
        if marker and str(marker[0]) > _stamp(moment - PRUNE_INTERVAL):
            return None
        return prune(connection, moment)
    except sqlite3.OperationalError as exc:
        if not database_is_busy(exc):
            raise
        return None
