"""The outbox: the only way anything leaves SOCify.

The app and workers have no route to the internet. They write a message to a separate SQLite database (its own volume,
SOCIFY_OUTBOX_DATABASE), and the egress service, which has network access but no case data, delivers it. A message
names a destination (a webhook name, or an email address) and carries the content to send; destination URLs, webhook
secrets and SMTP credentials exist only in the egress service's environment and never in the outbox.

Delivery is retried with exponential backoff up to SOCIFY_EGRESS_MAX_ATTEMPTS; a message that runs out of attempts is
kept as failed so the team's managers can see it and send it again.
"""

import json
import re
import sqlite3
from datetime import timedelta
from pathlib import Path
from typing import Any

from flask import Blueprint, current_app, jsonify

from .audit import record_audit
from .db import database_is_busy
from .security import current_user, error_response, login_required
from .timeutils import iso_now, utc_now

outbox_api = Blueprint("outbox", __name__)

KINDS = ("webhook", "email")
MANAGER_ROLES = {"soc_manager", "admin"}
MAX_PAYLOAD_BYTES = 256 * 1024
WEBHOOK_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
EMAIL_ADDRESS = re.compile(r"[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}")

SCHEMA = """
CREATE TABLE IF NOT EXISTS outbox_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('webhook', 'email')),
    target TEXT NOT NULL,
    payload TEXT NOT NULL CHECK (json_valid(payload)),
    status TEXT NOT NULL CHECK (status IN ('pending', 'sending', 'sent', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    lease_expires_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_outbox_due ON outbox_messages(status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_outbox_workspace ON outbox_messages(workspace_id, id);
CREATE TABLE IF NOT EXISTS outbox_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL REFERENCES outbox_messages(id),
    attempted_at TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('sent', 'retry', 'failed')),
    status_code INTEGER,
    error TEXT
);
CREATE TABLE IF NOT EXISTS worker_heartbeats (
    name TEXT PRIMARY KEY,
    instance TEXT,
    pid INTEGER,
    version TEXT,
    started_at TEXT,
    last_beat_at TEXT,
    state TEXT
);
"""


def _stamp(moment) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def connect_outbox(path: str) -> sqlite3.Connection:
    """Open the outbox database, creating its tables; WAL lets the app write while the egress service delivers."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=15, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 15000")
    try:
        connection.execute("PRAGMA journal_mode = WAL")
    except sqlite3.OperationalError as error:
        if not database_is_busy(error):
            raise
    connection.executescript(SCHEMA)
    return connection


def validate_message(kind: str, target: str, payload: dict[str, Any]) -> str:
    """Check a message before it is queued and return its JSON; raises ValueError when it cannot be sent."""
    if kind not in KINDS:
        raise ValueError("unknown outbox message kind")
    if kind == "webhook" and not (isinstance(target, str) and WEBHOOK_NAME.fullmatch(target)):
        raise ValueError("a webhook message names a configured destination")
    if kind == "email" and not (isinstance(target, str) and EMAIL_ADDRESS.fullmatch(target)):
        raise ValueError("an email message needs one valid recipient address")
    if kind == "email" and not (isinstance(payload.get("subject"), str) and isinstance(payload.get("text"), str)):
        raise ValueError("an email message needs a subject and a text body")
    if kind == "email" and (any(char in payload["subject"] for char in "\r\n") or not 1 <= len(payload["subject"]) <= 200):
        raise ValueError("an email subject is one line of at most 200 characters")
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode()) > MAX_PAYLOAD_BYTES:
        raise ValueError("outbox message is too large")
    return encoded


def enqueue(workspace_id: int, kind: str, target: str, payload: dict[str, Any]) -> int | None:
    """Queue a message for the egress service; returns its id, or None when outbound delivery is turned off."""
    if not current_app.config.get("EGRESS_ENABLED"):
        return None
    encoded = validate_message(kind, target, payload)
    connection = connect_outbox(str(current_app.config["OUTBOX_DATABASE"]))
    try:
        now = iso_now()
        cursor = connection.execute(
            "INSERT INTO outbox_messages (workspace_id, kind, target, payload, status, next_attempt_at, created_at, updated_at) VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)",
            (workspace_id, kind, target, encoded, now, now, now),
        )
        return int(cursor.lastrowid or 0)
    finally:
        connection.close()


def claim(connection: sqlite3.Connection, lease_seconds: int = 120) -> sqlite3.Row | None:
    """Take the oldest due message for delivery; an expired lease (a worker that stopped) makes it due again."""
    now = iso_now()
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute("UPDATE outbox_messages SET status = 'pending', lease_expires_at = NULL WHERE status = 'sending' AND lease_expires_at <= ?", (now,))
        row = connection.execute(
            "SELECT * FROM outbox_messages WHERE status = 'pending' AND next_attempt_at <= ? ORDER BY next_attempt_at, id LIMIT 1", (now,)
        ).fetchone()
        if row is not None:
            connection.execute(
                "UPDATE outbox_messages SET status = 'sending', attempts = attempts + 1, lease_expires_at = ?, updated_at = ? WHERE id = ?",
                (_stamp(utc_now() + timedelta(seconds=lease_seconds)), now, row["id"]),
            )
            row = connection.execute("SELECT * FROM outbox_messages WHERE id = ?", (row["id"],)).fetchone()
        connection.execute("COMMIT")
        return row
    except BaseException:
        connection.execute("ROLLBACK")
        raise


def backoff_seconds(attempts: int) -> int:
    """30 s after the first failure, doubling each time, at most an hour."""
    return min(30 * 2 ** max(attempts - 1, 0), 3600)


def finish(
    connection: sqlite3.Connection, message: sqlite3.Row, *, sent: bool, max_attempts: int, status_code: int | None = None, error: str | None = None
) -> str:
    """Record one delivery attempt and decide what happens next; returns the outcome."""
    now = utc_now()
    if sent:
        outcome, status, next_at = "sent", "sent", _stamp(now)
    elif int(message["attempts"]) >= max_attempts:
        outcome, status, next_at = "failed", "failed", _stamp(now)
    else:
        outcome, status, next_at = "retry", "pending", _stamp(now + timedelta(seconds=backoff_seconds(int(message["attempts"]))))
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            "UPDATE outbox_messages SET status = ?, next_attempt_at = ?, lease_expires_at = NULL, last_error = ?, updated_at = ? WHERE id = ?",
            (status, next_at, None if sent else (error or "delivery failed")[:300], _stamp(now), message["id"]),
        )
        connection.execute(
            "INSERT INTO outbox_results (message_id, attempted_at, outcome, status_code, error) VALUES (?, ?, ?, ?, ?)",
            (message["id"], _stamp(now), outcome, status_code, None if sent else (error or "delivery failed")[:300]),
        )
        connection.execute("COMMIT")
    except BaseException:
        connection.execute("ROLLBACK")
        raise
    return outcome


def _manager() -> dict[str, Any] | None:
    user = current_user()
    return user if user is not None and user.get("role") in MANAGER_ROLES else None


@outbox_api.get("/api/outbox")
@login_required
def outbox_list():
    user = _manager()
    if user is None:
        return error_response("PERMISSION_DENIED", "متابعة الرسائل الصادرة لمدير الفريق", 403)
    if not current_app.config.get("EGRESS_ENABLED"):
        return jsonify({"enabled": False, "items": []})
    connection = connect_outbox(str(current_app.config["OUTBOX_DATABASE"]))
    try:
        rows = connection.execute(
            "SELECT id, kind, target, status, attempts, next_attempt_at, last_error, created_at, updated_at FROM outbox_messages WHERE workspace_id = ? ORDER BY id DESC LIMIT 100",
            (int(user["workspace_id"]),),
        ).fetchall()
    finally:
        connection.close()
    return jsonify({"enabled": True, "items": [dict(row) for row in rows]})


@outbox_api.post("/api/outbox/<int:message_id>/retry")
@login_required
def outbox_retry(message_id: int):
    user = _manager()
    if user is None:
        return error_response("PERMISSION_DENIED", "متابعة الرسائل الصادرة لمدير الفريق", 403)
    if not current_app.config.get("EGRESS_ENABLED"):
        return error_response("EGRESS_DISABLED", "الإرسال الخارجي غير مفعّل", 409)
    connection = connect_outbox(str(current_app.config["OUTBOX_DATABASE"]))
    try:
        changed = connection.execute(
            "UPDATE outbox_messages SET status = 'pending', attempts = 0, next_attempt_at = ?, last_error = NULL, updated_at = ? WHERE id = ? AND workspace_id = ? AND status = 'failed'",
            (iso_now(), iso_now(), message_id, int(user["workspace_id"])),
        )
    finally:
        connection.close()
    if changed.rowcount != 1:
        return error_response("OUTBOX_MESSAGE_NOT_RETRYABLE", "الرسالة غير موجودة أو ليست فاشلة", 404)
    from .db import get_db

    record_audit(get_db(), "retry", "outbox_message", message_id)
    return jsonify({"id": message_id, "status": "pending"})
