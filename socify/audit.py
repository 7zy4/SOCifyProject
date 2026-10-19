import json
import sqlite3
from typing import Any

from flask import has_request_context, request, session

from .db import inserted_id
from .schema import insert_outbox
from .security import correlation_id, redact
from .timeutils import iso_now


def record_audit(
    connection: sqlite3.Connection,
    action: str,
    resource_type: str,
    resource_id: object | None,
    result: str = "success",
    details: dict[str, Any] | None = None,
    actor: int | None = None,
    workspace: int | None = None,
) -> int:
    actor_id = actor if actor is not None else session.get("user_id") if has_request_context() else None
    workspace_id = workspace if workspace is not None else session.get("workspace_id") if has_request_context() else None
    ip_address = request.remote_addr if has_request_context() else None
    user_agent = request.headers.get("User-Agent", "")[:500] if has_request_context() else None
    clean_details = redact(details or {})
    cursor = connection.execute(
        """INSERT INTO security_audit_logs
        (workspace_id, actor_id, action, resource_type, resource_id, result, details, correlation_id, ip_address, user_agent, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            workspace_id,
            actor_id,
            action,
            resource_type,
            None if resource_id is None else str(resource_id),
            result,
            json.dumps(clean_details, ensure_ascii=False, separators=(",", ":")),
            correlation_id() if has_request_context() else "system",
            ip_address,
            user_agent,
            iso_now(),
        ),
    )
    if isinstance(workspace_id, int):
        insert_outbox(connection, workspace_id, f"{resource_type}.{action}", {"resource_id": resource_id, "result": result})
    return inserted_id(cursor)


def record_training_action(
    connection: sqlite3.Connection,
    run_id: int | None,
    user_id: int,
    action_type: str,
    target_type: str | None,
    target_id: object | None,
    payload: dict[str, Any],
    idempotency_key: str,
) -> None:
    if run_id is None:
        return
    connection.execute(
        """INSERT OR IGNORE INTO trainee_actions
        (run_id, user_id, action_type, target_type, target_id, payload, occurred_at, idempotency_key)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            run_id,
            user_id,
            action_type,
            target_type,
            None if target_id is None else str(target_id),
            json.dumps(redact(payload), ensure_ascii=False, separators=(",", ":")),
            iso_now(),
            idempotency_key,
        ),
    )
