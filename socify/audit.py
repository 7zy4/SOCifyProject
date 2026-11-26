import json
import sqlite3
from typing import Any

from flask import g, has_request_context, request, session

from .db import inserted_id
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
    """Append a security audit entry with actor, team, client address and user agent; details are redacted before they are stored."""
    principal = getattr(g, "current_user", None) if has_request_context() else None
    via_token = getattr(g, "api_token_id", None) if has_request_context() else None
    # A bearer request has no browser session: its principal is the token's account (socify.api_tokens).
    session_actor = principal["id"] if principal else session.get("user_id") if has_request_context() else None
    session_workspace = principal["workspace_id"] if principal else session.get("workspace_id") if has_request_context() else None
    actor_id = actor if actor is not None else session_actor
    workspace_id = workspace if workspace is not None else session_workspace
    if via_token is not None:
        details = {**(details or {}), "api_token_id": via_token}
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
    return inserted_id(cursor)
