"""API tokens for integrations and scripts: bearer authentication without a browser session.

A token belongs to one team and acts as the manager who created it, so it can never do more than that account; its
scopes narrow it further to the endpoints that declare one with @accepts_token. Every other endpoint refuses a token.
Only the SHA-256 of the token is stored, and the full value is shown once, when it is created. A bearer request is
authenticated by the token alone (cookies are ignored), which is why only those requests skip the CSRF check:
a browser cannot attach an Authorization header to a cross-site request.
"""

import hashlib
import json
import re
import secrets
import sqlite3
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from flask import Blueprint, current_app, g, jsonify, request

from .audit import record_audit
from .db import get_db, inserted_id, transaction
from .security import current_user, error_response, login_required
from .timeutils import iso_now, utc_now

api_tokens_api = Blueprint("api_tokens", __name__)

PREFIX = "socify_pat_"
SCOPES = ("intake:write", "cases:read", "cases:write", "search:read", "reports:read", "audit:read")
MANAGER_ROLES = {"soc_manager", "admin"}
TOKEN_PATTERN = re.compile(r"socify_pat_[A-Za-z0-9_-]{43}")
MAX_ACTIVE_TOKENS = 50

SCHEMA = """
CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    display_prefix TEXT NOT NULL,
    scopes TEXT NOT NULL CHECK (json_valid(scopes)),
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_used_at TEXT,
    last_used_ip TEXT,
    revoked_at TEXT
);
"""


def migrate(connection: sqlite3.Connection) -> None:
    connection.execute(SCHEMA)


def accepts_token[F: Callable[..., Any]](scope: str, *, session: bool = True) -> Callable[[F], F]:
    """Let an API token with `scope` call this endpoint; the endpoint's own permission checks still apply.

    session=False marks an endpoint that never uses a browser session (it authenticates every request itself, as alert
    intake does with HMAC signatures), so a request without a token is not held to the cookie CSRF check either.
    """
    if scope not in SCOPES:
        raise ValueError(f"unknown token scope {scope}")

    def mark(function: F) -> F:
        function.token_scope = scope  # type: ignore[attr-defined]
        function.session_auth = session  # type: ignore[attr-defined]
        return function

    return mark


def bearer_value() -> str | None:
    scheme, _, value = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not value.strip().startswith(PREFIX):
        return None
    return value.strip()


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _refuse(code: str, message: str, status: int):
    response = error_response(code, message, status)
    if status == 401:
        response[0].headers["WWW-Authenticate"] = 'Bearer realm="socify-api"'
    return response


def authenticate_bearer(view: Callable[..., Any] | None):
    """Authenticate a bearer request for this view; returns None when it may proceed, else the refusal response."""
    from .auth import attempts_exhausted, record_failed_attempt

    token = bearer_value()
    if token is None:
        return None
    scope = getattr(view, "token_scope", None)
    if attempts_exhausted("api-token", "RATE_LIMIT_SOURCE_KEY_ATTEMPTS"):
        return _refuse("TOKEN_RATE_LIMITED", "محاولات رموز API خاطئة كثيرة من هذا العنوان. حاول لاحقًا", 429)
    row = get_db().execute("SELECT * FROM api_tokens WHERE token_hash = ?", (_digest(token),)).fetchone() if TOKEN_PATTERN.fullmatch(token) else None
    now = iso_now()
    if row is None or row["revoked_at"] or row["expires_at"] <= now:
        record_failed_attempt("api-token")
        return _refuse("TOKEN_INVALID", "رمز API غير صالح أو ملغى أو منتهٍ", 401)
    if scope is None:
        return _refuse("TOKEN_NOT_ACCEPTED", "هذا المسار لا يقبل رموز API", 403)
    if scope not in json.loads(row["scopes"]):
        return _refuse("TOKEN_SCOPE_DENIED", "رمز API لا يملك النطاق المطلوب لهذا المسار", 403)
    user = (
        get_db()
        .execute(
            "SELECT id, email, socify_user_name(name,name_ar,name_en) AS name, name AS account_name, name_ar, name_en, role, team, workspace_id, leaderboard_opt_in, is_active "
            "FROM users WHERE id = ? AND is_active = 1 AND workspace_id = ?",
            (row["user_id"], row["workspace_id"]),
        )
        .fetchone()
    )
    if user is None:
        return _refuse("TOKEN_INVALID", "رمز API غير صالح أو ملغى أو منتهٍ", 401)
    principal = dict(user)
    policy = (
        get_db()
        .execute("SELECT permissions FROM team_role_permissions WHERE workspace_id = ? AND role = ?", (principal["workspace_id"], principal["role"]))
        .fetchone()
    )
    if policy:
        principal["role_permissions"] = json.loads(policy["permissions"])
    principal["api_token_id"] = int(row["id"])
    g.current_user = principal
    g.api_token_id = int(row["id"])
    _touch(row, now)
    return None


def _touch(row: sqlite3.Row, now: str) -> None:
    """Record the last use at most once a minute; a busy database skips it rather than failing the request."""
    cutoff = (utc_now() - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    if row["last_used_at"] and row["last_used_at"] >= cutoff:
        return
    try:
        get_db().execute("UPDATE api_tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?", (now, request.remote_addr or "unknown", row["id"]))
    except sqlite3.OperationalError as error:
        from .db import database_is_busy

        if not database_is_busy(error):
            raise


def _manager() -> dict[str, Any] | None:
    user = current_user()
    if user is None or user.get("role") not in MANAGER_ROLES or getattr(g, "api_token_id", None) is not None:
        return None
    return user


def _view(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "display_prefix": row["display_prefix"],
        "scopes": json.loads(row["scopes"]),
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "last_used_at": row["last_used_at"],
        "last_used_ip": row["last_used_ip"],
        "revoked_at": row["revoked_at"],
        "active": not row["revoked_at"] and row["expires_at"] > iso_now(),
        "owner_name": row["owner_name"],
    }


def _rows(workspace: int) -> list[sqlite3.Row]:
    return (
        get_db()
        .execute(
            """SELECT t.*, socify_user_name(u.name, u.name_ar, u.name_en) AS owner_name FROM api_tokens t JOIN users u ON u.id = t.user_id
            WHERE t.workspace_id = ? ORDER BY t.revoked_at IS NOT NULL, t.created_at DESC LIMIT 200""",
            (workspace,),
        )
        .fetchall()
    )


@api_tokens_api.get("/api/tokens")
@login_required
def list_tokens():
    user = _manager()
    if user is None:
        return error_response("PERMISSION_DENIED", "إدارة رموز API لمدير الفريق", 403)
    return jsonify({"items": [_view(row) for row in _rows(int(user["workspace_id"]))], "scopes": list(SCOPES)})


@api_tokens_api.post("/api/tokens")
@login_required
def create_token():
    user = _manager()
    if user is None:
        return error_response("PERMISSION_DENIED", "إدارة رموز API لمدير الفريق", 403)
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) - {"name", "scopes", "expires_in_days"}:
        return error_response("INVALID_TOKEN_REQUEST", "أرسل الاسم والنطاقات ومدة الصلاحية فقط", 422)
    name, scopes, days = data.get("name"), data.get("scopes"), data.get("expires_in_days", 90)
    if not isinstance(name, str) or not 3 <= len(name.strip()) <= 100 or any(ord(char) < 32 for char in name):
        return error_response("INVALID_TOKEN_REQUEST", "اسم الرمز من 3 إلى 100 محرف", 422)
    if not isinstance(scopes, list) or not scopes or len(set(scopes)) != len(scopes) or not set(scopes) <= set(SCOPES):
        return error_response("INVALID_TOKEN_REQUEST", "اختر نطاقًا واحدًا على الأقل من النطاقات المعروفة", 422)
    if type(days) is not int or not 1 <= days <= 365:
        return error_response("INVALID_TOKEN_REQUEST", "مدة صلاحية الرمز من يوم إلى 365 يومًا", 422)
    workspace = int(user["workspace_id"])
    token = PREFIX + secrets.token_urlsafe(32)
    now = utc_now()
    with transaction():
        active = (
            get_db()
            .execute("SELECT COUNT(*) FROM api_tokens WHERE workspace_id = ? AND revoked_at IS NULL AND expires_at > ?", (workspace, iso_now()))
            .fetchone()[0]
        )
        if active >= MAX_ACTIVE_TOKENS:
            return error_response("TOKEN_LIMIT_REACHED", "بلغ الفريق الحد الأقصى للرموز النشطة؛ ألغِ رمزًا غير مستخدم أولًا", 409)
        token_id = inserted_id(
            get_db().execute(
                """INSERT INTO api_tokens (workspace_id, user_id, name, token_hash, display_prefix, scopes, created_by, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    workspace,
                    user["id"],
                    name.strip(),
                    _digest(token),
                    token[: len(PREFIX) + 6],
                    json.dumps(sorted(scopes)),
                    user["id"],
                    now.isoformat().replace("+00:00", "Z"),
                    (now + timedelta(days=days)).isoformat().replace("+00:00", "Z"),
                ),
            )
        )
        record_audit(get_db(), "create", "api_token", token_id, details={"name": name.strip(), "scopes": sorted(scopes), "expires_in_days": days})
    row = next(row for row in _rows(workspace) if row["id"] == token_id)
    # The only time the full value leaves the server.
    return jsonify({"token": token, "item": _view(row)}), 201


@api_tokens_api.delete("/api/tokens/<int:token_id>")
@login_required
def revoke_token(token_id: int):
    user = _manager()
    if user is None:
        return error_response("PERMISSION_DENIED", "إدارة رموز API لمدير الفريق", 403)
    with transaction():
        changed = get_db().execute(
            "UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND workspace_id = ? AND revoked_at IS NULL", (iso_now(), token_id, int(user["workspace_id"]))
        )
        if changed.rowcount != 1:
            exists = get_db().execute("SELECT 1 FROM api_tokens WHERE id = ? AND workspace_id = ?", (token_id, int(user["workspace_id"]))).fetchone()
            if not exists:
                return error_response("TOKEN_NOT_FOUND", "الرمز غير موجود", 404)
            return "", 204
        record_audit(get_db(), "revoke", "api_token", token_id)
    return "", 204


def register(app) -> None:
    """Exempt token-accepting views from the cookie CSRF check and check CSRF there for cookie requests instead."""
    from .extensions import csrf

    for name, view in app.view_functions.items():
        if getattr(view, "token_scope", None):
            csrf.exempt(view)
            app.config.setdefault("SOCIFY_TOKEN_VIEWS", set()).add(name)

    @app.before_request
    def authenticate_api_token():
        view = app.view_functions.get(request.endpoint or "")
        if bearer_value() is not None:
            return authenticate_bearer(view)
        if (
            getattr(view, "token_scope", None)
            and getattr(view, "session_auth", True)
            and current_app.config.get("WTF_CSRF_ENABLED", True)
            and request.method in current_app.config.get("WTF_CSRF_METHODS", {"POST", "PUT", "PATCH", "DELETE"})
        ):
            csrf.protect()
        return None
