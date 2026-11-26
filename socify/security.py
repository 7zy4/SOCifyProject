import base64
import functools
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import struct
import time
from collections.abc import Callable
from datetime import timedelta
from typing import Any, cast

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from flask import current_app, g, jsonify, redirect, request, session, url_for

from .db import get_db
from .outbound import resolve_external_target
from .timeutils import iso_now, utc_now
from .validation import ValidationError

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "analyst": {
        "events.read",
        "events.create",
        "alerts.read",
        "alerts.triage",
        "cases.read",
        "cases.create",
        "cases.update",
        "evidence.add",
        "notes.add",
        "hunt.execute",
        "hunt.save",
        "graph.read",
        "playbooks.request",
        "sources.read",
        "rules.read",
    },
    "soc_manager": {
        "events.read",
        "events.create",
        "alerts.read",
        "alerts.triage",
        "cases.read",
        "cases.create",
        "cases.update",
        "cases.close",
        "cases.override",
        "evidence.add",
        "notes.add",
        "hunt.execute",
        "hunt.save",
        "hunt.share",
        "graph.read",
        "playbooks.request",
        "playbooks.manage",
        "sources.read",
        "sources.manage",
        "rules.read",
        "rules.manage",
        "audit.read",
        "users.read",
    },
    "admin": {"*"},
    "instructor": {
        "events.read",
        "alerts.read",
        "cases.read",
        "cases.create",
        "cases.update",
        "evidence.add",
        "notes.add",
        "hunt.execute",
        "hunt.save",
        "hunt.share",
        "graph.read",
        "playbooks.request",
        "rules.read",
        "sources.read",
    },
    "auditor": {"events.read", "alerts.read", "cases.read", "graph.read", "audit.read", "rules.read", "sources.read"},
}

ROLE_PERMISSIONS.update(
    {
        "l1_analyst": ROLE_PERMISSIONS["analyst"].copy(),
        "l2_responder": ROLE_PERMISSIONS["analyst"].copy(),
        "investigator": ROLE_PERMISSIONS["analyst"].copy(),
        "reviewer": ROLE_PERMISSIONS["auditor"] | {"reports.approve", "notes.add"},
    }
)
ROLE_PERMISSIONS["soc_manager"].update({"reports.approve", "cases.assign", "intel.manage", "samples.download"})
for _role in ("analyst", "l1_analyst", "l2_responder", "investigator", "soc_manager"):
    ROLE_PERMISSIONS[_role].update({"cases.export", "evidence.download"})
# Alert intake (socify.intake): seeing the queue, and turning alerts into cases, links or dismissals.
for _role in ("analyst", "l1_analyst", "l2_responder", "investigator", "soc_manager", "instructor"):
    ROLE_PERMISSIONS[_role].update({"intake.read", "intake.triage"})
for _role in ("auditor", "reviewer"):
    ROLE_PERMISSIONS[_role].add("intake.read")

SENSITIVE_KEYS = {"password", "current_password", "new_password", "api_key", "secret", "token", "credential", "authorization", "backup_codes"}


def correlation_id() -> str:
    """The request's correlation id: a well-formed X-Correlation-ID from the client, else a random one, kept for the whole request."""
    value = getattr(g, "correlation_id", None)
    if isinstance(value, str):
        return value
    generated = request.headers.get("X-Correlation-ID", "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", generated):
        generated = secrets.token_hex(16)
    g.correlation_id = generated
    return generated


def error_response(code: str, message: str, status: int, details: dict[str, Any] | None = None):
    """The JSON error body every API failure uses, with a stable code, a message and the correlation id."""
    payload: dict[str, Any] = {"error": {"code": code, "message": message}, "correlation_id": correlation_id()}
    if details:
        cast(dict[str, Any], payload["error"])["details"] = details
    return jsonify(payload), status


def redact(value: object) -> object:
    if isinstance(value, dict):
        return {key: "[REDACTED]" if key.lower() in SENSITIVE_KEYS else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    return value


def _touch_session(record, now: str) -> None:
    cutoff = (utc_now() - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    if record["last_seen_at"] >= cutoff:
        return
    connection = get_db()
    timeout = connection.execute("PRAGMA busy_timeout").fetchone()[0]
    try:
        connection.execute("PRAGMA busy_timeout = 0")
        connection.execute(
            "UPDATE auth_sessions SET last_seen_at=? WHERE id=? AND last_seen_at<? AND revoked_at IS NULL AND expires_at>?",
            (now, record["id"], cutoff, now),
        )
    except sqlite3.OperationalError as exc:
        if getattr(exc, "sqlite_errorcode", 0) & 0xFF not in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
            raise
    finally:
        connection.execute(f"PRAGMA busy_timeout = {int(timeout)}")


BACKGROUND_ACTIVITY_HEADER = "X-SOCify-Activity"


def _end_idle_session(record) -> None:
    """Record that the session ended for inactivity; a busy database leaves it to the next request, which refuses it the same way."""
    connection = get_db()
    timeout = connection.execute("PRAGMA busy_timeout").fetchone()[0]
    try:
        connection.execute("PRAGMA busy_timeout = 0")
        connection.execute("UPDATE auth_sessions SET revoked_at = ?, revoked_reason = 'idle' WHERE id = ? AND revoked_at IS NULL", (iso_now(), record["id"]))
    except sqlite3.OperationalError as exc:
        if getattr(exc, "sqlite_errorcode", 0) & 0xFF not in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
            raise
    finally:
        connection.execute(f"PRAGMA busy_timeout = {int(timeout)}")


def _session_valid(user_id: int) -> bool:
    raw = session.get("session_id")
    if not isinstance(raw, str):
        return False
    digest = hashlib.sha256(raw.encode()).hexdigest()
    record = (
        get_db()
        .execute(
            "SELECT id, expires_at, revoked_at, revoked_reason, last_seen_at FROM auth_sessions WHERE session_hash = ? AND user_id = ?",
            (digest, user_id),
        )
        .fetchone()
    )
    now = iso_now()
    if not record or record["revoked_at"] or record["expires_at"] <= now:
        if record and record["revoked_reason"] == "idle":
            g.session_end_reason = "idle"
        return False
    idle = int(current_app.config.get("SESSION_IDLE_SECONDS") or 0)
    if idle > 0 and record["last_seen_at"] <= (utc_now() - timedelta(seconds=idle)).isoformat().replace("+00:00", "Z"):
        _end_idle_session(record)
        g.session_end_reason = "idle"
        return False
    # Polling for job status is not the person working: it is checked like any request but does not keep the session alive.
    if request.headers.get(BACKGROUND_ACTIVITY_HEADER, "").strip().lower() != "background":
        _touch_session(record, now)
    return True


def authentication_required():
    """The 401 every protected API answers when nobody is signed in; it says when the session ended for inactivity."""
    details = {"reason": "idle"} if getattr(g, "session_end_reason", None) == "idle" else None
    return error_response("AUTHENTICATION_REQUIRED", "يلزم تسجيل الدخول للوصول إلى هذا المورد", 401, details)


def current_user() -> dict[str, Any] | None:
    """The signed-in user for this request with their team's role permissions, or None when there is no valid server-side session."""
    cached = getattr(g, "current_user", None)
    if isinstance(cached, dict):
        return cached
    user_id = session.get("user_id")
    if not isinstance(user_id, int) or not _session_valid(user_id):
        return None
    row = (
        get_db()
        .execute(
            "SELECT id, email, socify_user_name(name,name_ar,name_en) AS name, name AS account_name, name_ar, name_en, role, team, workspace_id, leaderboard_opt_in, is_active FROM users WHERE id = ? AND is_active = 1",
            (user_id,),
        )
        .fetchone()
    )
    if not row:
        return None
    user = dict(row)
    policy = (
        get_db().execute("SELECT permissions FROM team_role_permissions WHERE workspace_id = ? AND role = ?", (user["workspace_id"], user["role"])).fetchone()
    )
    if policy:
        user["role_permissions"] = json.loads(policy["permissions"])
    g.current_user = user
    return user


def login_required[F: Callable[..., Any]](function: F) -> F:
    """Refuse anonymous requests: 401 for API calls, a redirect to the sign-in page for pages."""

    @functools.wraps(function)
    def wrapped(*args: object, **kwargs: object):
        if current_user() is None:
            session.clear()
            if request.path.startswith("/api/") or request.is_json:
                return authentication_required()
            target: dict[str, Any] = {"next": request.full_path}
            if getattr(g, "session_end_reason", None) == "idle":
                target["reason"] = "idle"
            return redirect(url_for("auth.login_page", **target))
        return function(*args, **kwargs)

    return cast(F, wrapped)


def has_permission(user: dict[str, Any] | None, permission: str) -> bool:
    """True when the user's effective permissions (role, narrowed by the team policy) include the permission."""
    if user is None:
        return False
    permissions = effective_permissions(user)
    return "*" in permissions or permission in permissions


def effective_permissions(user: dict[str, Any]) -> set[str]:
    permissions = ROLE_PERMISSIONS.get(str(user.get("role")), set()).copy()
    if "role_permissions" in user and user.get("role") not in {"soc_manager", "admin"}:
        permissions = permissions.intersection(user["role_permissions"])
    return permissions


def require_permission[F: Callable[..., Any]](permission: str) -> Callable[[F], F]:
    """Refuse the request with 401 when nobody is signed in and 403 when the user lacks the permission."""

    def decorator(function: F) -> F:
        @functools.wraps(function)
        def wrapped(*args: object, **kwargs: object):
            user = current_user()
            if user is None:
                session.clear()
                return authentication_required()
            if not has_permission(user, permission):
                return error_response("PERMISSION_DENIED", "ليست لديك الصلاحية اللازمة لهذا الإجراء", 403)
            return function(*args, **kwargs)

        return cast(F, wrapped)

    return decorator


def workspace_id() -> int:
    """The signed-in user's team (workspace) id; raises when nobody is signed in."""
    user = current_user()
    if user is None:
        raise PermissionError("authentication required")
    return int(user["workspace_id"])


def actor_id() -> int:
    """The signed-in user's id; raises when nobody is signed in."""
    user = current_user()
    if user is None:
        raise PermissionError("authentication required")
    return int(user["id"])


def fernet_for(configured: str | bytes) -> Fernet:
    raw = configured if isinstance(configured, bytes) else str(configured).encode()
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(raw).digest()))


def cipher() -> MultiFernet:
    """Encrypts with the current key; decrypts with it or, during a rotation, with the previous key (socify.key_rotation)."""
    configured = current_app.config.get("CREDENTIAL_KEY")
    if not configured:
        raise RuntimeError("credential encryption key is not configured")
    previous = current_app.config.get("CREDENTIAL_KEY_PREVIOUS")
    return MultiFernet([fernet_for(configured), *([fernet_for(previous)] if previous and previous != configured else [])])


def encrypt_secret(value: str) -> str:
    """Encrypt text with the current credential key."""
    return cipher().encrypt(value.encode()).decode()


def decrypt_secret(value: str) -> str:
    """Decrypt text with the current or previous credential key; a token neither key opens raises ValueError."""
    try:
        return cipher().decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("stored credential cannot be decrypted with the configured key") from exc


# Binary evidence is encrypted as it is. Rows written before this marker existed hold base64 text inside the token.
BINARY_MARKER = "b1:"


def encrypt_bytes(content: bytes) -> str:
    """Encrypt bytes with the current credential key, marked so decrypt_bytes knows the plaintext is binary."""
    return BINARY_MARKER + cipher().encrypt(content).decode()


def decrypt_bytes(value: str) -> bytes:
    if value.startswith(BINARY_MARKER):
        try:
            return cipher().decrypt(value[len(BINARY_MARKER) :].encode())
        except InvalidToken as exc:
            raise ValueError("stored content cannot be decrypted with the configured key") from exc
    return base64.b64decode(decrypt_secret(value), validate=True)


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_code(secret: str, moment: int | None = None) -> str:
    timestamp = int(time.time() if moment is None else moment)
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    counter = struct.pack(">Q", timestamp // 30)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{value:06d}"


def matching_totp_counter(secret: str, candidate: str, moment: int | None = None) -> int | None:
    """Return the 30-second counter the code belongs to, so a caller can refuse to accept it twice."""
    if not re.fullmatch(r"\d{6}", candidate):
        return None
    base = int(time.time() if moment is None else moment)
    matched = None
    for offset in (-1, 0, 1):
        if hmac.compare_digest(totp_code(secret, base + offset * 30), candidate):
            matched = (base + offset * 30) // 30
    return matched


def verify_totp(secret: str, candidate: str, moment: int | None = None) -> bool:
    return matching_totp_counter(secret, candidate, moment) is not None


def password_error(password: object) -> str | None:
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        return "يجب أن تتكون كلمة المرور من 12 إلى 128 محرفًا"
    try:
        size = len(password.encode())
    except UnicodeError:
        return "كلمة المرور تحتوي ترميزًا غير صالح"
    if size > 72:
        return "يجب ألا تتجاوز كلمة المرور 72 بايت بترميز UTF-8"
    normalized = password.casefold().strip()
    if normalized in {"password1234", "administrator", "socifypassword", "qwertyuiop12"} or len(set(normalized)) < 5:
        return "كلمة المرور شائعة أو سهلة التخمين"
    return None


def safe_external_endpoint(endpoint: str, allowed_hosts: set[str]) -> tuple[bool, str]:
    try:
        resolve_external_target(endpoint, allowed_hosts)
    except ValidationError as exc:
        return False, exc.public_message
    return True, "ok"


def parse_json_object(value: object, field: str) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"{field} must contain valid JSON") from exc
        if isinstance(parsed, dict):
            return parsed
    raise ValidationError(f"{field} must be an object")
