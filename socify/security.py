import base64
import functools
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import socket
import struct
import time
from collections.abc import Callable
from typing import Any, TypeVar, cast
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app, g, jsonify, redirect, request, session, url_for

from .db import get_db
from .timeutils import iso_now

F = TypeVar("F", bound=Callable[..., Any])

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
        "training.run",
        "hunt.execute",
        "hunt.save",
        "graph.read",
        "playbooks.request",
        "scores.read_own",
        "sources.read",
        "rules.read",
    },
    "soc_manager": {
        "events.read",
        "events.create",
        "events.delete",
        "alerts.read",
        "alerts.triage",
        "cases.read",
        "cases.create",
        "cases.update",
        "cases.close",
        "cases.override",
        "evidence.add",
        "notes.add",
        "training.run",
        "training.manage",
        "hunt.execute",
        "hunt.save",
        "hunt.share",
        "graph.read",
        "playbooks.request",
        "playbooks.approve",
        "playbooks.manage",
        "scores.read_own",
        "scores.read_team",
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
        "training.run",
        "training.manage",
        "ground_truth.read",
        "hunt.execute",
        "hunt.save",
        "hunt.share",
        "graph.read",
        "playbooks.request",
        "scores.read_own",
        "scores.read_team",
        "rules.read",
        "sources.read",
    },
    "auditor": {"events.read", "alerts.read", "cases.read", "graph.read", "audit.read", "scores.read_team", "rules.read", "sources.read"},
}

SENSITIVE_KEYS = {"password", "current_password", "new_password", "api_key", "secret", "token", "credential", "authorization", "backup_codes"}


def correlation_id() -> str:
    value = getattr(g, "correlation_id", None)
    if isinstance(value, str):
        return value
    generated = request.headers.get("X-Correlation-ID", "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", generated):
        generated = secrets.token_hex(16)
    g.correlation_id = generated
    return generated


def error_response(code: str, message: str, status: int, details: dict[str, Any] | None = None):
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


def _session_valid(user_id: int) -> bool:
    if current_app.config.get("TESTING") and not session.get("session_id"):
        return True
    raw = session.get("session_id")
    if not isinstance(raw, str):
        return False
    digest = hashlib.sha256(raw.encode()).hexdigest()
    record = (
        get_db()
        .execute(
            "SELECT id, expires_at, revoked_at FROM auth_sessions WHERE session_hash = ? AND user_id = ?",
            (digest, user_id),
        )
        .fetchone()
    )
    if not record or record["revoked_at"] or record["expires_at"] <= iso_now():
        return False
    get_db().execute("UPDATE auth_sessions SET last_seen_at = ? WHERE id = ?", (iso_now(), record["id"]))
    return True


def current_user() -> dict[str, Any] | None:
    cached = getattr(g, "current_user", None)
    if isinstance(cached, dict):
        return cached
    user_id = session.get("user_id")
    if not isinstance(user_id, int) or not _session_valid(user_id):
        return None
    row = (
        get_db()
        .execute(
            "SELECT id, email, name, role, team, workspace_id, leaderboard_opt_in, is_active FROM users WHERE id = ? AND is_active = 1",
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


def login_required(function: F) -> F:
    @functools.wraps(function)
    def wrapped(*args: object, **kwargs: object):
        if current_user() is None:
            session.clear()
            if request.path.startswith("/api/") or request.is_json:
                return error_response("AUTHENTICATION_REQUIRED", "يلزم تسجيل الدخول للوصول إلى هذا المورد", 401)
            return redirect(url_for("auth.login_page", next=request.full_path))
        return function(*args, **kwargs)

    return cast(F, wrapped)


def has_permission(user: dict[str, Any] | None, permission: str) -> bool:
    if user is None:
        return False
    permissions = ROLE_PERMISSIONS.get(str(user.get("role")), set())
    if "role_permissions" in user and user.get("role") not in {"soc_manager", "admin"}:
        permissions = permissions.intersection(user["role_permissions"])
    return "*" in permissions or permission in permissions


def require_permission(permission: str) -> Callable[[F], F]:
    def decorator(function: F) -> F:
        @functools.wraps(function)
        def wrapped(*args: object, **kwargs: object):
            user = current_user()
            if user is None:
                session.clear()
                return error_response("AUTHENTICATION_REQUIRED", "يلزم تسجيل الدخول للوصول إلى هذا المورد", 401)
            if not has_permission(user, permission):
                return error_response("PERMISSION_DENIED", "ليست لديك الصلاحية اللازمة لهذا الإجراء", 403)
            return function(*args, **kwargs)

        return cast(F, wrapped)

    return decorator


def workspace_id() -> int:
    user = current_user()
    if user is None:
        raise PermissionError("authentication required")
    return int(user["workspace_id"])


def actor_id() -> int:
    user = current_user()
    if user is None:
        raise PermissionError("authentication required")
    return int(user["id"])


def can_access_training_run(training_run_id: object) -> bool:
    if training_run_id is None:
        return True
    if type(training_run_id) is not int or training_run_id <= 0:
        return False
    user = current_user()
    if user is None:
        return False
    if has_permission(user, "training.manage") or has_permission(user, "scores.read_team"):
        return get_db().execute("SELECT 1 FROM training_runs WHERE id = ? AND workspace_id = ?", (training_run_id, workspace_id())).fetchone() is not None
    return (
        get_db()
        .execute("SELECT 1 FROM training_runs WHERE id = ? AND workspace_id = ? AND user_id = ?", (training_run_id, workspace_id(), actor_id()))
        .fetchone()
        is not None
    )


def training_scope_sql(column: str) -> tuple[str, list[object]]:
    user = current_user()
    if user is not None and (has_permission(user, "training.manage") or has_permission(user, "scores.read_team")):
        return "", []
    return f" AND ({column} IS NULL OR {column} IN (SELECT id FROM training_runs WHERE workspace_id = ? AND user_id = ?))", [workspace_id(), actor_id()]


def cipher() -> Fernet:
    configured = current_app.config.get("CREDENTIAL_KEY")
    if not configured:
        raise RuntimeError("credential encryption key is not configured")
    raw = configured if isinstance(configured, bytes) else str(configured).encode()
    key = base64.urlsafe_b64encode(hashlib.sha256(raw).digest())
    return Fernet(key)


def encrypt_secret(value: str) -> str:
    return cipher().encrypt(value.encode()).decode()


def decrypt_secret(value: str) -> str:
    try:
        return cipher().decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("stored credential cannot be decrypted with the configured key") from exc


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


def verify_totp(secret: str, candidate: str, moment: int | None = None) -> bool:
    if not re.fullmatch(r"\d{6}", candidate):
        return False
    base = int(time.time() if moment is None else moment)
    return any(hmac.compare_digest(totp_code(secret, base + offset * 30), candidate) for offset in (-1, 0, 1))


def password_error(password: object) -> str | None:
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        return "يجب أن تتكون كلمة المرور من 12 إلى 128 محرفًا"
    if len(password.encode()) > 72:
        return "يجب ألا تتجاوز كلمة المرور 72 بايت بترميز UTF-8"
    normalized = password.casefold().strip()
    if normalized in {"password1234", "administrator", "socifypassword", "qwertyuiop12"} or len(set(normalized)) < 5:
        return "كلمة المرور شائعة أو سهلة التخمين"
    return None


def safe_external_endpoint(endpoint: str, allowed_hosts: set[str]) -> tuple[bool, str]:
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"https"} or not parsed.hostname:
        return False, "يلزم عنوان HTTPS صالح"
    if parsed.username is not None or parsed.password is not None:
        return False, "بيانات الاعتماد غير مسموحة داخل عنوان المصدر"
    hostname = parsed.hostname.lower().rstrip(".")
    if hostname not in allowed_hosts:
        return False, "المضيف غير موجود في قائمة السماح"
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(hostname, parsed.port or 443, type=socket.SOCK_STREAM)}
    except OSError:
        return False, "تعذر حل اسم المضيف"
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return False, "عنوان المضيف محجوب بواسطة سياسة الشبكة"
    return True, "ok"


def parse_json_object(value: object, field: str) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{field} must contain valid JSON") from exc
        if isinstance(parsed, dict):
            return parsed
    raise ValueError(f"{field} must be an object")
