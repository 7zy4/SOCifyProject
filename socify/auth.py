import hashlib
import re
import secrets
import sqlite3
from datetime import timedelta
from typing import Any, TypeGuard

import bcrypt
from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, session, url_for
from flask_wtf.csrf import generate_csrf

from .audit import record_audit
from .db import get_db, inserted_id, transaction
from .security import (
    actor_id,
    current_user,
    decrypt_secret,
    encrypt_secret,
    error_response,
    generate_totp_secret,
    login_required,
    password_error,
    require_permission,
    verify_totp,
)
from .timeutils import iso_now, utc_now

auth_api = Blueprint("auth", __name__)


def _active_user() -> dict[str, Any]:
    user = current_user()
    if user is None:
        raise PermissionError("authentication required")
    return user


def _bounded_utf8(value: object, maximum: int) -> TypeGuard[str]:
    try:
        return isinstance(value, str) and len(value.encode()) <= maximum
    except UnicodeError:
        return False


def _password_matches(candidate: object, encoded: object) -> bool:
    if not _bounded_utf8(candidate, 72) or not candidate:
        return False
    if isinstance(encoded, str):
        try:
            matched = bcrypt.checkpw(candidate.encode(), encoded.encode())
        except (ValueError, UnicodeError):
            matched = None
        if matched is not None:
            return matched
    bcrypt.hashpw(candidate.encode(), bcrypt.gensalt(rounds=12))
    return False


def _payload() -> dict[str, Any]:
    if request.is_json:
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}
    return dict(request.form)


def _identifier_hash(email: str) -> str:
    pepper = current_app.config["SECRET_KEY"]
    raw = pepper if isinstance(pepper, bytes) else str(pepper).encode()
    return hashlib.sha256(raw + email.strip().lower().encode()).hexdigest()


def _rate_limited(email: str, ip_address: str) -> bool:
    cutoff = (utc_now() - timedelta(seconds=int(current_app.config["RATE_LIMIT_LOGIN_WINDOW_SECONDS"]))).isoformat().replace("+00:00", "Z")
    count = (
        get_db()
        .execute(
            "SELECT COUNT(*) FROM login_attempts WHERE identifier_hash = ? AND ip_address = ? AND succeeded = 0 AND occurred_at >= ?",
            (_identifier_hash(email), ip_address, cutoff),
        )
        .fetchone()[0]
    )
    return int(count) >= int(current_app.config["RATE_LIMIT_LOGIN_ATTEMPTS"])


def _record_attempt(email: str, ip_address: str, succeeded: bool) -> None:
    get_db().execute(
        "INSERT INTO login_attempts (identifier_hash, ip_address, succeeded, occurred_at) VALUES (?, ?, ?, ?)",
        (_identifier_hash(email), ip_address, 1 if succeeded else 0, iso_now()),
    )


def _backup_code_valid(user_id: int, code: str) -> bool:
    digest = hashlib.sha256(code.strip().upper().encode()).hexdigest()
    row = (
        get_db()
        .execute(
            "SELECT id, code_hash FROM mfa_backup_codes WHERE user_id = ? AND consumed_at IS NULL",
            (user_id,),
        )
        .fetchall()
    )
    for candidate in row:
        if secrets.compare_digest(candidate["code_hash"], digest):
            get_db().execute("UPDATE mfa_backup_codes SET consumed_at = ? WHERE id = ?", (iso_now(), candidate["id"]))
            return True
    return False


def _mfa_valid(user_id: int, candidate: object) -> bool:
    enrollment = get_db().execute("SELECT secret_ciphertext, enabled FROM mfa_enrollments WHERE user_id = ?", (user_id,)).fetchone()
    if not enrollment or not enrollment["enabled"]:
        return True
    if not isinstance(candidate, str) or not re.fullmatch(r"(?:[0-9]{6}|[0-9A-Fa-f]{10})", candidate.strip()):
        return False
    candidate = candidate.strip()
    try:
        secret = decrypt_secret(enrollment["secret_ciphertext"])
    except ValueError:
        return False
    return verify_totp(secret, candidate) or _backup_code_valid(user_id, candidate)


def _start_session(user: sqlite3.Row) -> dict[str, Any]:
    row = user
    raw_session_id = secrets.token_urlsafe(32)
    digest = hashlib.sha256(raw_session_id.encode()).hexdigest()
    now = utc_now()
    expiry = now + current_app.permanent_session_lifetime
    session.clear()
    session.permanent = True
    session["user_id"] = int(row["id"])
    session["workspace_id"] = int(row["workspace_id"] or 1)
    session["user_role"] = str(row["role"])
    session["session_id"] = raw_session_id
    get_db().execute(
        """INSERT INTO auth_sessions
        (session_hash, user_id, workspace_id, created_at, last_seen_at, expires_at, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            digest,
            row["id"],
            row["workspace_id"] or 1,
            now.isoformat().replace("+00:00", "Z"),
            now.isoformat().replace("+00:00", "Z"),
            expiry.isoformat().replace("+00:00", "Z"),
            request.remote_addr or "unknown",
            request.headers.get("User-Agent", "")[:500],
        ),
    )
    get_db().execute("UPDATE users SET last_login = ? WHERE id = ?", (iso_now(), row["id"]))
    record_audit(get_db(), "login", "auth", row["id"], actor=int(row["id"]), workspace=int(row["workspace_id"] or 1))
    return {"id": row["id"], "email": row["email"], "name": row["name"], "role": row["role"], "workspace_id": row["workspace_id"] or 1}


def _login_response(data: dict[str, Any]):
    email = data.get("email")
    password = data.get("password")
    ip_address = request.remote_addr or "unknown"
    if not _bounded_utf8(email, 320) or not isinstance(email, str) or not _bounded_utf8(password, 72) or not email.strip() or not password:
        return error_response("INVALID_CREDENTIALS", "بيانات الدخول غير صحيحة", 401)
    normalized_email = email.strip().lower()
    if _rate_limited(normalized_email, ip_address):
        return error_response("LOGIN_RATE_LIMITED", "تجاوزت الحد المسموح لمحاولات الدخول. حاول لاحقًا", 429)
    user = (
        get_db()
        .execute(
            "SELECT id, email, password_hash, name, role, workspace_id, is_active FROM users WHERE lower(email) = ?",
            (normalized_email,),
        )
        .fetchone()
    )
    matched = _password_matches(password, user["password_hash"] if user else None)
    valid_password = bool(user and user["is_active"] and matched)
    if not valid_password:
        _record_attempt(normalized_email, ip_address, False)
        if user:
            record_audit(
                get_db(),
                "login",
                "auth",
                user["id"],
                "denied",
                {"reason": "invalid_credentials"},
                actor=int(user["id"]),
                workspace=int(user["workspace_id"] or 1),
            )
        return error_response("INVALID_CREDENTIALS", "بيانات الدخول غير صحيحة", 401)
    if not _mfa_valid(int(user["id"]), data.get("mfa_code")):
        _record_attempt(normalized_email, ip_address, False)
        enrollment = get_db().execute("SELECT enabled FROM mfa_enrollments WHERE user_id = ?", (user["id"],)).fetchone()
        if enrollment and enrollment["enabled"] and not data.get("mfa_code"):
            return error_response("MFA_REQUIRED", "أدخل رمز المصادقة متعددة العوامل", 428)
        return error_response("INVALID_MFA_CODE", "رمز المصادقة غير صحيح", 401)
    _record_attempt(normalized_email, ip_address, True)
    return jsonify({"message": "تم تسجيل الدخول", "user": _start_session(user), "correlation_id": request.environ.get("socify.correlation_id")})


@auth_api.get("/login")
def login_page():
    if current_user():
        return redirect("/dashboard")
    return render_template("login.html", csrf_token=generate_csrf())


@auth_api.post("/login")
def login_form():
    response = _login_response(_payload())
    if request.is_json:
        return response
    if isinstance(response, tuple):
        messages = {
            "LOGIN_RATE_LIMITED": "محاولات دخول كثيرة. انتظر انتهاء مدة الحماية ثم أعد المحاولة دون تكرار الطلب.",
            "MFA_REQUIRED": "أدخل رمز المصادقة متعددة العوامل أو رمز الاسترداد الخاص بك.",
            "INVALID_MFA_CODE": "رمز المصادقة غير صحيح. تحقق من الرمز وتوقيت جهازك.",
        }
        body = response[0].get_json(silent=True) or {}
        flash(messages.get(body.get("error", {}).get("code"), "تعذر تسجيل الدخول. تحقق من البريد وكلمة المرور."), "error")
        return redirect(url_for("auth.login_page"))
    return redirect("/dashboard")


@auth_api.post("/api/auth/login")
def login_api():
    return _login_response(_payload())


@auth_api.get("/register")
def register_page():
    from .operational import operational_mode

    if not current_app.config["ALLOW_REGISTRATION"] and not operational_mode():
        return error_response("REGISTRATION_DISABLED", "إنشاء الحسابات العامة غير متاح", 403)
    return render_template("register.html", csrf_token=generate_csrf())


def _register(data: dict[str, Any]):
    from .operational import operational_mode

    if operational_mode() or not current_app.config["ALLOW_REGISTRATION"]:
        token = data.get("invitation_token")
        if not isinstance(token, str) or not 32 <= len(token) <= 200 or not token.strip():
            return error_response("REGISTRATION_DISABLED", "إنشاء الحسابات يتطلب دعوة صالحة من مدير الفريق", 403)
    if operational_mode() and set(data) - {"email", "name", "password", "invitation_token", "csrf_token"}:
        return error_response("INVALID_REGISTRATION", "أرسل حقول الدعوة والحساب المعروفة فقط", 422)
    email = data.get("email")
    name = data.get("name")
    password = data.get("password")
    if not isinstance(email, str) or not isinstance(name, str) or not re_email(email) or not 2 <= len(name.strip()) <= 120:
        return error_response("INVALID_REGISTRATION", "تحقق من الاسم والبريد الإلكتروني", 422)
    problem = password_error(password)
    if problem:
        return error_response("WEAK_PASSWORD", problem, 422)
    team_name = data.get("team_name")
    invitation = data.get("invitation_token")
    if team_name is not None and not isinstance(team_name, str) or team_name and not 2 <= len(team_name.strip()) <= 120:
        return error_response("INVALID_TEAM", "اسم الفريق غير صالح", 422)
    if invitation is not None and not isinstance(invitation, str) or invitation and (len(invitation) > 200 or team_name):
        return error_response("INVALID_INVITATION", "بيانات الدعوة غير صالحة", 422)
    password_hash = bcrypt.hashpw(str(password).encode(), bcrypt.gensalt(rounds=12)).decode()
    try:
        with transaction():
            if get_db().execute("SELECT 1 FROM users WHERE lower(email)=?", (email.strip().lower(),)).fetchone():
                return error_response("ACCOUNT_EXISTS", "تعذر إنشاء الحساب بهذه البيانات", 409)
            target_workspace, target_role, target_team = 1, "analyst", str(data.get("team") or "المتدربون")[:120]
            invite_row = None
            if team_name:
                created = get_db().execute(
                    "INSERT INTO training_workspaces (public_id, name, created_at) VALUES (?, ?, ?)",
                    ("team-" + secrets.token_hex(16), team_name.strip(), iso_now()),
                )
                target_workspace, target_role, target_team = inserted_id(created), "soc_manager", team_name.strip()
            elif invitation:
                invite_row = (
                    get_db()
                    .execute(
                        "SELECT i.*, w.name AS team_name FROM team_invitations i JOIN training_workspaces w ON w.id = i.workspace_id WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ? AND w.is_active = 1",
                        (hashlib.sha256(invitation.encode()).hexdigest(), iso_now()),
                    )
                    .fetchone()
                )
                if not invite_row or invite_row["email"] != email.strip().lower():
                    return error_response("INVALID_INVITATION", "الدعوة غير صالحة أو منتهية أو لبريد آخر", 422)
                target_workspace, target_role, target_team = invite_row["workspace_id"], invite_row["role"], invite_row["team_name"]
            cursor = get_db().execute(
                """INSERT INTO users
                (email, password_hash, name, role, team, workspace_id, created_at, password_changed_at, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                (email.strip().lower(), password_hash, name.strip(), target_role, target_team, target_workspace, iso_now(), iso_now()),
            )
            user_id = inserted_id(cursor)
            get_db().execute(
                "INSERT INTO workspace_memberships (workspace_id, user_id, role, created_at) VALUES (?, ?, ?, ?)",
                (target_workspace, user_id, target_role, iso_now()),
            )
            if invite_row:
                get_db().execute("UPDATE team_invitations SET consumed_at = ? WHERE id = ?", (iso_now(), invite_row["id"]))
            record_audit(get_db(), "register", "user", user_id, actor=user_id, workspace=target_workspace)
    except Exception as exc:
        if "UNIQUE" in str(exc).upper():
            return error_response("ACCOUNT_EXISTS", "تعذر إنشاء الحساب بهذه البيانات", 409)
        raise
    return jsonify({"message": "تم إنشاء الحساب"}), 201


def re_email(value: str) -> bool:
    if len(value) > 254 or value.count("@") != 1:
        return False
    local, domain = value.rsplit("@", 1)
    return bool(local and "." in domain and not any(char.isspace() for char in value))


@auth_api.post("/register")
def register_form():
    response = _register(_payload())
    if request.is_json:
        return response
    if isinstance(response, tuple) and response[1] >= 400:
        flash("تعذر إنشاء الحساب. تحقق من البيانات", "error")
        return redirect(url_for("auth.register_page"))
    flash("تم إنشاء الحساب. يمكنك تسجيل الدخول الآن", "success")
    return redirect(url_for("auth.login_page"))


@auth_api.post("/api/auth/register")
def register_api():
    return _register(_payload())


def _revoke_current_session() -> None:
    raw = session.get("session_id")
    user_id = session.get("user_id")
    workspace = session.get("workspace_id")
    if isinstance(raw, str):
        digest = hashlib.sha256(raw.encode()).hexdigest()
        get_db().execute("UPDATE auth_sessions SET revoked_at = ? WHERE session_hash = ?", (iso_now(), digest))
    if isinstance(user_id, int):
        record_audit(get_db(), "logout", "auth", user_id, actor=user_id, workspace=int(workspace or 1))
    session.clear()


@auth_api.post("/logout")
def logout_page():
    _revoke_current_session()
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({"message": "تم تسجيل الخروج"})
    return redirect(url_for("ui.index"))


@auth_api.post("/api/auth/logout")
def logout_api():
    _revoke_current_session()
    return jsonify({"message": "تم تسجيل الخروج"})


@auth_api.get("/api/auth/csrf")
def csrf_token_api():
    return jsonify({"csrf_token": generate_csrf()})


@auth_api.get("/api/auth/me")
@login_required
def me():
    from .security import effective_permissions

    user = _active_user()
    permissions = effective_permissions(user)
    return jsonify({"user": user, "permissions": sorted(permissions)})


def current_permissions(role: str) -> set[str]:
    from .security import ROLE_PERMISSIONS

    return ROLE_PERMISSIONS.get(role, set())


@auth_api.get("/api/auth/sessions")
@login_required
def sessions_list():
    raw = session.get("session_id")
    digest = hashlib.sha256(raw.encode()).hexdigest() if isinstance(raw, str) else ""
    rows = (
        get_db()
        .execute(
            """SELECT id, session_hash, created_at, last_seen_at, expires_at, revoked_at, ip_address, user_agent
        FROM auth_sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 50""",
            (actor_id(),),
        )
        .fetchall()
    )
    return jsonify(
        {
            "items": [
                {**{key: value for key, value in dict(row).items() if key != "session_hash"}, "is_current": secrets.compare_digest(row["session_hash"], digest)}
                for row in rows
            ]
        }
    )


@auth_api.delete("/api/auth/sessions/<int:session_id>")
@login_required
def revoke_session(session_id: int):
    row = get_db().execute("SELECT id FROM auth_sessions WHERE id = ? AND user_id = ?", (session_id, actor_id())).fetchone()
    if not row:
        return error_response("SESSION_NOT_FOUND", "الجلسة غير موجودة", 404)
    get_db().execute("UPDATE auth_sessions SET revoked_at = ? WHERE id = ?", (iso_now(), session_id))
    record_audit(get_db(), "revoke", "auth_session", session_id)
    return "", 204


@auth_api.post("/api/profile/password")
@login_required
def change_password():
    data = _payload()
    current = data.get("current_password")
    new = data.get("new_password")
    problem = password_error(new)
    if not _bounded_utf8(current, 72) or problem:
        return error_response("INVALID_PASSWORD_CHANGE", problem or "كلمة المرور الحالية مطلوبة", 422)
    user = get_db().execute("SELECT password_hash FROM users WHERE id = ? AND is_active = 1", (actor_id(),)).fetchone()
    if not _password_matches(current, user["password_hash"] if user else None):
        record_audit(get_db(), "password_change", "user", actor_id(), "denied", {"reason": "current_password_mismatch"})
        return error_response("CURRENT_PASSWORD_INCORRECT", "كلمة المرور الحالية غير صحيحة", 403)
    replacement = bcrypt.hashpw(str(new).encode(), bcrypt.gensalt(rounds=12)).decode()
    with transaction():
        get_db().execute("UPDATE users SET password_hash = ?, password_changed_at = ? WHERE id = ?", (replacement, iso_now(), actor_id()))
        raw = session.get("session_id")
        current_hash = hashlib.sha256(raw.encode()).hexdigest() if isinstance(raw, str) else ""
        get_db().execute(
            "UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND session_hash != ? AND revoked_at IS NULL", (iso_now(), actor_id(), current_hash)
        )
        record_audit(get_db(), "password_change", "user", actor_id())
    return jsonify({"message": "تم تغيير كلمة المرور وإلغاء الجلسات الأخرى"})


@auth_api.post("/api/auth/mfa/enroll")
@login_required
def mfa_enroll():
    from .operational import operational_mode

    if operational_mode():
        supplied = _payload().get("current_password")
        user = get_db().execute("SELECT password_hash FROM users WHERE id = ?", (actor_id(),)).fetchone()
        if not _password_matches(supplied, user["password_hash"] if user else None):
            return error_response("REAUTHENTICATION_FAILED", "أدخل كلمة المرور الحالية لبدء إعداد المصادقة", 403)
    enrollment = get_db().execute("SELECT enabled FROM mfa_enrollments WHERE user_id = ?", (actor_id(),)).fetchone()
    if enrollment and enrollment["enabled"]:
        return error_response("MFA_ALREADY_ENABLED", "ألغِ التفعيل الحالي بعد التحقق قبل إعادة التسجيل", 409)
    secret = generate_totp_secret()
    encrypted = encrypt_secret(secret)
    updated = get_db().execute(
        """INSERT INTO mfa_enrollments (user_id, secret_ciphertext, enabled, updated_at)
        VALUES (?, ?, 0, ?) ON CONFLICT(user_id) DO UPDATE SET secret_ciphertext = excluded.secret_ciphertext,
        enabled = 0, verified_at = NULL, updated_at = excluded.updated_at WHERE mfa_enrollments.enabled = 0""",
        (actor_id(), encrypted, iso_now()),
    )
    if updated.rowcount != 1:
        return error_response("MFA_ALREADY_ENABLED", "ألغِ التفعيل الحالي بعد التحقق قبل إعادة التسجيل", 409)
    user = _active_user()
    uri = f"otpauth://totp/SOCify:{user['email']}?secret={secret}&issuer=SOCify&algorithm=SHA1&digits=6&period=30"
    record_audit(get_db(), "enroll_started", "mfa", actor_id())
    return jsonify({"secret": secret, "otpauth_uri": uri})


@auth_api.get("/api/auth/mfa/status")
@login_required
def mfa_status():
    row = get_db().execute("SELECT enabled, verified_at FROM mfa_enrollments WHERE user_id = ?", (actor_id(),)).fetchone()
    remaining = get_db().execute("SELECT COUNT(*) FROM mfa_backup_codes WHERE user_id = ? AND consumed_at IS NULL", (actor_id(),)).fetchone()[0]
    return jsonify(
        {
            "enabled": bool(row and row["enabled"]),
            "pending": bool(row and not row["enabled"]),
            "verified_at": row["verified_at"] if row else None,
            "recovery_codes_remaining": remaining,
        }
    )


@auth_api.post("/api/auth/mfa/verify")
@login_required
def mfa_verify():
    identity, address = f"mfa-verification:{actor_id()}", request.remote_addr or "unknown"
    if _rate_limited(identity, address):
        return error_response("RATE_LIMITED", "محاولات تحقق كثيرة؛ انتظر ثم أعد المحاولة", 429)
    code = _payload().get("code")
    enrollment = get_db().execute("SELECT secret_ciphertext FROM mfa_enrollments WHERE user_id = ?", (actor_id(),)).fetchone()
    if not enrollment or not isinstance(code, str):
        return error_response("MFA_ENROLLMENT_NOT_FOUND", "ابدأ إعداد المصادقة أولًا", 404)
    try:
        secret = decrypt_secret(enrollment["secret_ciphertext"])
    except ValueError:
        return error_response("MFA_KEY_MISMATCH", "تعذر فك إعداد المصادقة. أعد التسجيل", 409)
    if not verify_totp(secret, code):
        _record_attempt(identity, address, False)
        record_audit(get_db(), "verify", "mfa", actor_id(), "denied")
        return error_response("INVALID_MFA_CODE", "رمز المصادقة غير صحيح", 422)
    codes = [secrets.token_hex(5).upper() for _ in range(10)]
    _record_attempt(identity, address, True)
    with transaction():
        get_db().execute("UPDATE mfa_enrollments SET enabled = 1, verified_at = ?, updated_at = ? WHERE user_id = ?", (iso_now(), iso_now(), actor_id()))
        get_db().execute("DELETE FROM mfa_backup_codes WHERE user_id = ?", (actor_id(),))
        get_db().executemany(
            "INSERT INTO mfa_backup_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)",
            [(actor_id(), hashlib.sha256(item.encode()).hexdigest(), iso_now()) for item in codes],
        )
        record_audit(get_db(), "enabled", "mfa", actor_id())
    return jsonify({"message": "تم تفعيل المصادقة متعددة العوامل", "backup_codes": codes})


@auth_api.delete("/api/auth/mfa")
@login_required
def mfa_disable():
    data = _payload()
    password = data.get("current_password")
    code = data.get("code")
    user = get_db().execute("SELECT password_hash FROM users WHERE id = ?", (actor_id(),)).fetchone()
    if not _password_matches(password, user["password_hash"] if user else None) or not _mfa_valid(actor_id(), code):
        return error_response("REAUTHENTICATION_FAILED", "يلزم التحقق من كلمة المرور ورمز المصادقة", 403)
    with transaction():
        get_db().execute("DELETE FROM mfa_backup_codes WHERE user_id = ?", (actor_id(),))
        get_db().execute("DELETE FROM mfa_enrollments WHERE user_id = ?", (actor_id(),))
        record_audit(get_db(), "disabled", "mfa", actor_id())
    return "", 204


@auth_api.get("/api/admin/users")
@require_permission("users.read")
def users_list():
    workspace = int(_active_user()["workspace_id"])
    rows = (
        get_db()
        .execute(
            "SELECT id, email, name, role, team, is_active, created_at, last_login FROM users WHERE workspace_id = ? ORDER BY name",
            (workspace,),
        )
        .fetchall()
    )
    return jsonify({"items": [dict(row) for row in rows]})


@auth_api.patch("/api/admin/users/<int:user_id>")
@require_permission("users.manage")
def update_user(user_id: int):
    row = get_db().execute("SELECT id, role, is_active FROM users WHERE id = ? AND workspace_id = ?", (user_id, int(_active_user()["workspace_id"]))).fetchone()
    if not row:
        return error_response("USER_NOT_FOUND", "المستخدم غير موجود", 404)
    data = _payload()
    updates: dict[str, Any] = {}
    if "role" in data:
        if data["role"] not in {"analyst", "soc_manager", "admin", "instructor", "auditor"}:
            return error_response("INVALID_ROLE", "الدور غير صالح", 422)
        updates["role"] = data["role"]
    if "is_active" in data:
        if not isinstance(data["is_active"], bool):
            return error_response("INVALID_USER_STATE", "is_active يجب أن تكون قيمة منطقية", 422)
        if user_id == actor_id() and not data["is_active"]:
            return error_response("SELF_DISABLE_DENIED", "لا يمكن تعطيل حساب الجلسة الحالية", 409)
        updates["is_active"] = 1 if data["is_active"] else 0
    if not updates:
        return error_response("NO_CHANGES", "لم تُرسل حقول قابلة للتعديل", 422)
    assignments = ", ".join(f"{field} = ?" for field in updates)
    with transaction():
        get_db().execute(f"UPDATE users SET {assignments} WHERE id = ?", (*updates.values(), user_id))
        if "role" in updates:
            get_db().execute(
                "UPDATE workspace_memberships SET role = ? WHERE workspace_id = ? AND user_id = ?",
                (updates["role"], int(_active_user()["workspace_id"]), user_id),
            )
        if updates.get("is_active") == 0:
            get_db().execute("UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", (iso_now(), user_id))
        record_audit(get_db(), "update", "user", user_id, details={"fields": list(updates)})
    updated = get_db().execute("SELECT id, email, name, role, team, is_active FROM users WHERE id = ?", (user_id,)).fetchone()
    return jsonify(dict(updated))


@auth_api.delete("/api/admin/users/<int:user_id>/mfa")
@require_permission("users.manage")
def admin_reset_mfa(user_id: int):
    data = _payload()
    reason = data.get("reason")
    if not isinstance(reason, str) or len(reason.strip()) < 10:
        return error_response("RESET_REASON_REQUIRED", "يلزم سبب واضح لإعادة ضبط MFA", 422)
    user = get_db().execute("SELECT id FROM users WHERE id = ? AND workspace_id = ?", (user_id, int(_active_user()["workspace_id"]))).fetchone()
    if not user:
        return error_response("USER_NOT_FOUND", "المستخدم غير موجود", 404)
    with transaction():
        get_db().execute("DELETE FROM mfa_backup_codes WHERE user_id = ?", (user_id,))
        get_db().execute("DELETE FROM mfa_enrollments WHERE user_id = ?", (user_id,))
        get_db().execute("UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", (iso_now(), user_id))
        record_audit(get_db(), "admin_reset", "mfa", user_id, details={"reason": reason.strip()})
    return "", 204
