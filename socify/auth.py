import hashlib
import math
import re
import secrets
import sqlite3
import unicodedata
from datetime import timedelta
from typing import Any, TypeGuard
from urllib.parse import unquote

import bcrypt
from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, session, url_for
from flask_wtf.csrf import generate_csrf

from .audit import record_audit
from .db import get_db, inserted_id, transaction
from .maintenance import prune_if_due
from .recovery_codes import hash_recovery_code, verify_recovery_code
from .security import (
    ROLE_PERMISSIONS,
    actor_id,
    current_user,
    decrypt_secret,
    encrypt_secret,
    error_response,
    generate_totp_secret,
    login_required,
    matching_totp_counter,
    password_error,
    require_permission,
    verify_totp,
)
from .timeutils import iso_now, parse_timestamp, utc_now

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


def _window_start() -> str:
    return (utc_now() - timedelta(seconds=int(current_app.config["RATE_LIMIT_LOGIN_WINDOW_SECONDS"]))).isoformat().replace("+00:00", "Z")


def _failures(identity: str, ip_address: str) -> int:
    """Failures for this identity from this address inside the window and after its most recent success there.

    A success closes the count, so a user who signs in correctly many times is never locked out by earlier mistakes.
    Row ids order the attempts, so a failure recorded in the same second as a later success is not counted.
    """
    digest = _identifier_hash(identity)
    return int(
        get_db()
        .execute(
            """SELECT COUNT(*) FROM login_attempts WHERE identifier_hash = ? AND ip_address = ? AND succeeded = 0 AND occurred_at >= ?
            AND id > COALESCE((SELECT MAX(id) FROM login_attempts WHERE identifier_hash = ? AND ip_address = ? AND succeeded = 1), 0)""",
            (digest, ip_address, _window_start(), digest, ip_address),
        )
        .fetchone()[0]
    )


def _account_failures(identity: str) -> int:
    """Failures for this identity from every address inside the window and after its most recent success from any address."""
    digest = _identifier_hash(identity)
    return int(
        get_db()
        .execute(
            """SELECT COUNT(*) FROM login_attempts WHERE identifier_hash = ? AND succeeded = 0 AND occurred_at >= ?
            AND id > COALESCE((SELECT MAX(id) FROM login_attempts WHERE identifier_hash = ? AND succeeded = 1), 0)""",
            (digest, _window_start(), digest),
        )
        .fetchone()[0]
    )


def _rate_limited(email: str, ip_address: str) -> bool:
    return _failures(email, ip_address) >= int(current_app.config["RATE_LIMIT_LOGIN_ATTEMPTS"])


def _address_rate_limited(ip_address: str) -> bool:
    """Bound failures from one address across every account, so rotating usernames does not reset the limit."""
    limit = int(current_app.config.get("RATE_LIMIT_LOGIN_IP_ATTEMPTS") or 0)
    if limit <= 0:
        return False
    count = (
        get_db()
        .execute("SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? AND succeeded = 0 AND occurred_at >= ?", (ip_address, _window_start()))
        .fetchone()[0]
    )
    return int(count) >= limit


def _account_throttle_delay(failures: int) -> int:
    """Seconds an account waits after its latest failure: 30, then doubling with each further failure, never past the window."""
    limit = int(current_app.config.get("RATE_LIMIT_LOGIN_ACCOUNT_ATTEMPTS") or 0)
    window = int(current_app.config["RATE_LIMIT_LOGIN_WINDOW_SECONDS"])
    return min(30 * 2 ** min(max(failures - limit, 0), 16), window)


def _account_throttle_seconds(identity: str, ip_address: str) -> int:
    """How long this account must wait before another password check from this address; 0 when it may go ahead.

    Failures are counted across every address since the account's last success. An address the account has signed in
    from before is not throttled, so guessing from elsewhere slows the guesser without locking the owner out.
    Unknown and existing accounts are treated alike, so the answer reveals nothing about which accounts exist.
    """
    limit = int(current_app.config.get("RATE_LIMIT_LOGIN_ACCOUNT_ATTEMPTS") or 0)
    if limit <= 0:
        return 0
    failures = _account_failures(identity)
    if failures < limit:
        return 0
    digest = _identifier_hash(identity)
    if get_db().execute("SELECT 1 FROM login_attempts WHERE identifier_hash = ? AND ip_address = ? AND succeeded = 1 LIMIT 1", (digest, ip_address)).fetchone():
        return 0
    latest = get_db().execute("SELECT MAX(occurred_at) FROM login_attempts WHERE identifier_hash = ? AND succeeded = 0", (digest,)).fetchone()[0]
    remaining = (parse_timestamp(latest) + timedelta(seconds=_account_throttle_delay(failures)) - utc_now()).total_seconds()
    return max(0, math.ceil(remaining))


def _note_account_failure(identity: str, user: sqlite3.Row | None) -> None:
    """Once failures reach the account limit, each further one is audited for the team's managers to see."""
    limit = int(current_app.config.get("RATE_LIMIT_LOGIN_ACCOUNT_ATTEMPTS") or 0)
    if user is None or limit <= 0:
        return
    failures = _account_failures(identity)
    if failures >= limit:
        record_audit(
            get_db(),
            "login_throttled",
            "user",
            user["id"],
            "denied",
            {"failures": failures, "retry_after": _account_throttle_delay(failures)},
            workspace=int(user["workspace_id"] or 1),
        )


def _failures_since_last_success(identity: str) -> int:
    digest = _identifier_hash(identity)
    return int(
        get_db()
        .execute(
            "SELECT COUNT(*) FROM login_attempts WHERE identifier_hash = ? AND succeeded = 0 AND id > COALESCE((SELECT MAX(id) FROM login_attempts WHERE identifier_hash = ? AND succeeded = 1), 0)",
            (digest, digest),
        )
        .fetchone()[0]
    )


def attempts_exhausted(identity: str, limit_key: str) -> bool:
    """Failure-only limiter for unauthenticated endpoints; successful requests are never counted."""
    limit = int(current_app.config.get(limit_key) or 0)
    return limit > 0 and _failures(identity, request.remote_addr or "unknown") >= limit


def record_failed_attempt(identity: str) -> None:
    _record_attempt(identity, request.remote_addr or "unknown", False)


def _record_attempt(email: str, ip_address: str, succeeded: bool) -> None:
    get_db().execute(
        "INSERT INTO login_attempts (identifier_hash, ip_address, succeeded, occurred_at) VALUES (?, ?, ?, ?)",
        (_identifier_hash(email), ip_address, 1 if succeeded else 0, iso_now()),
    )


def _reauthentication_identity(user_id: int) -> str:
    return f"reauth:{user_id}"


def _reauthentication_blocked(user_id: int) -> bool:
    """True once the account has used up its password re-checks; counted across addresses, since a stolen session may move."""
    limit = int(current_app.config.get("RATE_LIMIT_REAUTH_ATTEMPTS") or 0)
    return limit > 0 and _account_failures(_reauthentication_identity(user_id)) >= limit


def _record_reauthentication(user_id: int, succeeded: bool) -> None:
    _record_attempt(_reauthentication_identity(user_id), request.remote_addr or "unknown", succeeded)


def _end_current_session(reason: str) -> None:
    raw = session.get("session_id")
    if isinstance(raw, str):
        digest = hashlib.sha256(raw.encode()).hexdigest()
        get_db().execute(
            "UPDATE auth_sessions SET revoked_at = ?, revoked_reason = ? WHERE session_hash = ? AND revoked_at IS NULL", (iso_now(), reason, digest)
        )
    session.clear()


def _reauthentication_limited(user_id: int):
    """Refuse further guesses; by default the session that kept guessing is ended, so a stolen session cannot go on."""
    end_session = bool(current_app.config.get("REAUTH_REVOKE_SESSION", True))
    record_audit(get_db(), "reauthentication_limited", "auth", user_id, "denied", {"path": request.path, "session_ended": end_session}, actor=user_id)
    if end_session:
        _end_current_session("reauthentication_limit")
    return error_response(
        "REAUTH_RATE_LIMITED", "محاولات تحقق خاطئة كثيرة من هذا الحساب. سجّل الدخول من جديد أو حاول لاحقًا", 429, {"session_ended": end_session}
    )


def _reauthentication_failed(user_id: int, code: str, message: str, status: int):
    _record_reauthentication(user_id, False)
    if _reauthentication_blocked(user_id):
        return _reauthentication_limited(user_id)
    return error_response(code, message, status)


def _backup_code_valid(user_id: int, code: str) -> bool:
    row = (
        get_db()
        .execute(
            "SELECT id, code_hash FROM mfa_backup_codes WHERE user_id = ? AND consumed_at IS NULL",
            (user_id,),
        )
        .fetchall()
    )
    for candidate in row:
        if verify_recovery_code(code, candidate["code_hash"]):
            consumed = get_db().execute("UPDATE mfa_backup_codes SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL", (iso_now(), candidate["id"]))
            return consumed.rowcount == 1
    return False


def _mfa_valid(user_id: int, candidate: object, consume: bool = False) -> bool:
    enrollment = get_db().execute("SELECT secret_ciphertext, enabled FROM mfa_enrollments WHERE user_id = ?", (user_id,)).fetchone()
    if not enrollment or not enrollment["enabled"]:
        return True
    if not isinstance(candidate, str) or not re.fullmatch(r"(?:[0-9]{6}|[0-9A-Fa-f]{10}|[0-9A-Fa-f]{32})", candidate.strip()):
        return False
    candidate = candidate.strip()
    try:
        secret = decrypt_secret(enrollment["secret_ciphertext"])
    except ValueError:
        return False
    if len(candidate) != 6:
        return _backup_code_valid(user_id, candidate)
    counter = matching_totp_counter(secret, candidate)
    if counter is None:
        return False
    if not consume:
        return True
    # A code that already opened a session cannot open another one inside its validity window.
    accepted = get_db().execute(
        "UPDATE mfa_enrollments SET last_totp_counter = ? WHERE user_id = ? AND (last_totp_counter IS NULL OR last_totp_counter < ?)",
        (counter, user_id, counter),
    )
    return accepted.rowcount == 1


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
    prune_if_due(get_db())
    return {"id": row["id"], "email": row["email"], "name": row["name"], "role": row["role"], "workspace_id": row["workspace_id"] or 1}


def _login_response(data: dict[str, Any]):
    email = data.get("email")
    password = data.get("password")
    ip_address = request.remote_addr or "unknown"
    if not _bounded_utf8(email, 320) or not isinstance(email, str) or not _bounded_utf8(password, 72) or not email.strip() or not password:
        return error_response("INVALID_CREDENTIALS", "بيانات الدخول غير صحيحة", 401)
    normalized_email = email.strip().lower()
    if _rate_limited(normalized_email, ip_address) or _address_rate_limited(ip_address):
        return error_response("LOGIN_RATE_LIMITED", "تجاوزت الحد المسموح لمحاولات الدخول. حاول لاحقًا", 429)
    wait = _account_throttle_seconds(normalized_email, ip_address)
    if wait:
        body, status = error_response("LOGIN_RATE_LIMITED", "محاولات دخول خاطئة كثيرة لهذا الحساب. أعد المحاولة بعد قليل", 429, {"retry_after": wait})
        body.headers["Retry-After"] = str(wait)
        return body, status
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
        _note_account_failure(normalized_email, user)
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
    enrollment = get_db().execute("SELECT enabled FROM mfa_enrollments WHERE user_id = ?", (user["id"],)).fetchone()
    if enrollment and enrollment["enabled"] and not data.get("mfa_code"):
        # The first step of a two-step sign-in: the password was right and no code was sent yet. This is not a failure.
        return error_response("MFA_REQUIRED", "أدخل رمز المصادقة متعددة العوامل", 428)
    if not _mfa_valid(int(user["id"]), data.get("mfa_code"), consume=True):
        _record_attempt(normalized_email, ip_address, False)
        _note_account_failure(normalized_email, user)
        return error_response("INVALID_MFA_CODE", "رمز المصادقة غير صحيح", 401)
    missed = _failures_since_last_success(normalized_email)
    _record_attempt(normalized_email, ip_address, True)
    signed_in = _start_session(user)
    limit = int(current_app.config.get("RATE_LIMIT_LOGIN_ACCOUNT_ATTEMPTS") or 0)
    if limit > 0 and missed >= limit:
        # Shown once to the owner after sign-in: someone failed to sign in to this account many times.
        session["security_notice"] = {"failed_sign_ins": missed}
    return jsonify({"message": "تم تسجيل الدخول", "user": signed_in, "correlation_id": request.environ.get("socify.correlation_id")})


def safe_next_path(value: object) -> str:
    """A same-site page to return to after sign-in; anything else, including other sites and API paths, falls back to the case list."""
    # Only URL characters: browsers drop tabs and newlines, so "/<TAB>/evil.example" would turn into "//evil.example".
    if not isinstance(value, str) or len(value) > 2048 or not re.fullmatch(r"/(?![/\\])[A-Za-z0-9\-._~!$&'()*+,;=:@%/?]*", value):
        return "/cases"
    if unquote(value).startswith(("//", "/\\")):
        return "/cases"
    path = value.rstrip("?")
    if path.split("?", 1)[0] in {"/login", "/logout", "/register"} or path.startswith("/api/"):
        return "/cases"
    return path


@auth_api.get("/login")
def login_page():
    next_path = safe_next_path(request.args.get("next"))
    if current_user():
        return redirect(next_path)
    return render_template("login.html", csrf_token=generate_csrf(), next_path=next_path, session_ended_idle=request.args.get("reason") == "idle")


@auth_api.post("/login")
def login_form():
    data = _payload()
    response = _login_response(data)
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
        next_path = safe_next_path(data.get("next"))
        follow: dict[str, Any] = {"next": next_path} if next_path != "/cases" else {}
        if body.get("error", {}).get("code") in {"MFA_REQUIRED", "INVALID_MFA_CODE"}:
            return redirect(url_for("auth.login_page", mfa=1, **follow))
        return redirect(url_for("auth.login_page", **follow))
    return redirect(safe_next_path(data.get("next")))


@auth_api.post("/api/auth/login")
def login_api():
    return _login_response(_payload())


@auth_api.get("/register")
def register_page():
    return render_template("register.html", csrf_token=generate_csrf())


def _register(data: dict[str, Any]):
    if attempts_exhausted("registration", "RATE_LIMIT_REGISTER_ATTEMPTS"):
        return error_response("REGISTRATION_RATE_LIMITED", "محاولات تسجيل مرفوضة كثيرة من هذا العنوان. حاول لاحقًا", 429)
    response = _register_account(data)
    # Only rejected invitations and existing accounts count; ordinary validation mistakes never lock a real user out.
    if response[1] in {403, 409} or (response[1] == 422 and response[0].get_json()["error"]["code"] == "INVALID_INVITATION"):
        record_failed_attempt("registration")
    return response


def _register_account(data: dict[str, Any]):
    token = data.get("invitation_token")
    if not isinstance(token, str) or not 32 <= len(token) <= 200 or not token.strip():
        return error_response("REGISTRATION_DISABLED", "إنشاء الحسابات يتطلب دعوة صالحة من مدير الفريق", 403)
    if set(data) - {"email", "name", "password", "invitation_token", "csrf_token"}:
        return error_response("INVALID_REGISTRATION", "أرسل حقول الدعوة والحساب المعروفة فقط", 422)
    email = data.get("email")
    name = data.get("name")
    password = data.get("password")
    if not isinstance(email, str) or not isinstance(name, str) or not re_email(email) or not 2 <= len(name.strip()) <= 120:
        return error_response("INVALID_REGISTRATION", "تحقق من الاسم والبريد الإلكتروني", 422)
    problem = password_error(password)
    if problem:
        return error_response("WEAK_PASSWORD", problem, 422)
    password_hash = bcrypt.hashpw(str(password).encode(), bcrypt.gensalt(rounds=12)).decode()
    try:
        with transaction():
            if get_db().execute("SELECT 1 FROM users WHERE lower(email)=?", (email.strip().lower(),)).fetchone():
                return error_response("ACCOUNT_EXISTS", "تعذر إنشاء الحساب بهذه البيانات", 409)
            # The invitation alone decides the team and the role; a new team is created with scripts/bootstrap_team.py.
            invite_row = (
                get_db()
                .execute(
                    "SELECT i.*, w.name AS team_name FROM team_invitations i JOIN workspaces w ON w.id = i.workspace_id WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ? AND w.is_active = 1",
                    (hashlib.sha256(token.encode()).hexdigest(), iso_now()),
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
    data = _payload()
    response = _register(data)
    if request.is_json:
        return response
    if isinstance(response, tuple) and response[1] >= 400:
        fields = {
            key: value
            for key, limit in {"name": 120, "email": 254, "team_name": 120, "invitation_token": 200}.items()
            if isinstance(value := data.get(key), str) and len(value) <= limit
        }
        return render_template("register.html", csrf_token=generate_csrf(), form_values=fields, registration_error=response[0].get_json()["error"]), response[1]
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
    body: dict[str, Any] = {"user": user, "permissions": sorted(permissions), "csrf_token": generate_csrf()}
    notice = session.pop("security_notice", None)
    if isinstance(notice, dict):
        body["security_notice"] = notice
    return jsonify(body)


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


@auth_api.put("/api/profile/display-name")
@login_required
def update_display_name():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) != {"name_ar", "name_en"}:
        return error_response("INVALID_DISPLAY_NAME", "أدخل اسم العرض بالعربية والإنجليزية", 422)
    values = {}
    for key in ("name_ar", "name_en"):
        value = data[key]
        if not isinstance(value, str) or len(value) > 100 or any(unicodedata.category(char).startswith("C") for char in value):
            return error_response("INVALID_DISPLAY_NAME", "اسم العرض يجب ألا يتجاوز 100 محرف دون محارف تحكم", 422)
        values[key] = value.strip()
    with transaction():
        get_db().execute(
            "UPDATE users SET name_ar=?, name_en=? WHERE id=? AND workspace_id=?",
            (values["name_ar"], values["name_en"], actor_id(), int(_active_user()["workspace_id"])),
        )
        record_audit(get_db(), "update", "display_name", actor_id(), details=values)
    return jsonify(values)


@auth_api.post("/api/profile/password")
@login_required
def change_password():
    data = _payload()
    current = data.get("current_password")
    new = data.get("new_password")
    problem = password_error(new)
    if not _bounded_utf8(current, 72) or problem:
        return error_response("INVALID_PASSWORD_CHANGE", problem or "كلمة المرور الحالية مطلوبة", 422)
    if _reauthentication_blocked(actor_id()):
        return _reauthentication_limited(actor_id())
    user = get_db().execute("SELECT password_hash FROM users WHERE id = ? AND is_active = 1", (actor_id(),)).fetchone()
    if not _password_matches(current, user["password_hash"] if user else None):
        record_audit(get_db(), "password_change", "user", actor_id(), "denied", {"reason": "current_password_mismatch"})
        return _reauthentication_failed(actor_id(), "CURRENT_PASSWORD_INCORRECT", "كلمة المرور الحالية غير صحيحة", 403)
    _record_reauthentication(actor_id(), True)
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
    if _reauthentication_blocked(actor_id()):
        return _reauthentication_limited(actor_id())
    supplied = _payload().get("current_password")
    user = get_db().execute("SELECT password_hash FROM users WHERE id = ?", (actor_id(),)).fetchone()
    if not _password_matches(supplied, user["password_hash"] if user else None):
        return _reauthentication_failed(actor_id(), "REAUTHENTICATION_FAILED", "أدخل كلمة المرور الحالية لبدء إعداد المصادقة", 403)
    _record_reauthentication(actor_id(), True)
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
    codes = [secrets.token_hex(16).upper() for _ in range(10)]
    _record_attempt(identity, address, True)
    with transaction():
        get_db().execute("UPDATE mfa_enrollments SET enabled = 1, verified_at = ?, updated_at = ? WHERE user_id = ?", (iso_now(), iso_now(), actor_id()))
        get_db().execute("DELETE FROM mfa_backup_codes WHERE user_id = ?", (actor_id(),))
        get_db().executemany(
            "INSERT INTO mfa_backup_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)",
            [(actor_id(), hash_recovery_code(item), iso_now()) for item in codes],
        )
        record_audit(get_db(), "enabled", "mfa", actor_id())
    return jsonify({"message": "تم تفعيل المصادقة متعددة العوامل", "backup_codes": codes})


@auth_api.delete("/api/auth/mfa")
@login_required
def mfa_disable():
    if _reauthentication_blocked(actor_id()):
        return _reauthentication_limited(actor_id())
    data = _payload()
    password = data.get("current_password")
    code = data.get("code")
    user = get_db().execute("SELECT password_hash FROM users WHERE id = ?", (actor_id(),)).fetchone()
    if not _password_matches(password, user["password_hash"] if user else None) or not _mfa_valid(actor_id(), code):
        return _reauthentication_failed(actor_id(), "REAUTHENTICATION_FAILED", "يلزم التحقق من كلمة المرور ورمز المصادقة", 403)
    _record_reauthentication(actor_id(), True)
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
            "SELECT id, email, socify_user_name(name,name_ar,name_en) AS name, role, team, is_active, created_at, last_login FROM users WHERE workspace_id = ? ORDER BY name",
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
        if not isinstance(data["role"], str) or data["role"] not in ROLE_PERMISSIONS:
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
    updated = (
        get_db()
        .execute("SELECT id, email, socify_user_name(name,name_ar,name_en) AS name, role, team, is_active FROM users WHERE id = ?", (user_id,))
        .fetchone()
    )
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
