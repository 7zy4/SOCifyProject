import argparse
import getpass
import os
import uuid
from pathlib import Path

import bcrypt

from scripts.start_codespace import load_environment
from socify import create_app
from socify.audit import record_audit
from socify.auth import re_email
from socify.autopsy_domain import text_value
from socify.db import get_db, inserted_id, transaction
from socify.security import password_error
from socify.timeutils import iso_now


def create_manager(app, email: str, name: str, team: str, password: str) -> int:
    normalized = text_value(email, 254, True).lower()
    name, team = text_value(name, 120, True), text_value(team, 120, True)
    if not re_email(normalized):
        raise ValueError("البريد الإلكتروني غير صالح")
    problem = password_error(password)
    if problem:
        raise ValueError(problem)
    encoded = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    with app.app_context(), transaction():
        if get_db().execute("SELECT 1 FROM users WHERE email = ?", (normalized,)).fetchone():
            raise ValueError("الحساب موجود؛ لن تتم إعادة تعيينه أو تعديل بياناته")
        now = iso_now()
        workspace = inserted_id(
            get_db().execute("INSERT INTO training_workspaces(public_id, name, created_at) VALUES (?, ?, ?)", (f"organization-{uuid.uuid4().hex}", team, now))
        )
        user = inserted_id(
            get_db().execute(
                "INSERT INTO users(email, password_hash, name, role, team, workspace_id, created_at, password_changed_at, is_active) VALUES (?, ?, ?, 'soc_manager', ?, ?, ?, ?, 1)",
                (normalized, encoded, name, team, workspace, now, now),
            )
        )
        get_db().execute("INSERT INTO workspace_memberships(workspace_id, user_id, role, created_at) VALUES (?, ?, 'soc_manager', ?)", (workspace, user, now))
        record_audit(get_db(), "bootstrap", "organization", workspace, actor=user, workspace=workspace)
    return user


def reset_password(app, email: str, password: str) -> int:
    normalized = text_value(email, 254, True).lower()
    if not re_email(normalized):
        raise ValueError("البريد الإلكتروني غير صالح")
    problem = password_error(password)
    if problem:
        raise ValueError(problem)
    replacement = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    with app.app_context(), transaction():
        user = get_db().execute("SELECT id, workspace_id, is_active FROM users WHERE lower(email)=?", (normalized,)).fetchone()
        if not user:
            raise ValueError("الحساب غير موجود في قاعدة البيانات المحددة؛ لن يُنشأ حساب بديل")
        if not user["is_active"]:
            raise ValueError("الحساب معطل؛ يلزم الرجوع إلى مسؤول الفريق")
        now = iso_now()
        get_db().execute("UPDATE users SET password_hash=?, password_changed_at=? WHERE id=?", (replacement, now, user["id"]))
        get_db().execute("UPDATE auth_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", (now, user["id"]))
        record_audit(
            get_db(),
            "password_reset",
            "user",
            user["id"],
            details={"source": "local_server_administrator"},
            workspace=user["workspace_id"],
        )
    return int(user["id"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Create an internal team manager without public registration or default credentials")
    parser.add_argument("--email", required=True)
    parser.add_argument("--name")
    parser.add_argument("--team")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--status", action="store_true", help="Show the selected database and account state without changing credentials")
    modes.add_argument(
        "--reset-password", action="store_true", help="Local server administrator recovery; revoke sessions and preserve MFA, roles and evidence"
    )
    options = parser.parse_args()
    if not options.status and not options.reset_password and (not options.name or not options.team):
        parser.error("--name and --team are required when creating a manager")
    if os.environ.get("SOCIFY_ENV", "development") != "production":
        load_environment(Path(__file__).resolve().parent.parent)
    try:
        app = create_app()
        print(f"Database: {Path(app.config['DATABASE']).resolve()}")
        if options.status:
            normalized = text_value(options.email, 254, True).lower()
            if not re_email(normalized):
                raise ValueError("البريد الإلكتروني غير صالح")
            with app.app_context():
                user = get_db().execute("SELECT id, is_active FROM users WHERE lower(email)=?", (normalized,)).fetchone()
                if not user:
                    raise ValueError("الحساب غير موجود في قاعدة البيانات المحددة")
                mfa = get_db().execute("SELECT enabled FROM mfa_enrollments WHERE user_id=?", (user["id"],)).fetchone()
                print(f"Account found (user_id={user['id']}, active={bool(user['is_active'])}, MFA={bool(mfa and mfa['enabled'])})")
            return
        if options.reset_password:
            password = getpass.getpass("كلمة المرور الجديدة: ")
            if password != getpass.getpass("أعد إدخال كلمة المرور الجديدة: "):
                raise ValueError("كلمتا المرور غير متطابقتين؛ لم يتغير الحساب")
            user_id = reset_password(app, options.email, password)
            print(f"Password reset (user_id={user_id}); sessions revoked; MFA, roles and evidence preserved")
            return
        password = os.environ.get("SOCIFY_BOOTSTRAP_PASSWORD") or getpass.getpass("كلمة مرور مدير الفريق: ")
        user_id = create_manager(app, options.email, options.name, options.team, password)
    except ValueError as exc:
        parser.exit(2, f"{exc}\n")
    print(f"Internal team manager created (user_id={user_id}); existing users and evidence preserved")


if __name__ == "__main__":
    main()
