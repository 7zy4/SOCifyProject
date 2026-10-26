import argparse
import getpass
import os
import secrets
import stat
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import bcrypt

from scripts.environment import load_environment
from socify import create_app
from socify.audit import record_audit
from socify.auth import re_email
from socify.autopsy_domain import text_value
from socify.db import get_db, inserted_id, transaction
from socify.security import password_error
from socify.timeutils import iso_now


def normalized_email(email: str) -> str:
    normalized = text_value(email, 254, True).lower()
    if not re_email(normalized):
        raise ValueError("البريد الإلكتروني غير صالح")
    return normalized


def create_manager(app, email: str, name: str, team: str, password: str) -> int:
    normalized = normalized_email(email)
    name, team = text_value(name, 120, True), text_value(team, 120, True)
    problem = password_error(password)
    if problem:
        raise ValueError(problem)
    encoded = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    with app.app_context(), transaction():
        if get_db().execute("SELECT 1 FROM users WHERE lower(email) = ?", (normalized,)).fetchone():
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
    normalized = normalized_email(email)
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


def account_status(app, email: str) -> dict:
    normalized = normalized_email(email)
    with app.app_context():
        user = (
            get_db()
            .execute(
                "SELECT u.id,u.email,u.is_active,COALESCE(m.enabled,0) AS mfa_enabled FROM users u LEFT JOIN mfa_enrollments m ON m.user_id=u.id WHERE lower(u.email)=?",
                (normalized,),
            )
            .fetchone()
        )
        if not user:
            raise ValueError("الحساب غير موجود في قاعدة البيانات المحددة؛ لن يُنشأ حساب بديل")
        return dict(user)


def recovery_account(app, email: str) -> dict:
    user = account_status(app, email)
    if not user["is_active"]:
        raise ValueError("الحساب معطل؛ يلزم الرجوع إلى مسؤول الفريق")
    return user


@contextmanager
def private_password_file(app, prefix: str) -> Iterator[tuple[Path, str]]:
    if app.config["ENV_NAME"] != "development":
        raise ValueError("حفظ كلمة المرور في ملف خاص مخصص للتطوير؛ استخدم الإدخال التفاعلي في الإنتاج")
    directory = Path(app.config["DATABASE"]).resolve().parent / ".account-recovery"
    destination = None
    try:
        if directory.is_symlink():
            raise ValueError("مجلد الاستعادة يجب ألا يكون رابطًا رمزيًا")
        directory.mkdir(mode=0o700, exist_ok=True)
        if stat.S_IMODE(directory.stat().st_mode) != 0o700 or directory.stat().st_uid != os.geteuid():
            raise ValueError("مجلد الاستعادة يجب أن يكون خاصًا بمالك الخادم بصلاحية 0700")
        descriptor, filename = tempfile.mkstemp(prefix=prefix, suffix=".txt", dir=directory)
        destination = Path(filename)
        password = secrets.token_urlsafe(24)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(password + "\n")
            output.flush()
            os.fsync(output.fileno())
        yield destination, password
    except Exception:
        if destination is not None:
            destination.unlink(missing_ok=True)
        raise


def generate_recovery_file(app, email: str) -> Path:
    user = recovery_account(app, email)
    with private_password_file(app, f"access-{user['id']}-") as (destination, password):
        reset_password(app, user["email"], password)
    return destination


def generate_manager_file(app, email: str, name: str, team: str) -> tuple[int, Path]:
    with private_password_file(app, "new-manager-") as (destination, password):
        user_id = create_manager(app, email, name, team, password)
    return user_id, destination


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
    parser.add_argument("--generate-password-file", action="store_true", help="Development-only creation or recovery with a private local password file")
    options = parser.parse_args()
    if options.generate_password_file and options.status:
        parser.error("--generate-password-file cannot be combined with --status")
    if not options.status and not options.reset_password and (not options.name or not options.team):
        parser.error("--name and --team are required when creating a manager")
    if os.environ.get("SOCIFY_ENV", "development").strip().lower() != "production":
        load_environment(Path(__file__).resolve().parent.parent)
    try:
        app = create_app()
        print(f"Database: {Path(app.config['DATABASE']).resolve()}")
        if options.status:
            user = account_status(app, options.email)
            print(f"Account found (user_id={user['id']}, active={bool(user['is_active'])}, MFA={bool(user['mfa_enabled'])})")
            return
        if options.reset_password:
            target = recovery_account(app, options.email)
            print(f"Recovering existing account: {target['email']} (user_id={target['id']})")
            if options.generate_password_file:
                destination = generate_recovery_file(app, options.email)
                print(f"Recovery file: {destination}")
                print("Password reset; open the private file in your editor. Do not share its contents. MFA, roles and evidence preserved.")
                return
            password = getpass.getpass("كلمة المرور الجديدة: ")
            if password != getpass.getpass("أعد إدخال كلمة المرور الجديدة: "):
                raise ValueError("كلمتا المرور غير متطابقتين؛ لم يتغير الحساب")
            user_id = reset_password(app, options.email, password)
            print(f"Password reset (user_id={user_id}); sessions revoked; MFA, roles and evidence preserved")
            return
        if options.generate_password_file:
            user_id, destination = generate_manager_file(app, options.email, options.name, options.team)
            print(f"Internal team manager created (user_id={user_id}); existing users and evidence preserved")
            print(f"Recovery file: {destination}")
            print("Open the private file in your editor. Do not share its contents.")
            return
        password = os.environ.get("SOCIFY_BOOTSTRAP_PASSWORD") or getpass.getpass("كلمة مرور مدير الفريق: ")
        user_id = create_manager(app, options.email, options.name, options.team, password)
    except ValueError as exc:
        parser.exit(2, f"{exc}\n")
    print(f"Internal team manager created (user_id={user_id}); existing users and evidence preserved")


if __name__ == "__main__":
    main()
