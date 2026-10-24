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


def main() -> None:
    parser = argparse.ArgumentParser(description="Create an internal team manager without public registration or default credentials")
    parser.add_argument("--email", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--team", required=True)
    options = parser.parse_args()
    if os.environ.get("SOCIFY_ENV", "development") != "production":
        load_environment(Path(__file__).resolve().parent.parent)
    password = os.environ.get("SOCIFY_BOOTSTRAP_PASSWORD") or getpass.getpass("كلمة مرور مدير الفريق: ")
    try:
        user = create_manager(create_app(), options.email, options.name, options.team, password)
    except ValueError as exc:
        parser.exit(2, f"{exc}\n")
    print(f"Internal team manager created (user_id={user}); existing users and evidence preserved")


if __name__ == "__main__":
    main()
