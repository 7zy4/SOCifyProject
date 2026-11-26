"""First-run checklist for team managers.

A manager of a new team (one with no cases yet) sees six set-up steps on the case list until they finish or dismiss
it. Steps that leave a trace in the database are recognised on their own; any step can also be marked done by hand.
Progress is kept per user and team in onboarding_progress. Teams that already have cases never see the checklist
unless their manager had started it while the team was still empty.
"""

import sqlite3
from datetime import timedelta
from typing import Any

from flask import Blueprint, jsonify, request

from .audit import record_audit
from .db import get_db, transaction
from .security import current_user, error_response, login_required
from .timeutils import iso_now, utc_now

onboarding_api = Blueprint("onboarding", __name__)

MANAGER_ROLES = {"soc_manager", "admin"}
ITEMS = ("invite_team", "first_case", "sla_calendar", "attack_catalogue", "threat_intel", "backups")
# Markers that share the table with the steps: the checklist was shown to this manager, or they dismissed it.
SHOWN, DISMISSED = "shown", "dismissed"
BACKUP_FRESH_HOURS = 48

SCHEMA = """
CREATE TABLE IF NOT EXISTS onboarding_progress (
    user_id INTEGER NOT NULL REFERENCES users(id),
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    item TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    PRIMARY KEY (user_id, workspace_id, item)
);
"""


def migrate(connection: sqlite3.Connection) -> None:
    connection.execute(SCHEMA)


def _marks(user_id: int, workspace: int) -> dict[str, str]:
    rows = get_db().execute("SELECT item, completed_at FROM onboarding_progress WHERE user_id = ? AND workspace_id = ?", (user_id, workspace)).fetchall()
    return {row["item"]: row["completed_at"] for row in rows}


def _first_case(workspace: int) -> int | None:
    row = get_db().execute("SELECT id FROM incident_cases WHERE workspace_id = ? ORDER BY id LIMIT 1", (workspace,)).fetchone()
    return int(row["id"]) if row else None


def _detected(workspace: int) -> dict[str, bool]:
    """Which steps the database already shows as done for this team."""
    db = get_db()
    members = db.execute("SELECT COUNT(*) FROM users WHERE workspace_id = ? AND is_active = 1", (workspace,)).fetchone()[0]
    invited = db.execute("SELECT 1 FROM team_invitations WHERE workspace_id = ? LIMIT 1", (workspace,)).fetchone() is not None
    sla = (
        db.execute(
            "SELECT 1 FROM autopsy_records r JOIN incident_cases c ON c.id = r.case_id WHERE c.workspace_id = ? AND r.kind = 'workflow_sla' LIMIT 1",
            (workspace,),
        ).fetchone()
        is not None
    )
    intelligence = db.execute("SELECT 1 FROM autopsy_intel_bundles WHERE workspace_id = ? LIMIT 1", (workspace,)).fetchone() is not None
    recent = (utc_now() - timedelta(hours=BACKUP_FRESH_HOURS)).isoformat().replace("+00:00", "Z")
    backup = db.execute("SELECT 1 FROM backup_runs WHERE status = 'succeeded' AND finished_at >= ? LIMIT 1", (recent,)).fetchone() is not None
    return {
        "invite_team": invited or int(members) > 1,
        "first_case": _first_case(workspace) is not None,
        "sla_calendar": sla,
        "attack_catalogue": False,
        "threat_intel": intelligence,
        "backups": backup,
    }


def _context(workspace: int) -> dict[str, Any]:
    db = get_db()
    attack = db.execute("SELECT value FROM schema_meta WHERE key = 'attack_version'").fetchone()
    last_backup = db.execute("SELECT MAX(finished_at) FROM backup_runs WHERE status = 'succeeded'").fetchone()[0]
    return {"attack_version": attack["value"] if attack else None, "last_backup_at": last_backup, "first_case_id": _first_case(workspace)}


def checklist(user: dict[str, Any]) -> dict[str, Any]:
    """The checklist as the case list shows it; visible is False for everyone except a manager who still needs it."""
    if user.get("role") not in MANAGER_ROLES:
        return {"visible": False}
    workspace, user_id = int(user["workspace_id"]), int(user["id"])
    marks = _marks(user_id, workspace)
    detected = _detected(workspace)
    items = [{"id": item, "done": detected[item] or item in marks, "detected": detected[item], "marked": item in marks} for item in ITEMS]
    complete = all(item["done"] for item in items)
    empty_team = not detected["first_case"]
    visible = DISMISSED not in marks and not complete and (empty_team or SHOWN in marks)
    if visible and SHOWN not in marks:
        # Remember that this manager started the checklist, so it stays after the team's first case is created.
        get_db().execute(
            "INSERT OR IGNORE INTO onboarding_progress (user_id, workspace_id, item, completed_at) VALUES (?, ?, ?, ?)", (user_id, workspace, SHOWN, iso_now())
        )
    return {"visible": visible, "items": items, "completed": sum(item["done"] for item in items), "total": len(items), **_context(workspace)}


def _manager() -> dict[str, Any] | None:
    user = current_user()
    return user if user is not None and user.get("role") in MANAGER_ROLES else None


def _not_manager():
    return error_response("PERMISSION_DENIED", "قائمة البدء متاحة لمدير الفريق", 403)


@onboarding_api.get("/api/onboarding")
@login_required
def onboarding_status():
    return jsonify(checklist(current_user() or {}))


@onboarding_api.put("/api/onboarding/items/<item>")
@login_required
def mark_onboarding_item(item: str):
    user = _manager()
    if user is None:
        return _not_manager()
    if item not in ITEMS:
        return error_response("ONBOARDING_ITEM_NOT_FOUND", "خطوة البدء غير معروفة", 404)
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or set(body) != {"done"} or not isinstance(body["done"], bool):
        return error_response("INVALID_ONBOARDING_ITEM", "أرسل done بقيمة منطقية فقط", 422)
    workspace, user_id = int(user["workspace_id"]), int(user["id"])
    with transaction():
        if body["done"]:
            get_db().execute(
                "INSERT OR IGNORE INTO onboarding_progress (user_id, workspace_id, item, completed_at) VALUES (?, ?, ?, ?)",
                (user_id, workspace, item, iso_now()),
            )
        else:
            get_db().execute("DELETE FROM onboarding_progress WHERE user_id = ? AND workspace_id = ? AND item = ?", (user_id, workspace, item))
        record_audit(get_db(), "onboarding_step", "user", user_id, details={"item": item, "done": body["done"]})
    return jsonify(checklist(user))


@onboarding_api.post("/api/onboarding/dismiss")
@login_required
def dismiss_onboarding():
    user = _manager()
    if user is None:
        return _not_manager()
    with transaction():
        get_db().execute(
            "INSERT OR IGNORE INTO onboarding_progress (user_id, workspace_id, item, completed_at) VALUES (?, ?, ?, ?)",
            (int(user["id"]), int(user["workspace_id"]), DISMISSED, iso_now()),
        )
        record_audit(get_db(), "onboarding_dismissed", "user", int(user["id"]))
    return jsonify(checklist(user))
