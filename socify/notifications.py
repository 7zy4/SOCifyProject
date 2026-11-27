"""In-app notifications: work that needs a person now, under a bell with an unread count.

A notification names an event, the case or incoming alert it concerns and who caused it; it stores no case text or
evidence. Its words are built when it is read. Recipients are filtered when it is written (active members of the
team who can see the case or the intake queue) and again when it is read, so a person who lost access to a case
stops seeing its notifications. The SLA check runs in the case worker once a minute and notifies each threshold once.
"""

import json
import sqlite3
from collections.abc import Iterable
from datetime import timedelta
from typing import Any

from flask import Blueprint, jsonify, request

from .db import get_db, transaction
from .operational import case_scope
from .security import current_user, error_response, has_permission, login_required
from .timeutils import iso_now, parse_timestamp, utc_now

notifications_api = Blueprint("notifications", __name__)

KINDS = (
    "case_assigned",
    "case_member_added",
    "batch_assigned",
    "handoff",
    "review_requested",
    "case_returned",
    "report_approved",
    "escalated",
    "escalation_decided",
    "sla_warning",
    "sla_breached",
    "intake_alert",
)
MANAGER_ROLES = {"soc_manager", "admin"}
RETENTION_DAYS = 90
LIST_LIMIT = 30
SCAN_LIMIT = 100

SCHEMA = """
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    kind TEXT NOT NULL,
    case_id INTEGER REFERENCES incident_cases(id),
    intake_alert_id INTEGER,
    actor_id INTEGER REFERENCES users(id),
    dedup_key TEXT,
    created_at TEXT NOT NULL,
    read_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_notifications_inbox ON notifications(user_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_notifications_once ON notifications(user_id, dedup_key) WHERE dedup_key IS NOT NULL
"""


def migrate(connection: sqlite3.Connection) -> None:
    for statement in SCHEMA.split(";"):
        if statement.strip():
            connection.execute(statement)


# Writing --------------------------------------------------------------------------------------------------------


def _principal(row: sqlite3.Row) -> dict[str, Any]:
    principal = dict(row)
    policy = (
        get_db().execute("SELECT permissions FROM team_role_permissions WHERE workspace_id = ? AND role = ?", (row["workspace_id"], row["role"])).fetchone()
    )
    if policy:
        principal["role_permissions"] = json.loads(policy[0])
    return principal


def _members(workspace: int, user_ids: Iterable[int] | None = None) -> list[dict[str, Any]]:
    query = "SELECT id, role, workspace_id FROM users WHERE workspace_id = ? AND is_active = 1"
    values: list[Any] = [workspace]
    if user_ids is not None:
        chosen = sorted({int(item) for item in user_ids})
        if not chosen:
            return []
        query += " AND id IN (" + ",".join("?" for _ in chosen) + ")"
        values.extend(chosen)
    return [_principal(row) for row in get_db().execute(query, values)]


def _sees_case(principal: dict[str, Any], case_id: int) -> bool:
    from .autopsy_pipeline import full_case_scope_sql

    if not has_permission(principal, "cases.read"):
        return False
    scope, args = case_scope(principal)
    restricted, more = full_case_scope_sql(principal)
    return (
        get_db()
        .execute(
            f"SELECT 1 FROM incident_cases c WHERE c.id = ? AND c.workspace_id = ? AND c.archived_at IS NULL{scope}{restricted}",
            (case_id, principal["workspace_id"], *args, *more),
        )
        .fetchone()
        is not None
    )


def notify(
    recipients: Iterable[int | None] | None,
    kind: str,
    *,
    workspace: int,
    case_id: int | None = None,
    intake_alert_id: int | None = None,
    actor: int | None = None,
    dedup_key: str | None = None,
    permission: str | None = None,
) -> int:
    """Notify active team members (all of them when recipients is None) who may see the subject; never the actor."""
    if kind not in KINDS:
        raise ValueError(f"unknown notification kind {kind}")
    chosen = None if recipients is None else [item for item in recipients if item is not None]
    sent = 0
    now = iso_now()
    for principal in _members(workspace, chosen):
        if principal["id"] == actor or (permission and not has_permission(principal, permission)):
            continue
        if case_id is not None and not _sees_case(principal, case_id):
            continue
        if intake_alert_id is not None and not has_permission(principal, "intake.read"):
            continue
        sent += (
            get_db()
            .execute(
                "INSERT OR IGNORE INTO notifications(workspace_id, user_id, kind, case_id, intake_alert_id, actor_id, dedup_key, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (workspace, principal["id"], kind, case_id, intake_alert_id, actor, dedup_key, now),
            )
            .rowcount
        )
    return sent


def managers(workspace: int) -> list[int]:
    return [int(row[0]) for row in get_db().execute("SELECT id FROM users WHERE workspace_id = ? AND is_active = 1 AND role = 'soc_manager'", (workspace,))]


def case_people(case_id: int) -> list[int]:
    """The case's assignee, or its analysts when nobody is assigned."""
    row = get_db().execute("SELECT assignee FROM incident_cases WHERE id = ?", (case_id,)).fetchone()
    if row and row["assignee"]:
        return [int(row["assignee"])]
    return [
        int(item[0])
        for item in get_db().execute("SELECT user_id FROM autopsy_case_members WHERE case_id = ? AND responsibility != 'previous_shift'", (case_id,))
    ]


def case_transition(case: sqlite3.Row, target: str, actor: int | None) -> None:
    """Who must act after a status change: reviewers when a case waits for review, the analyst when it comes back."""
    workspace = int(case["workspace_id"])
    if target == "awaiting_review":
        notify(None, "review_requested", workspace=workspace, case_id=int(case["id"]), actor=actor, permission="reports.approve")
    elif case["status"] == "awaiting_review" and target not in {"closed", "cancelled"}:
        notify(case_people(int(case["id"])), "case_returned", workspace=workspace, case_id=int(case["id"]), actor=actor)


# SLA thresholds (case worker) -----------------------------------------------------------------------------------


def check_sla_deadlines(now=None) -> int:
    """Notify the case's people at 80% of its response budget and, with the managers, when it runs out; once each."""
    from .autopsy_workflow import sla_status

    now = now or utc_now()
    sent = 0
    rows = (
        get_db()
        .execute(
            """SELECT * FROM incident_cases WHERE archived_at IS NULL AND status NOT IN ('closed', 'cancelled')
        AND sla_due_at IS NOT NULL AND sla_paused_at IS NULL ORDER BY id"""
        )
        .fetchall()
    )
    for case in rows:
        status = sla_status(case, now)
        if status["configured"]:
            if status["status"] == "paused":
                continue
            budget, elapsed, version = status["policy"]["minutes"] * 60, status["elapsed_work_seconds"], f"p{status['policy']['policy_version']}"
        else:
            start, due = parse_timestamp(case["created_at"]), parse_timestamp(case["sla_due_at"])
            budget, elapsed, version = (due - start).total_seconds(), (now - start).total_seconds(), f"d{case['sla_due_at']}"
        if budget <= 0:
            continue
        ratio = elapsed / budget
        workspace, case_id = int(case["workspace_id"]), int(case["id"])
        with transaction():
            if ratio >= 1:
                sent += notify(
                    case_people(case_id) + managers(workspace), "sla_breached", workspace=workspace, case_id=case_id, dedup_key=f"sla100:{case_id}:{version}"
                )
            elif ratio >= 0.8:
                sent += notify(case_people(case_id), "sla_warning", workspace=workspace, case_id=case_id, dedup_key=f"sla80:{case_id}:{version}")
    with transaction():
        cutoff = (now - timedelta(days=RETENTION_DAYS)).isoformat().replace("+00:00", "Z")
        get_db().execute("DELETE FROM notifications WHERE created_at < ?", (cutoff,))
    return sent


# Reading --------------------------------------------------------------------------------------------------------


def _visible_rows(user: dict[str, Any], *, unread_only: bool = False) -> list[sqlite3.Row]:
    rows = (
        get_db()
        .execute(
            f"""SELECT n.*, c.reference, socify_case_title(c.title, c.title_en) AS case_title, c.workspace_id AS case_workspace,
            a.title AS alert_title, a.severity AS alert_severity, a.workspace_id AS alert_workspace,
            socify_user_name(u.name, u.name_ar, u.name_en) AS actor_name
            FROM notifications n
            LEFT JOIN incident_cases c ON c.id = n.case_id
            LEFT JOIN intake_alerts a ON a.id = n.intake_alert_id
            LEFT JOIN users u ON u.id = n.actor_id
            WHERE n.user_id = ? AND n.workspace_id = ?{" AND n.read_at IS NULL" if unread_only else ""}
            ORDER BY n.id DESC LIMIT {SCAN_LIMIT}""",
            (int(user["id"]), int(user["workspace_id"])),
        )
        .fetchall()
    )
    seen: dict[int, bool] = {}
    visible = []
    for row in rows:
        if row["case_id"] is not None:
            if row["case_id"] not in seen:
                seen[row["case_id"]] = _sees_case(user, int(row["case_id"]))
            if not seen[row["case_id"]]:
                continue
        if row["intake_alert_id"] is not None and (row["alert_workspace"] != user["workspace_id"] or not has_permission(user, "intake.read")):
            continue
        visible.append(row)
    return visible


def _view(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "kind": row["kind"],
        "created_at": row["created_at"],
        "read": row["read_at"] is not None,
        "actor_name": row["actor_name"],
        "case": {"id": row["case_id"], "reference": row["reference"], "title": row["case_title"]} if row["case_id"] else None,
        "alert": {"id": row["intake_alert_id"], "title": row["alert_title"], "severity": row["alert_severity"]} if row["intake_alert_id"] else None,
    }


@notifications_api.get("/api/notifications")
@login_required
def list_notifications():
    user = current_user() or {}
    rows = _visible_rows(user)
    return jsonify({"items": [_view(row) for row in rows[:LIST_LIMIT]], "unread": sum(row["read_at"] is None for row in rows)})


@notifications_api.get("/api/notifications/unread")
@login_required
def unread_count():
    return jsonify({"unread": len(_visible_rows(current_user() or {}, unread_only=True))})


@notifications_api.post("/api/notifications/<int:notification_id>/read")
@login_required
def mark_read(notification_id: int):
    user = current_user() or {}
    with transaction():
        changed = (
            get_db()
            .execute("UPDATE notifications SET read_at = COALESCE(read_at, ?) WHERE id = ? AND user_id = ?", (iso_now(), notification_id, int(user["id"])))
            .rowcount
        )
    if not changed:
        return error_response("NOTIFICATION_NOT_FOUND", "الإشعار غير موجود", 404)
    return jsonify({"id": notification_id, "read": True})


@notifications_api.post("/api/notifications/read-all")
@login_required
def mark_all_read():
    user = current_user() or {}
    if request.get_json(silent=True) not in (None, {}):
        return error_response("INVALID_NOTIFICATION_ACTION", "لا يقبل هذا الإجراء حقولًا", 422)
    with transaction():
        changed = get_db().execute("UPDATE notifications SET read_at = ? WHERE user_id = ? AND read_at IS NULL", (iso_now(), int(user["id"]))).rowcount
    return jsonify({"marked": changed})
