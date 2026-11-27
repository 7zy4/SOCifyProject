"""One response-time policy per team: a time budget per case severity and the calendar it is counted in.

When a team has a policy, every new case starts with it: the case gets its workflow SLA record (the same record a
manager can set by hand on one case) and its due date is projected on that calendar, so the overdue flag, the SLA
panel of the case and the team dashboards all read the same deadline. Without a policy, cases keep the fixed
around-the-clock due date by priority. Changing the policy applies to new cases only; a case keeps the policy it
started with until a manager changes that case.
"""

import json
import sqlite3
from datetime import timedelta
from typing import Any

from flask import Blueprint, jsonify, request

from .audit import record_audit
from .db import get_db, transaction
from .security import actor_id, current_user, error_response, has_permission, require_permission, workspace_id
from .timeutils import iso_now, parse_timestamp, utc_now
from .validation import ValidationError, public_error_message

team_sla_api = Blueprint("team_sla", __name__)

SEVERITIES = ("critical", "high", "medium", "low")
MANAGER_ROLES = {"soc_manager", "admin"}
# The fixed hours a case gets without a team policy (by priority), offered as the starting values of the form.
SUGGESTED_MINUTES = {"critical": 60, "high": 240, "medium": 1440, "low": 4320}

SCHEMA = """
CREATE TABLE IF NOT EXISTS team_sla_policies (
    workspace_id INTEGER PRIMARY KEY REFERENCES workspaces(id),
    minutes TEXT NOT NULL CHECK (json_valid(minutes)),
    calendar TEXT NOT NULL CHECK (json_valid(calendar)),
    version INTEGER NOT NULL,
    updated_by INTEGER REFERENCES users(id),
    updated_at TEXT NOT NULL
)
"""


def migrate(connection: sqlite3.Connection) -> None:
    connection.execute(SCHEMA)


def team_policy(workspace: int) -> dict[str, Any] | None:
    row = get_db().execute("SELECT * FROM team_sla_policies WHERE workspace_id = ?", (workspace,)).fetchone()
    if row is None:
        return None
    return {
        "minutes": json.loads(row["minutes"]),
        "calendar": json.loads(row["calendar"]),
        "version": row["version"],
        "updated_by": row["updated_by"],
        "updated_at": row["updated_at"],
    }


def _minutes(value: object) -> dict[str, int]:
    if not isinstance(value, dict) or set(value) != set(SEVERITIES):
        raise ValidationError("حدد المهلة لكل درجة خطورة")
    if any(type(value[key]) is not int or not 1 <= value[key] <= 525600 for key in SEVERITIES):
        raise ValidationError("المهلة من دقيقة إلى سنة لكل درجة")
    return {key: value[key] for key in SEVERITIES}


def apply_to_new_case(case_id: int, severity: str, created_at: str) -> None:
    """Inside the case-creation transaction: start the case on the team policy and project its due date."""
    from .autopsy_api import insert_record
    from .autopsy_workflow import _project_due

    policy = team_policy(workspace_id())
    if policy is None or severity not in policy["minutes"]:
        return
    minutes = int(policy["minutes"][severity])
    insert_record(
        case_id,
        "workflow_sla",
        {
            "minutes": minutes,
            "calendar": policy["calendar"],
            "reason": "سياسة الفريق",
            "policy_version": 1,
            "severity_at_configuration": severity,
            "configured_by": actor_id(),
            "configured_at": created_at,
            "source": "team_policy",
            "team_policy_version": policy["version"],
        },
    )
    due = _project_due(parse_timestamp(created_at), minutes * 60, policy["calendar"])
    get_db().execute("UPDATE incident_cases SET sla_due_at = ? WHERE id = ?", (due, case_id))


def sync_due_date(case: sqlite3.Row | None) -> None:
    """After a manager sets, pauses or resumes a case's SLA: keep the case's due date and pause mark on that policy."""
    from .autopsy_workflow import sla_status

    if case is None:
        return
    status = sla_status(case)
    if not status["configured"]:
        return
    if status["status"] == "paused":
        get_db().execute("UPDATE incident_cases SET sla_paused_at = COALESCE(sla_paused_at, ?) WHERE id = ?", (iso_now(), case["id"]))
        return
    due = status["projected_due_at"]
    if due is None and status["remaining_work_seconds"] <= 0:
        # Already past the budget: the due date is the moment it ran out (exact around the clock, close on a calendar).
        due = (utc_now() + timedelta(seconds=status["remaining_work_seconds"])).isoformat().replace("+00:00", "Z")
    get_db().execute("UPDATE incident_cases SET sla_due_at = ?, sla_paused_at = NULL WHERE id = ?", (due, case["id"]))


def rebase_on_severity(case_id: int, severity: str) -> None:
    """A case that runs on the team policy moves to the budget of its new severity; a hand-set case SLA stays as set."""
    from .autopsy_api import insert_record
    from .cases import _case_row

    row = get_db().execute("SELECT payload FROM autopsy_records WHERE case_id = ? AND kind = 'workflow_sla' ORDER BY id DESC LIMIT 1", (case_id,)).fetchone()
    policy = team_policy(workspace_id())
    if row is None or policy is None or json.loads(row["payload"]).get("source") != "team_policy" or severity not in policy["minutes"]:
        return
    count = get_db().execute("SELECT COUNT(*) FROM autopsy_records WHERE case_id = ? AND kind = 'workflow_sla'", (case_id,)).fetchone()[0]
    insert_record(
        case_id,
        "workflow_sla",
        {
            "minutes": int(policy["minutes"][severity]),
            "calendar": policy["calendar"],
            "reason": "سياسة الفريق بعد تغيير الخطورة",
            "policy_version": count + 1,
            "severity_at_configuration": severity,
            "configured_by": actor_id(),
            "configured_at": iso_now(),
            "source": "team_policy",
            "team_policy_version": policy["version"],
        },
    )
    sync_due_date(_case_row(case_id))


@team_sla_api.get("/api/team/sla-policy")
@require_permission("cases.read")
def read_policy():
    user = current_user() or {}
    return jsonify(
        {
            "policy": team_policy(workspace_id()),
            "suggested_minutes": SUGGESTED_MINUTES,
            "can_manage": user.get("role") in MANAGER_ROLES and has_permission(user, "cases.assign"),
        }
    )


@team_sla_api.put("/api/team/sla-policy")
@require_permission("cases.assign")
def save_policy():
    from .autopsy_workflow import validate_calendar

    user = current_user() or {}
    if user.get("role") not in MANAGER_ROLES:
        return error_response("PERMISSION_DENIED", "سياسة المهلة يضعها مدير الفريق", 403)
    data = request.get_json(silent=True)
    try:
        if not isinstance(data, dict) or set(data) != {"minutes", "calendar"}:
            raise ValidationError("أرسل المهلة لكل درجة وتقويم الاحتساب")
        minutes, calendar = _minutes(data["minutes"]), validate_calendar(data["calendar"])
    except ValueError as exc:
        return error_response("INVALID_SLA_POLICY", public_error_message(exc, "تحقق من مهلة الاستجابة وتقويمها"), 422)
    now = iso_now()
    with transaction():
        current = get_db().execute("SELECT version FROM team_sla_policies WHERE workspace_id = ?", (workspace_id(),)).fetchone()
        version = (current["version"] if current else 0) + 1
        get_db().execute(
            """INSERT INTO team_sla_policies(workspace_id, minutes, calendar, version, updated_by, updated_at) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace_id) DO UPDATE SET minutes = excluded.minutes, calendar = excluded.calendar, version = excluded.version,
            updated_by = excluded.updated_by, updated_at = excluded.updated_at""",
            (workspace_id(), json.dumps(minutes), json.dumps(calendar, ensure_ascii=False), version, actor_id(), now),
        )
        record_audit(get_db(), "update", "team_sla_policy", workspace_id(), details={"version": version, "minutes": minutes, "mode": calendar["mode"]})
    return jsonify({"policy": team_policy(workspace_id())})
