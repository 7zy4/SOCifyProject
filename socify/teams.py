import hashlib
import json
import secrets
from datetime import timedelta

from flask import Blueprint, jsonify, request

from .audit import record_audit
from .db import get_db, inserted_id, transaction
from .security import ROLE_PERMISSIONS, actor_id, current_user, error_response, has_permission, login_required, workspace_id
from .timeutils import iso_now, utc_now

teams_api = Blueprint("teams", __name__)
MEMBER_ROLES = {"analyst", "auditor", "instructor", "soc_manager"}


def manager():
    return (current_user() or {}).get("role") in {"admin", "soc_manager"}


@teams_api.get("/api/team")
@login_required
def team_detail():
    members = [
        dict(row)
        for row in get_db().execute("SELECT id, name, email, role, is_active FROM users WHERE workspace_id = ? ORDER BY id", (workspace_id(),)).fetchall()
    ]
    roles = []
    for role in sorted(MEMBER_ROLES):
        policy = get_db().execute("SELECT permissions FROM team_role_permissions WHERE workspace_id = ? AND role = ?", (workspace_id(), role)).fetchone()
        roles.append(
            {"role": role, "permissions": json.loads(policy[0]) if policy else sorted(ROLE_PERMISSIONS[role]), "available": sorted(ROLE_PERMISSIONS[role])}
        )
    scope = "" if manager() else " AND a.assignee = ?"
    args = [workspace_id()] if manager() else [workspace_id(), actor_id()]
    assignments = [
        dict(row)
        for row in get_db()
        .execute(
            f"SELECT a.*, t.status AS task_status, u.name AS assignee_name, c.reference, c.title AS case_title, j.filename FROM team_log_assignments a JOIN case_tasks t ON t.id = a.task_id JOIN users u ON u.id = a.assignee JOIN incident_cases c ON c.id = a.case_id JOIN ingestion_jobs j ON j.id = a.job_id WHERE a.workspace_id = ?{scope} ORDER BY a.id DESC LIMIT 100",
            args,
        )
        .fetchall()
    ]
    if not has_permission(current_user(), "cases.read"):
        assignments = []
    return jsonify({"members": members, "roles": roles, "assignments": assignments, "can_manage": manager()})


@teams_api.post("/api/team/invitations")
@login_required
def invite_member():
    from .auth import re_email

    if not manager():
        return error_response("PERMISSION_DENIED", "إدارة الدعوات للمدير فقط", 403)
    data = request.get_json(silent=True)
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("email"), str)
        or not re_email(data["email"])
        or not isinstance(data.get("role"), str)
        or data["role"] not in MEMBER_ROLES
    ):
        return error_response("INVALID_INVITATION", "حدد البريد والدور المسموح", 422)
    token = secrets.token_urlsafe(32)
    expires = (utc_now() + timedelta(days=1)).isoformat().replace("+00:00", "Z")
    with transaction():
        get_db().execute(
            "INSERT INTO team_invitations (workspace_id, email, role, token_hash, created_by, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
            (workspace_id(), data["email"].strip().lower(), data["role"], hashlib.sha256(token.encode()).hexdigest(), actor_id(), expires),
        )
        record_audit(get_db(), "invite", "team", workspace_id(), details={"role": data["role"]})
    return jsonify({"invitation_token": token, "expires_at": expires}), 201


@teams_api.patch("/api/team/members/<int:user_id>")
@login_required
def change_member(user_id):
    if not manager():
        return error_response("PERMISSION_DENIED", "تغيير الأدوار للمدير فقط", 403)
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("role"), str) or data["role"] not in MEMBER_ROLES:
        return error_response("INVALID_ROLE", "الدور غير مسموح", 422)
    with transaction():
        member = get_db().execute("SELECT role FROM users WHERE id = ? AND workspace_id = ? AND is_active = 1", (user_id, workspace_id())).fetchone()
        if not member or member["role"] == "admin":
            return error_response("MEMBER_NOT_FOUND", "العضو غير متاح", 404)
        count = (
            get_db()
            .execute("SELECT COUNT(*) FROM users WHERE workspace_id = ? AND is_active = 1 AND role IN ('soc_manager', 'admin')", (workspace_id(),))
            .fetchone()[0]
        )
        if member["role"] == "soc_manager" and data["role"] != "soc_manager" and count <= 1:
            return error_response("LAST_MANAGER", "لا يمكن إزالة آخر مدير", 409)
        get_db().execute("UPDATE users SET role = ? WHERE id = ?", (data["role"], user_id))
        get_db().execute("UPDATE workspace_memberships SET role = ? WHERE workspace_id = ? AND user_id = ?", (data["role"], workspace_id(), user_id))
        record_audit(get_db(), "role_change", "user", user_id, details={"from": member["role"], "to": data["role"]})
    return jsonify({"updated": True})


@teams_api.put("/api/team/roles/<role>")
@login_required
def role_policy(role):
    if not manager():
        return error_response("PERMISSION_DENIED", "إدارة الصلاحيات للمدير فقط", 403)
    data = request.get_json(silent=True)
    permissions = data.get("permissions") if isinstance(data, dict) else None
    if (
        role not in MEMBER_ROLES - {"soc_manager"}
        or not isinstance(permissions, list)
        or any(not isinstance(value, str) for value in permissions)
        or not set(permissions).issubset(ROLE_PERMISSIONS[role])
    ):
        return error_response("INVALID_ROLE_POLICY", "اختر صلاحيات ضمن حدود الدور الأساسية", 422)
    with transaction():
        get_db().execute(
            "INSERT INTO team_role_permissions (workspace_id, role, permissions) VALUES (?, ?, ?) ON CONFLICT(workspace_id, role) DO UPDATE SET permissions = excluded.permissions",
            (workspace_id(), role, json.dumps(sorted(set(permissions)))),
        )
        record_audit(get_db(), "permissions_change", "team_role", role, details={"permissions": permissions})
    return jsonify({"updated": True})


@teams_api.post("/api/team/assignments")
@login_required
def assign_logs():
    from .cases import _case_row, _history
    from .ingestion import _job_access

    if not manager():
        return error_response("PERMISSION_DENIED", "إسناد السجلات للمدير فقط", 403)
    data = request.get_json(silent=True)
    if (
        not isinstance(data, dict)
        or any(type(data.get(key)) is not int for key in ("job_id", "case_id", "assignee"))
        or not isinstance(data.get("instructions"), str)
        or not 3 <= len(data["instructions"].strip()) <= 2000
    ):
        return error_response("INVALID_ASSIGNMENT", "حدد الاستيراد والقضية والعضو والتعليمات", 422)
    case, job = _case_row(data["case_id"]), _job_access(data["job_id"])
    member = get_db().execute("SELECT role FROM users WHERE id = ? AND workspace_id = ? AND is_active = 1", (data["assignee"], workspace_id())).fetchone()
    if (
        not case
        or not job
        or not member
        or member["role"] not in {"analyst", "soc_manager"}
        or case["training_run_id"] is not None
        or job["training_run_id"] is not None
    ):
        return error_response("ASSIGNMENT_SCOPE_INVALID", "اختر قضية واستيرادًا مشتركين وعضوًا من الفريق", 422)
    if job["status"] != "completed" or case["status"] == "closed":
        return error_response("ASSIGNMENT_NOT_READY", "يلزم استيراد مكتمل وقضية مفتوحة", 409)
    policy = get_db().execute("SELECT permissions FROM team_role_permissions WHERE workspace_id = ? AND role = ?", (workspace_id(), member["role"])).fetchone()
    if policy and "cases.update" not in json.loads(policy[0]):
        return error_response("ASSIGNEE_PERMISSION_REQUIRED", "العضو لا يملك صلاحية تنفيذ مهام التحقيق", 422)
    missing = (
        get_db()
        .execute(
            "SELECT 1 FROM security_events e WHERE e.workspace_id = ? AND e.training_run_id IS NULL AND e.idempotency_key LIKE ? AND NOT EXISTS (SELECT 1 FROM case_events ce WHERE ce.case_id = ? AND ce.event_id = e.id) LIMIT 1",
            (workspace_id(), f"import:{job['content_hash']}:%", case["id"]),
        )
        .fetchone()
    )
    if missing:
        return error_response("CASE_LOGS_REQUIRED", "اربط سجلات الاستيراد بالقضية أولًا", 409)
    with transaction():
        if get_db().execute("SELECT status FROM incident_cases WHERE id = ?", (case["id"],)).fetchone()[0] == "closed":
            return error_response("ASSIGNMENT_NOT_READY", "القضية مغلقة", 409)
        duplicate = (
            get_db()
            .execute(
                "SELECT id FROM team_log_assignments WHERE workspace_id = ? AND job_id = ? AND case_id = ? AND assignee = ?",
                (workspace_id(), job["id"], case["id"], data["assignee"]),
            )
            .fetchone()
        )
        if duplicate:
            return jsonify({"id": duplicate["id"], "duplicate": True})
        task = get_db().execute(
            "INSERT INTO case_tasks (case_id, title, required, status, assignee, created_at) VALUES (?, ?, 1, 'pending', ?, ?)",
            (case["id"], data["instructions"].strip()[:255], data["assignee"], iso_now()),
        )
        assignment = get_db().execute(
            "INSERT INTO team_log_assignments (workspace_id, job_id, case_id, task_id, assignee, assigned_by, instructions, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (workspace_id(), job["id"], case["id"], inserted_id(task), data["assignee"], actor_id(), data["instructions"].strip(), iso_now()),
        )
        identifier = inserted_id(assignment)
        _history(get_db(), case["id"], "logs_assigned", None, {"assignment_id": identifier, "assignee": data["assignee"], "job_id": job["id"]})
        record_audit(get_db(), "assign", "team_logs", identifier, details={"case_id": case["id"], "assignee": data["assignee"]})
    return jsonify({"id": identifier}), 201


@teams_api.patch("/api/team/assignments/<int:assignment_id>")
@login_required
def update_assignment(assignment_id):
    from .cases import _history

    if not has_permission(current_user(), "cases.update"):
        return error_response("PERMISSION_DENIED", "الدور لا يسمح بتحديث مهام التحقيق", 403)
    data = request.get_json(silent=True)
    status = data.get("status") if isinstance(data, dict) else None
    if not isinstance(status, str) or status not in {"in_progress", "completed"}:
        return error_response("INVALID_ASSIGNMENT_STATE", "حالة المهمة غير صالحة", 422)
    with transaction():
        row = (
            get_db()
            .execute(
                "SELECT a.*, c.status AS case_status FROM team_log_assignments a JOIN incident_cases c ON c.id = a.case_id WHERE a.id = ? AND a.workspace_id = ?",
                (assignment_id, workspace_id()),
            )
            .fetchone()
        )
        if not row or not manager() and row["assignee"] != actor_id():
            return error_response("ASSIGNMENT_NOT_FOUND", "المهمة غير موجودة", 404)
        if row["case_status"] == "closed":
            return error_response("CASE_CLOSED", "المهمة مقفلة مع القضية", 409)
        get_db().execute(
            "UPDATE case_tasks SET status = ?, completed_by = ?, completed_at = ? WHERE id = ?",
            (status, actor_id() if status == "completed" else None, iso_now() if status == "completed" else None, row["task_id"]),
        )
        get_db().execute(
            "UPDATE team_log_assignments SET state = ?, completed_at = ? WHERE id = ?", (status, iso_now() if status == "completed" else None, assignment_id)
        )
        _history(get_db(), row["case_id"], "assigned_logs_updated", None, {"assignment_id": assignment_id, "status": status})
        record_audit(get_db(), "update", "team_logs", assignment_id, details={"status": status})
    return jsonify({"updated": True})
