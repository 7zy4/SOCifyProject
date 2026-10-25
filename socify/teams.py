import hashlib
import json
import secrets
from datetime import timedelta

from flask import Blueprint, jsonify, request

from .audit import record_audit
from .db import get_db, inserted_id, transaction
from .operational import case_scope, case_visible, operational_mode
from .security import actor_id, current_user, error_response, has_permission, login_required, workspace_id
from .timeutils import iso_now, utc_now

teams_api = Blueprint("teams", __name__)
MEMBER_ROLES = {"analyst", "auditor", "instructor", "soc_manager", "l1_analyst", "l2_responder", "investigator", "reviewer"}


def allowed_roles():
    return MEMBER_ROLES - {"instructor"} if operational_mode() else MEMBER_ROLES


def manager():
    return (current_user() or {}).get("role") in {"admin", "soc_manager"}


@teams_api.get("/api/team")
@login_required
def team_detail():
    from .operational import operational_mode
    from .security import effective_permissions

    members = [
        dict(row)
        for row in get_db().execute("SELECT id, name, email, role, is_active FROM users WHERE workspace_id = ? ORDER BY id", (workspace_id(),)).fetchall()
    ]
    roles = []
    for role in sorted(MEMBER_ROLES):
        if operational_mode() and role == "instructor":
            continue
        available = effective_permissions({"role": role})
        policy = get_db().execute("SELECT permissions FROM team_role_permissions WHERE workspace_id = ? AND role = ?", (workspace_id(), role)).fetchone()
        roles.append(
            {"role": role, "permissions": sorted(set(json.loads(policy[0])) & available) if policy else sorted(available), "available": sorted(available)}
        )
    scope = "" if manager() else " AND a.assignee = ?"
    args: list[object] = [workspace_id()] if manager() else [workspace_id(), actor_id()]
    if operational_mode():
        membership, parameters = case_scope(current_user() or {})
        scope += membership
        args.extend(parameters)
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
    if operational_mode():
        from .autopsy_pipeline import job_visible

        assignments = [assignment for assignment in assignments if job_visible(assignment["job_id"])]
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
        or data["role"] not in allowed_roles()
        or operational_mode()
        and set(data) != {"email", "role"}
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
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("role"), str)
        or data["role"] not in allowed_roles()
        or operational_mode()
        and set(data) != {"role"}
    ):
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
        get_db().execute("UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", (iso_now(), user_id))
        record_audit(get_db(), "role_change", "user", user_id, details={"from": member["role"], "to": data["role"]})
    return jsonify({"updated": True})


@teams_api.put("/api/team/roles/<role>")
@login_required
def role_policy(role):
    from .security import effective_permissions

    if not manager():
        return error_response("PERMISSION_DENIED", "إدارة الصلاحيات للمدير فقط", 403)
    data = request.get_json(silent=True)
    permissions = data.get("permissions") if isinstance(data, dict) else None
    if (
        role not in allowed_roles() - {"soc_manager"}
        or not isinstance(permissions, list)
        or any(not isinstance(value, str) for value in permissions)
        or not set(permissions).issubset(effective_permissions({"role": role}))
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
        or member["role"] not in {"analyst", "l1_analyst", "l2_responder", "investigator", "soc_manager"}
        or case["training_run_id"] is not None
        or job["training_run_id"] is not None
    ):
        return error_response("ASSIGNMENT_SCOPE_INVALID", "اختر قضية واستيرادًا مشتركين وعضوًا من الفريق", 422)
    if operational_mode() and job["case_id"] != case["id"]:
        return error_response("ASSIGNMENT_SCOPE_INVALID", "دفعة السجلات تابعة لقضية أخرى", 422)
    if job["status"] not in {"completed", "completed_with_errors"} or case["status"] == "closed":
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
        if operational_mode():
            get_db().execute(
                "INSERT INTO autopsy_case_members(case_id, user_id, responsibility, assigned_by, assigned_at) VALUES (?, ?, 'investigator', ?, ?) ON CONFLICT(case_id, user_id) DO NOTHING",
                (case["id"], data["assignee"], actor_id(), iso_now()),
            )
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
        if operational_mode() and not case_visible(row["case_id"], current_user() or {}):
            return error_response("ASSIGNMENT_NOT_FOUND", "المهمة غير متاحة بعد سحب عضوية القضية", 404)
        if operational_mode():
            from .autopsy_pipeline import job_visible

            if not job_visible(row["job_id"]):
                return error_response("ASSIGNMENT_NOT_FOUND", "دفعة المهمة غير متاحة", 404)
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


@teams_api.post("/api/team/members/<int:user_id>/deactivate")
@login_required
def deactivate_member(user_id: int):
    from .autopsy_domain import custody, text_value

    if not manager():
        return error_response("PERMISSION_DENIED", "إيقاف عضو وتسليم مسؤولياته للمدير فقط", 403)
    data = request.get_json(silent=True)
    try:
        if not isinstance(data, dict) or set(data) - {"handoff_to", "reason"}:
            raise ValueError("حدد سبب الإيقاف والبديل إن كانت هناك مسؤوليات")
        reason = text_value(data.get("reason"), 1000, True)
        target = data.get("handoff_to")
        if target is not None and (type(target) is not int or target == user_id):
            raise ValueError("حدد عضوًا آخر لتسليم المسؤوليات")
    except ValueError as exc:
        return error_response("INVALID_HANDOFF", str(exc), 422)
    with transaction():
        member = get_db().execute("SELECT id, role FROM users WHERE id = ? AND workspace_id = ? AND is_active = 1", (user_id, workspace_id())).fetchone()
        if not member or member["role"] == "admin":
            return error_response("MEMBER_NOT_FOUND", "العضو غير متاح", 404)
        if (
            member["role"] == "soc_manager"
            and get_db()
            .execute("SELECT COUNT(*) FROM users WHERE workspace_id = ? AND is_active = 1 AND role IN ('soc_manager', 'admin')", (workspace_id(),))
            .fetchone()[0]
            <= 1
        ):
            return error_response("LAST_MANAGER", "لا يمكن إيقاف آخر مدير", 409)
        cases = (
            get_db()
            .execute(
                "SELECT DISTINCT c.id FROM incident_cases c WHERE c.workspace_id = ? AND (c.assignee = ? OR EXISTS (SELECT 1 FROM case_tasks t WHERE t.case_id = c.id AND t.assignee = ? AND t.status NOT IN ('completed', 'reviewed')) OR EXISTS (SELECT 1 FROM autopsy_case_members m WHERE m.case_id = c.id AND m.user_id = ? AND m.responsibility = 'owner') OR EXISTS (SELECT 1 FROM autopsy_records r WHERE r.case_id = c.id AND ((r.kind = 'corrective' AND json_extract(r.payload, '$.owner_id') = ? AND json_extract(r.payload, '$.status') != 'validated') OR (r.kind = 'escalation' AND json_extract(r.payload, '$.to_user') = ? AND json_extract(r.payload, '$.status') IN ('raised', 'acknowledged'))))) ORDER BY c.id LIMIT 2001",
                (workspace_id(), user_id, user_id, user_id, user_id, user_id),
            )
            .fetchall()
        )
        if len(cases) > 2000:
            return error_response("HANDOFF_TOO_LARGE", "انقل المسؤوليات على دفعات قبل إيقاف العضو", 409)
        if cases and target is None:
            return error_response("HANDOFF_REQUIRED", "حدد بديلًا قبل سحب الوصول والمهام", 409)
        if target is not None:
            replacement = (
                get_db()
                .execute("SELECT id, role, workspace_id FROM users WHERE id = ? AND workspace_id = ? AND is_active = 1", (target, workspace_id()))
                .fetchone()
            )
            if not replacement:
                return error_response("HANDOFF_MEMBER_NOT_FOUND", "البديل غير متاح", 422)
            principal = dict(replacement)
            policy = (
                get_db()
                .execute("SELECT permissions FROM team_role_permissions WHERE workspace_id = ? AND role = ?", (workspace_id(), replacement["role"]))
                .fetchone()
            )
            if policy:
                principal["role_permissions"] = json.loads(policy[0])
            if not has_permission(principal, "cases.read") or not has_permission(principal, "cases.update"):
                return error_response("HANDOFF_PERMISSION_REQUIRED", "البديل يحتاج صلاحية قراءة القضية وتحديثها", 422)
            duplicate = (
                get_db()
                .execute(
                    "SELECT 1 FROM team_log_assignments a JOIN team_log_assignments b ON a.workspace_id = b.workspace_id AND a.job_id = b.job_id AND a.case_id = b.case_id WHERE a.workspace_id = ? AND a.assignee = ? AND b.assignee = ? AND a.state != 'completed' LIMIT 1",
                    (workspace_id(), user_id, target),
                )
                .fetchone()
            )
            if duplicate:
                return error_response("HANDOFF_ASSIGNMENT_CONFLICT", "البديل لديه إسناد لهذه الدفعة؛ اختر بديلًا آخر أو عالج الإسناد الحالي أولًا", 409)
            for case in cases:
                get_db().execute(
                    "INSERT INTO autopsy_case_members(case_id, user_id, responsibility, assigned_by, assigned_at) VALUES (?, ?, 'owner', ?, ?) ON CONFLICT(case_id, user_id) DO UPDATE SET responsibility = 'owner', assigned_by = excluded.assigned_by, assigned_at = excluded.assigned_at",
                    (case["id"], target, actor_id(), iso_now()),
                )
                get_db().execute(
                    "UPDATE incident_cases SET assignee = CASE WHEN assignee = ? THEN ? ELSE assignee END WHERE id = ?", (user_id, target, case["id"])
                )
                get_db().execute(
                    "UPDATE case_tasks SET assignee = ? WHERE case_id = ? AND assignee = ? AND status NOT IN ('completed', 'reviewed')",
                    (target, case["id"], user_id),
                )
                custody(case["id"], "member_responsibilities_handed_off", {"from": user_id, "to": target, "reason": reason})
                get_db().execute(
                    "INSERT OR IGNORE INTO autopsy_batch_members(job_id,user_id) SELECT j.id,? FROM ingestion_jobs j JOIN autopsy_batch_access a ON a.job_id=j.id AND a.restricted=1 WHERE j.case_id=? AND (j.created_by=? OR EXISTS (SELECT 1 FROM autopsy_batch_members m WHERE m.job_id=j.id AND m.user_id=?))",
                    (target, case["id"], user_id, user_id),
                )
                handoff_records(case["id"], user_id, target, reason)
            get_db().execute(
                "UPDATE team_log_assignments SET assignee = ? WHERE workspace_id = ? AND assignee = ? AND state != 'completed'",
                (target, workspace_id(), user_id),
            )
        get_db().execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
        get_db().execute("UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", (iso_now(), user_id))
        record_audit(get_db(), "deactivate", "user", user_id, details={"handoff_to": target, "reason": reason, "cases": len(cases)})
    return jsonify({"deactivated": True, "handoff_to": target, "cases_transferred": len(cases)})


def handoff_records(case_id, source, target, reason):
    from .autopsy_api import insert_record
    from .autopsy_domain import canonical, custody, touch_case

    target_role = get_db().execute("SELECT role FROM users WHERE id = ?", (target,)).fetchone()[0]
    target_level = {"analyst": "l1", "l1_analyst": "l1", "l2_responder": "l2", "investigator": "investigation"}.get(target_role, "management")

    rows = (
        get_db()
        .execute(
            "SELECT * FROM autopsy_records WHERE case_id = ? AND ((kind = 'corrective' AND json_extract(payload, '$.owner_id') = ? AND json_extract(payload, '$.status') != 'validated') OR (kind = 'escalation' AND json_extract(payload, '$.to_user') = ? AND json_extract(payload, '$.status') IN ('raised', 'acknowledged')))",
            (case_id, source, source),
        )
        .fetchall()
    )
    for row in rows:
        payload = json.loads(row["payload"])
        if row["kind"] == "corrective":
            payload["owner_id"] = target
        else:
            forwarded = {key: value for key, value in payload.items() if key not in {"acknowledged_at", "responded_at", "response"}}
            forwarded.update(
                to_user=target,
                from_user=actor_id(),
                from_level="management",
                to_level=target_level,
                raised_at=iso_now(),
                status="raised",
                reason=f"تسليم مسؤولية: {reason}. التصعيد السابق {row['id']}: {payload['reason']}"[:2000],
            )
            identifier = insert_record(case_id, "escalation", forwarded)
            payload.update(status="returned", response=f"أعاد المدير الإسناد في التصعيد {identifier}: {reason}")
        serialized, version = canonical(payload), row["version"] + 1
        get_db().execute(
            "UPDATE autopsy_records SET payload = ?, version = ?, updated_by = ?, updated_at = ? WHERE id = ?",
            (serialized, version, actor_id(), iso_now(), row["id"]),
        )
        get_db().execute(
            "INSERT INTO autopsy_record_revisions(record_id, version, payload, actor_id, created_at) VALUES (?, ?, ?, ?, ?)",
            (row["id"], version, serialized, actor_id(), iso_now()),
        )
        custody(case_id, "record_responsibility_handed_off", {"record_id": row["id"], "version": version, "from": source, "to": target, "reason": reason})
        touch_case(case_id)
