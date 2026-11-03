import hashlib
import json
from typing import Any

from flask import Blueprint, jsonify, request

from .autopsy_domain import KINDS, canonical, custody, member_has_open_work, text_value, touch_case, validate_record
from .case_counts import cached_case_count, consistent_read
from .cases import _case_row, _case_view, create_case, list_cases
from .db import get_db, inserted_id, transaction
from .security import actor_id, current_user, error_response, has_permission, require_permission, workspace_id
from .task_titles import task_view
from .timeutils import iso_now
from .validation import ValidationError, public_error_message

autopsy_api = Blueprint("autopsy", __name__)


def manager() -> bool:
    return (current_user() or {}).get("role") in {"admin", "soc_manager"}


def validate_escalation_routing(payload):
    levels = {
        "monitoring": {"analyst", "l1_analyst"},
        "l1": {"analyst", "l1_analyst"},
        "l2": {"l2_responder"},
        "investigation": {"investigator"},
        "management": {"soc_manager", "admin"},
    }
    if not manager() and (current_user() or {}).get("role") not in levels[payload["from_level"]]:
        raise ValidationError("مستوى إرسال التصعيد لا يطابق دورك")
    target = get_db().execute("SELECT id, role, workspace_id FROM users WHERE id = ? AND is_active = 1", (payload["to_user"],)).fetchone()
    if target is None or target["role"] not in levels[payload["to_level"]] | {"admin", "soc_manager"}:
        raise ValidationError("دور المستلم لا يطابق مستوى التصعيد")
    principal = dict(target)
    policy = (
        get_db()
        .execute("SELECT permissions FROM team_role_permissions WHERE workspace_id = ? AND role = ?", (target["workspace_id"], target["role"]))
        .fetchone()
    )
    if policy:
        principal["role_permissions"] = json.loads(policy[0])
    if not has_permission(principal, "cases.read") or not has_permission(principal, "cases.update"):
        raise ValidationError("مستقبل التصعيد يحتاج صلاحية قراءة القضية وتحديثها")


def record_view(row) -> dict[str, Any]:
    return {**dict(row), "payload": json.loads(row["payload"])}


def records_for_case(case_id: int, kind: str | None = None, limit: int = 100, before: int | None = None, query: str = "", focus: int | None = None):
    clauses = ["case_id = ?"]
    args: list[Any] = [case_id]
    if kind:
        clauses.append("kind = ?")
        args.append(kind)
    if before:
        clauses.append("id < ?")
        args.append(before)
    if focus is not None:
        clauses.append("id = ?")
        args.append(focus)
    if query:
        clauses.append(
            "LOWER(COALESCE(json_extract(payload, '$.title'), json_extract(payload, '$.conclusion'), json_extract(payload, '$.name'), '')) LIKE ? ESCAPE '\\'"
        )
        args.append("%" + query.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    if not manager():
        clauses.append("(COALESCE(json_extract(payload, '$.visibility'), 'team') != 'private' OR created_by = ?)")
        args.append(actor_id())
    rows = get_db().execute(f"SELECT * FROM autopsy_records WHERE {' AND '.join(clauses)} ORDER BY id DESC LIMIT ?", (*args, limit)).fetchall()
    return [record_view(row) for row in rows]


def insert_record(case_id: int, kind: str, payload: dict[str, Any], actor: int | None = None) -> int:
    now = iso_now()
    serialized = canonical(payload)
    principal = actor if actor is not None else actor_id()
    record_id = inserted_id(
        get_db().execute(
            "INSERT INTO autopsy_records(case_id, kind, payload, created_by, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (case_id, kind, serialized, principal, principal, now, now),
        )
    )
    get_db().execute(
        "INSERT INTO autopsy_record_revisions(record_id, version, payload, actor_id, created_at) VALUES (?, 1, ?, ?, ?)",
        (record_id, serialized, principal, now),
    )
    custody(case_id, "record_added", {"record_id": record_id, "kind": kind, "sha256": hashlib.sha256(serialized.encode()).hexdigest()}, actor=principal)
    touch_case(case_id)
    return record_id


@consistent_read
def case_summary(case_id: int):
    case = _case_row(case_id)
    if not case:
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    result = _case_view(case)
    from flask import current_app

    from .autopsy_workspace import can_review, case_approved, selected_ids

    result["can_review_request"] = can_review()
    result["approval_enforced"] = current_app.config["REQUIRE_CASE_APPROVAL"]
    result["selection_required"] = current_app.config["REQUIRE_INVESTIGATION_SELECTION"] and case_id not in selected_ids()
    if not case_approved(case_id) or result["selection_required"]:
        result.update(
            counts={}, members=[], tasks=[], history=[], evidence=[], reports=[], archived_reports=[], can_manage=False, can_update=False, can_approve=False
        )
        return jsonify(result)
    if not result.get("full_case_access", True):
        from .autopsy_pipeline import visibility_sql

        scope, args = visibility_sql("ce")
        count = (
            get_db().execute(f"SELECT COUNT(*) FROM case_events ce WHERE ce.case_id = ? AND ce.active_event = 1 AND {scope}", (case_id, *args)).fetchone()[0]
        )
        result.update(
            counts={"events": count, "evidence": 0, "tasks": 0, "records": 0},
            members=[],
            tasks=[],
            history=[],
            evidence=[],
            reports=[],
            archived_reports=[],
            can_manage=False,
            can_update=False,
            can_approve=False,
        )
        return jsonify(result)
    result["counts"] = {
        name: get_db().execute(f"SELECT COUNT(*) FROM {table} WHERE case_id = ?", (case_id,)).fetchone()[0]
        for name, table in [("evidence", "case_evidence"), ("tasks", "case_tasks"), ("records", "autopsy_records")]
    }
    if not manager():
        result["counts"]["records"] = (
            get_db()
            .execute(
                "SELECT COUNT(*) FROM autopsy_records WHERE case_id = ? AND (COALESCE(json_extract(payload, '$.visibility'), 'team') != 'private' OR created_by = ?)",
                (case_id, actor_id()),
            )
            .fetchone()[0]
        )
    count = cached_case_count(case_id)
    result["counts"]["events"] = (
        count if count is not None else get_db().execute("SELECT COUNT(*) FROM case_events WHERE case_id = ? AND active_event = 1", (case_id,)).fetchone()[0]
    )
    result["members"] = [
        dict(row)
        for row in get_db()
        .execute(
            "SELECT m.*, socify_user_name(u.name,u.name_ar,u.name_en) AS name, u.role FROM autopsy_case_members m JOIN users u ON u.id = m.user_id WHERE m.case_id = ? ORDER BY u.name",
            (case_id,),
        )
        .fetchall()
    ]
    result["tasks"] = [
        task_view(row)
        for row in get_db()
        .execute(
            "SELECT t.*, a.id AS assignment_id, socify_user_name(u.name,u.name_ar,u.name_en) AS assignee_name FROM case_tasks t LEFT JOIN team_log_assignments a ON a.task_id=t.id LEFT JOIN users u ON u.id=t.assignee WHERE t.case_id=? ORDER BY t.id DESC LIMIT 100",
            (case_id,),
        )
        .fetchall()
    ]
    result["history"] = [
        dict(row)
        for row in get_db()
        .execute(
            "SELECT h.*, socify_user_name(u.name,u.name_ar,u.name_en) AS actor_name FROM case_history h LEFT JOIN users u ON u.id = h.actor_id WHERE h.case_id = ? ORDER BY h.id DESC LIMIT 100",
            (case_id,),
        )
        .fetchall()
    ]
    result["evidence"] = [
        dict(row)
        for row in get_db()
        .execute("SELECT id, evidence_type, title, sha256, added_at FROM case_evidence WHERE case_id = ? ORDER BY id DESC LIMIT 100", (case_id,))
        .fetchall()
    ]
    result["reports"] = [
        dict(row)
        for row in get_db()
        .execute(
            "SELECT id, revision, sha256, source_version, state, created_at, approved_at FROM autopsy_reports WHERE case_id = ? ORDER BY revision DESC LIMIT 100",
            (case_id,),
        )
        .fetchall()
    ]
    result["archived_reports"] = [
        dict(row)
        for row in get_db().execute(
            "SELECT id, revision, format, sha256, created_at FROM case_reports WHERE case_id = ? ORDER BY revision DESC, format LIMIT 100", (case_id,)
        )
    ]
    result["can_manage"] = manager()
    result["can_update"] = has_permission(current_user(), "cases.update")
    for task in result["tasks"]:
        task["can_update"] = bool(
            result["can_update"] and result["status"] != "closed" and (not task["assignment_id"] or task["assignee"] == actor_id() or manager())
        )
    result["can_approve"] = has_permission(current_user(), "reports.approve")
    return jsonify(result)


@autopsy_api.get("/api/cases/<int:case_id>/tasks")
@require_permission("cases.read")
@consistent_read
def case_task_list(case_id: int):
    case = _case_row(case_id)
    if not case:
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    try:
        if set(request.args) - {"q", "status", "page", "focus"} or any(len(request.args.getlist(key)) != 1 for key in request.args):
            raise ValueError
        query, status = request.args.get("q", "").strip(), request.args.get("status", "")
        page_text, focus_text = request.args.get("page", "1"), request.args.get("focus", "")
        if len(query) > 200 or status not in {"", "pending", "in_progress", "completed", "reviewed"}:
            raise ValueError
        if len(page_text) > 7 or not page_text.isascii() or not page_text.isdecimal() or not 1 <= int(page_text) <= 1000000:
            raise ValueError
        if focus_text and (len(focus_text) > 19 or not focus_text.isascii() or not focus_text.isdecimal() or not 1 <= int(focus_text) <= 2**63 - 1):
            raise ValueError
        page, focus = int(page_text), int(focus_text) if focus_text else None
    except ValueError:
        return error_response("INVALID_TASK_FILTER", "حدد مرشحات المهام الصحيحة", 422)
    where = "t.case_id=?"
    args: list[object] = [case_id]
    if status:
        where += " AND t.status=?"
        args.append(status)
    if query:
        where += " AND (LOWER(t.title) LIKE ? ESCAPE '\\' OR LOWER(socify_task_title(t.title,t.system_key)) LIKE ? ESCAPE '\\')"
        pattern = "%" + query.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        args.extend([pattern, pattern])
    total = get_db().execute(f"SELECT COUNT(*) FROM case_tasks t WHERE {where}", args).fetchone()[0]
    page_size = 25
    if focus is not None:
        if not get_db().execute(f"SELECT 1 FROM case_tasks t WHERE {where} AND t.id=?", (*args, focus)).fetchone():
            return error_response("TASK_NOT_FOUND", "المهمة غير متاحة", 404)
        preceding = get_db().execute(f"SELECT COUNT(*) FROM case_tasks t WHERE {where} AND t.id>?", (*args, focus)).fetchone()[0]
        page = preceding // page_size + 1
    else:
        page = min(page, max(1, (total + page_size - 1) // page_size))
    rows = (
        get_db()
        .execute(
            f"SELECT t.*, a.id AS assignment_id, socify_user_name(u.name,u.name_ar,u.name_en) AS assignee_name FROM case_tasks t LEFT JOIN team_log_assignments a ON a.task_id=t.id LEFT JOIN users u ON u.id=t.assignee WHERE {where} ORDER BY t.id DESC LIMIT ? OFFSET ?",
            (*args, page_size, (page - 1) * page_size),
        )
        .fetchall()
    )
    can_update = has_permission(current_user(), "cases.update") and case["status"] != "closed"
    items = [{**task_view(row), "can_update": bool(can_update and (not row["assignment_id"] or row["assignee"] == actor_id() or manager()))} for row in rows]
    return jsonify({"items": items, "total": total, "page": page, "page_size": page_size, "focus": focus})


@autopsy_api.get("/api/cases")
@require_permission("cases.read")
def cases_list():
    return list_cases()


@autopsy_api.post("/api/cases")
@require_permission("cases.create")
def cases_create():
    return create_case()


@autopsy_api.get("/api/cases/claimable")
@require_permission("cases.update")
def cases_claimable():
    from .autopsy_workspace import case_approved

    rows = (
        get_db()
        .execute(
            """SELECT c.id, c.reference, c.title, c.severity, c.priority, c.status, c.created_at, c.updated_at,
                      COALESCE(ctx.classification, 'confidential') AS classification, socify_user_name(u.name,u.name_ar,u.name_en) AS creator_name
               FROM incident_cases c
               LEFT JOIN autopsy_case_context ctx ON ctx.case_id = c.id
               LEFT JOIN users u ON u.id = c.creator
               WHERE c.workspace_id = ?
                 AND c.archived_at IS NULL
                 AND c.assignee IS NULL
                 AND c.status NOT IN ('closed', 'cancelled')
                 AND COALESCE(ctx.classification, 'confidential') != 'restricted'
               ORDER BY c.updated_at DESC
               LIMIT 100""",
            (workspace_id(),),
        )
        .fetchall()
    )
    items = [dict(row) for row in rows if case_approved(int(row["id"]))]
    return jsonify({"items": items, "total": len(items)})


@autopsy_api.post("/api/cases/<int:case_id>/claim")
@require_permission("cases.update")
def case_claim(case_id: int):
    from .audit import record_audit
    from .autopsy_workspace import case_approved
    from .cases import _history

    with transaction():
        row = (
            get_db()
            .execute(
                """SELECT c.*, COALESCE(ctx.classification, 'confidential') AS classification
                   FROM incident_cases c
                   LEFT JOIN autopsy_case_context ctx ON ctx.case_id = c.id
                   WHERE c.id = ? AND c.workspace_id = ? AND c.archived_at IS NULL""",
                (case_id, workspace_id()),
            )
            .fetchone()
        )
        if not row or (row["classification"] == "restricted" and not _case_row(case_id)):
            return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
        if not case_approved(case_id):
            return error_response("CASE_APPROVAL_REQUIRED", "بانتظار اعتماد المدير؛ أعمال القضية مقفلة", 409)
        if row["status"] in {"closed", "cancelled"}:
            return error_response("CASE_CLOSED", "لا يمكن استلام ملكية قضية مغلقة أو ملغاة", 409)
        current_actor = actor_id()
        if row["assignee"] is not None and int(row["assignee"]) != int(current_actor or 0):
            return error_response("CASE_ALREADY_CLAIMED", "تم استلام ملكية هذه القضية بالفعل من محلل آخر", 409)
        now = iso_now()
        new_status = "investigating" if row["status"] in {"new", "open"} else row["status"]
        updated = get_db().execute(
            "UPDATE incident_cases SET assignee = ?, status = ?, updated_at = ?, version = version + 1 WHERE id = ? AND workspace_id = ? AND (assignee IS NULL OR assignee = ?)",
            (current_actor, new_status, now, case_id, workspace_id(), current_actor),
        )
        if updated.rowcount != 1:
            return error_response("CASE_ALREADY_CLAIMED", "تم استلام ملكية هذه القضية بالفعل من محلل آخر", 409)
        get_db().execute(
            "INSERT INTO autopsy_case_members(case_id, user_id, responsibility, assigned_by, assigned_at) VALUES (?, ?, 'owner', ?, ?) ON CONFLICT(case_id, user_id) DO UPDATE SET responsibility = 'owner', assigned_by = excluded.assigned_by, assigned_at = excluded.assigned_at",
            (case_id, current_actor, current_actor, now),
        )
        get_db().execute("UPDATE case_tasks SET assignee = ? WHERE case_id = ? AND assignee IS NULL", (current_actor, case_id))
        _history(
            get_db(),
            case_id,
            "case_claimed",
            {"assignee": row["assignee"], "status": row["status"]},
            {"assignee": current_actor, "status": new_status},
            "Claimed case ownership",
        )
        custody(case_id, "case_claimed", {"owner": current_actor, "status": new_status})
        record_audit(get_db(), "claim", "case", case_id, details={"owner": current_actor})
    return case_summary(case_id)


@autopsy_api.get("/api/cases/<int:case_id>")
@require_permission("cases.read")
def case_get(case_id: int):
    return case_summary(case_id)


@autopsy_api.get("/api/autopsy/catalog")
@require_permission("cases.read")
def catalog():
    from zoneinfo import available_timezones

    from .autopsy_report_render import LABELS
    from .autopsy_reports import STATES
    from .security import ROLE_PERMISSIONS

    return jsonify(
        {
            "product": "SOCify Tactical Workbench",
            "import_formats": ["auto", "csv", "json", "jsonl", "zeek_tsv", "syslog", "cef", "linux_auth", "web", "sysmon_xml", "evtx", "pcap", "pcapng"],
            "source_timezones": sorted(available_timezones()),
            "mapping_fields": [
                "event_time",
                "title",
                "event_type",
                "severity",
                "source_ip",
                "destination_ip",
                "hostname",
                "username",
                "process_name",
                "parent_process",
                "file_hash",
                "http_status",
                "action",
                "outcome",
            ],
            "network_policy": "offline-only",
            "case_transitions": {key: sorted(value) for key, value in STATES.items()},
            "record_schemas": KINDS,
            "report_labels": LABELS,
            "roles": [role for role in ROLE_PERMISSIONS if role not in {"instructor", "analyst", "auditor"}],
            "reasons": ["alert_review", "suspicious_activity", "threat_hunt", "user_report", "forensic_review", "other"],
            "classifications": ["internal", "confidential", "restricted"],
            "outcomes": ["successful", "blocked", "partial", "unknown"],
            "verdicts": ["malicious", "benign", "false_positive", "undetermined"],
        }
    )


@autopsy_api.patch("/api/cases/<int:case_id>/context")
@require_permission("cases.update")
def update_context(case_id: int):
    data = request.get_json(silent=True)
    fields = {"reason", "objective", "classification", "attack_outcome", "alert_verdict", "legal_hold", "retention_until"}
    if not isinstance(data, dict) or set(data) - (fields | {"version"}) or type(data.get("version")) is not int:
        return error_response("INVALID_CASE_CONTEXT", "أرسل إصدار القضية والحقول المعروفة فقط", 422)
    with transaction():
        case = _case_row(case_id)
        if not case:
            return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
        if case["version"] != data["version"]:
            return error_response("CASE_VERSION_CONFLICT", "حدّث القضية قبل الحفظ", 409)
        if case["status"] == "closed":
            return error_response("CASE_CLOSED", "أعد فتح القضية قبل تعديل نتائجها", 409)
        old = get_db().execute("SELECT * FROM autopsy_case_context WHERE case_id = ?", (case_id,)).fetchone()
        result = (
            dict(old)
            if old
            else {
                "case_id": case_id,
                "reason": "",
                "objective": "",
                "classification": "confidential",
                "attack_outcome": "unknown",
                "alert_verdict": "undetermined",
                "legal_hold": 0,
                "retention_until": None,
                "created_at": iso_now(),
            }
        )
        try:
            for key in fields & data.keys():
                value = data[key]
                if key == "legal_hold":
                    if type(value) is not bool or not manager():
                        raise ValidationError("تغيير الحفظ القانوني للمدير فقط")
                    result[key] = int(value)
                elif key == "retention_until":
                    from .timeutils import iso_timestamp

                    if not manager() or not isinstance(value, str):
                        raise ValidationError("سياسة الاحتفاظ للمدير فقط")
                    result[key] = iso_timestamp(value)
                else:
                    result[key] = text_value(value, 2000 if key == "objective" else 500, True)
            choices = {
                "classification": {"internal", "confidential", "restricted"},
                "attack_outcome": {"successful", "blocked", "partial", "unknown"},
                "alert_verdict": {"malicious", "benign", "false_positive", "undetermined"},
            }
            if any(result[key] not in allowed for key, allowed in choices.items()) or not result["reason"] or not result["objective"]:
                raise ValidationError("سبب القضية وهدفها واختياراتها مطلوبة وصالحة")
        except ValueError as exc:
            return error_response("INVALID_CASE_CONTEXT", public_error_message(exc, "تحقق من حقول القضية"), 422)
        get_db().execute(
            "INSERT INTO autopsy_case_context(case_id, reason, objective, classification, attack_outcome, alert_verdict, legal_hold, retention_until, created_at) VALUES (:case_id, :reason, :objective, :classification, :attack_outcome, :alert_verdict, :legal_hold, :retention_until, :created_at) ON CONFLICT(case_id) DO UPDATE SET reason=excluded.reason, objective=excluded.objective, classification=excluded.classification, attack_outcome=excluded.attack_outcome, alert_verdict=excluded.alert_verdict, legal_hold=excluded.legal_hold, retention_until=excluded.retention_until",
            result,
        )
        custody(case_id, "context_updated", {"fields": sorted(fields & data.keys())})
        touch_case(case_id)
    return case_summary(case_id)


@autopsy_api.get("/api/cases/<int:case_id>/records")
@require_permission("cases.read")
@consistent_read
def records_list(case_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    try:
        limit = int(request.args.get("limit", 50))
        before = int(request.args["before"]) if "before" in request.args else None
        focus = int(request.args["focus"]) if "focus" in request.args else None
        query = request.args.get("q", "").strip()
        if (
            not 1 <= limit <= 100
            or any(value is not None and not 1 <= value <= 2**63 - 1 for value in (before, focus))
            or len(query) > 200
            or any(len(request.args.getlist(key)) != 1 for key in request.args)
        ):
            raise ValueError
    except ValueError:
        return error_response("INVALID_PAGINATION", "قيم الترقيم غير صالحة", 422)
    kind = request.args.get("kind")
    if kind and kind not in KINDS and kind not in {"playbook", "reputation", "analysis"}:
        return error_response("INVALID_RECORD_KIND", "نوع السجل غير صالح", 422)
    items = records_for_case(case_id, kind, limit + 1, before, query, focus)
    if focus is not None and not items:
        return error_response("RECORD_NOT_FOUND", "مرجع نتيجة التحقيق غير متاح", 404)
    return jsonify({"items": items[:limit], "next_before": items[limit - 1]["id"] if len(items) > limit else None})


@autopsy_api.post("/api/cases/<int:case_id>/records/<kind>")
@require_permission("cases.update")
def record_create(case_id: int, kind: str):
    with transaction():
        case = _case_row(case_id)
        if not case:
            return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
        if case["status"] == "closed" and kind != "corrective":
            return error_response("CASE_CLOSED", "القضية مغلقة", 409)
        try:
            payload = validate_record(case_id, kind, request.get_json(silent=True))
            if kind == "escalation":
                validate_escalation_routing(payload)
                if payload["status"] != "raised":
                    raise ValidationError("يبدأ التصعيد بحالة raised")
                payload.update({"from_user": actor_id(), "raised_at": iso_now()})
                get_db().execute(
                    "INSERT INTO autopsy_case_members(case_id, user_id, responsibility, assigned_by, assigned_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(case_id, user_id) DO NOTHING",
                    (case_id, payload["to_user"], payload["to_level"], actor_id(), iso_now()),
                )
        except (ValueError, UnicodeError) as exc:
            return error_response("INVALID_RECORD", public_error_message(exc, "تحقق من حقول السجل"), 422)
        if kind == "indicator":
            duplicate = (
                get_db()
                .execute(
                    "SELECT id FROM autopsy_records WHERE case_id = ? AND kind = 'indicator' AND json_extract(payload, '$.type') = ? AND json_extract(payload, '$.value') = ?",
                    (case_id, payload["type"], payload["value"]),
                )
                .fetchone()
            )
            if duplicate:
                return error_response("DUPLICATE_INDICATOR", "المؤشر موجود في القضية", 409, {"record_id": duplicate["id"]})
        record_id = insert_record(case_id, kind, payload)
    return jsonify({"id": record_id, "kind": kind, "payload": payload, "version": 1}), 201


@autopsy_api.patch("/api/cases/<int:case_id>/records/<int:record_id>")
@require_permission("cases.update")
def record_update(case_id: int, record_id: int):
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) != {"version", "payload"} or type(data["version"]) is not int:
        return error_response("INVALID_RECORD", "أرسل إصدار السجل وبياناته فقط", 422)
    with transaction():
        case = _case_row(case_id)
        if not case:
            return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
        row = get_db().execute("SELECT * FROM autopsy_records WHERE id = ? AND case_id = ?", (record_id, case_id)).fetchone()
        if not row:
            return error_response("RECORD_NOT_FOUND", "السجل غير متاح", 404)
        if case["status"] == "closed" and row["kind"] != "corrective":
            return error_response("CASE_CLOSED", "القضية مغلقة", 409)
        if row["version"] != data["version"]:
            return error_response("RECORD_VERSION_CONFLICT", "تغير السجل؛ حدّث الصفحة", 409)
        previous = json.loads(row["payload"])
        if previous.get("visibility") == "private" and row["created_by"] != actor_id() and not manager():
            return error_response("RECORD_NOT_FOUND", "السجل غير متاح", 404)
        try:
            payload = validate_record(case_id, row["kind"], data["payload"])
            if row["kind"] == "escalation":
                if any(payload[key] != previous[key] for key in ("to_user", "from_level", "to_level")):
                    raise ValidationError("حافظ على مسار التصعيد؛ أضف تصعيدًا جديدًا أو سلّم المسؤوليات من إدارة الفريق")
                if not manager() and previous["to_user"] != actor_id():
                    return error_response("PERMISSION_DENIED", "الإقرار والاستجابة لمتلقي التصعيد أو المدير", 403)
                transitions = {
                    "raised": {"raised", "acknowledged", "returned"},
                    "acknowledged": {"acknowledged", "resolved", "returned"},
                    "returned": {"returned", "raised"},
                    "resolved": {"resolved"},
                }
                if payload["status"] not in transitions[previous["status"]]:
                    raise ValidationError("انتقال التصعيد غير مسموح")
                payload.update({key: value for key, value in previous.items() if key in {"from_user", "raised_at", "acknowledged_at", "responded_at"}})
                if payload["status"] == "acknowledged" and not payload.get("acknowledged_at"):
                    payload["acknowledged_at"] = iso_now()
                if payload["status"] == "resolved":
                    if not payload.get("response"):
                        raise ValidationError("سجل الاستجابة قبل إتمام التصعيد")
                    payload.setdefault("responded_at", iso_now())
        except (ValueError, UnicodeError) as exc:
            return error_response("INVALID_RECORD", public_error_message(exc, "تحقق من حقول السجل"), 422)
        serialized = canonical(payload)
        if row["kind"] == "root_cause":
            branch_ids = {item["id"] for item in payload.get("whys", [])}
            linked_branches = get_db().execute(
                "SELECT json_extract(payload, '$.why_id') AS why_id FROM autopsy_records "
                "WHERE case_id = ? AND kind = 'corrective' AND json_extract(payload, '$.root_cause_id') = ? "
                "AND json_extract(payload, '$.why_id') IS NOT NULL",
                (case_id, record_id),
            )
            if any(link["why_id"] not in branch_ids for link in linked_branches):
                return error_response("CAUSE_BRANCH_IN_USE", "أعد ربط الإجراء التصحيحي أو أزل ارتباطه قبل حذف فرع السبب", 409)
        version = row["version"] + 1
        get_db().execute(
            "UPDATE autopsy_records SET payload = ?, version = ?, updated_by = ?, updated_at = ? WHERE id = ?",
            (serialized, version, actor_id(), iso_now(), record_id),
        )
        get_db().execute(
            "INSERT INTO autopsy_record_revisions(record_id, version, payload, actor_id, created_at) VALUES (?, ?, ?, ?, ?)",
            (record_id, version, serialized, actor_id(), iso_now()),
        )
        custody(case_id, "record_updated", {"record_id": record_id, "version": version, "sha256": hashlib.sha256(serialized.encode()).hexdigest()})
        touch_case(case_id)
    return jsonify({"id": record_id, "payload": payload, "version": version})


@autopsy_api.post("/api/cases/<int:case_id>/members")
@require_permission("cases.assign")
def case_member(case_id: int):
    data = request.get_json(silent=True)
    if (
        not isinstance(data, dict)
        or set(data) - {"user_id", "responsibility", "version"}
        or type(data.get("user_id")) is not int
        or not 1 <= data["user_id"] <= 9223372036854775807
        or ("version" in data and (type(data["version"]) is not int or not 1 <= data["version"] <= 9223372036854775807))
        or not isinstance(data.get("responsibility"), str)
        or data.get("responsibility") not in {"monitoring", "l1", "l2", "investigator", "reviewer", "owner"}
    ):
        return error_response("INVALID_MEMBER", "حدد العضو ومسؤوليته", 422)
    with transaction():
        case = _case_row(case_id)
        if not case:
            return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
        user = get_db().execute("SELECT id FROM users WHERE id = ? AND workspace_id = ? AND is_active = 1", (data["user_id"], workspace_id())).fetchone()
        if not user:
            return error_response("MEMBER_NOT_FOUND", "العضو غير متاح", 404)
        if "version" in data and case["version"] != data["version"]:
            return error_response("CASE_VERSION_CONFLICT", "تغيرت القضية؛ حدّث قبل الحفظ", 409)
        get_db().execute(
            "INSERT INTO autopsy_case_members(case_id, user_id, responsibility, assigned_by, assigned_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(case_id, user_id) DO UPDATE SET responsibility = excluded.responsibility, assigned_by = excluded.assigned_by, assigned_at = excluded.assigned_at",
            (case_id, data["user_id"], data["responsibility"], actor_id(), iso_now()),
        )
        if data["responsibility"] == "owner":
            get_db().execute("UPDATE incident_cases SET assignee = ? WHERE id = ?", (data["user_id"], case_id))
        custody(case_id, "member_assigned", {"user_id": data["user_id"], "responsibility": data["responsibility"]})
        touch_case(case_id)
    return case_summary(case_id)


@autopsy_api.delete("/api/cases/<int:case_id>/members/<int:user_id>")
@require_permission("cases.assign")
def remove_case_member(case_id: int, user_id: int):
    from .operational import operational_mode

    if not operational_mode() or not manager():
        return error_response("PERMISSION_DENIED", "سحب وصول القضية للمدير المخول فقط", 403)
    data = request.get_json(silent=True)
    try:
        if not isinstance(data, dict) or set(data) != {"version", "reason"}:
            raise ValidationError("حدد سبب سحب الوصول وحالة القضية الحالية")
        if type(data["version"]) is not int or not 1 <= data["version"] <= 9223372036854775807:
            raise ValidationError("حدد سبب سحب الوصول وحالة القضية الحالية")
        reason = text_value(data["reason"], 1000, True)
    except ValueError as exc:
        return error_response("INVALID_MEMBER_REMOVAL", public_error_message(exc, "حدد سبب سحب الوصول وحالة القضية الحالية"), 422)
    with transaction():
        case = _case_row(case_id)
        if not case:
            return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
        if not 1 <= user_id <= 9223372036854775807:
            return error_response("MEMBER_NOT_FOUND", "العضو غير متاح", 404)
        user = get_db().execute("SELECT role FROM users WHERE id=? AND workspace_id=?", (user_id, workspace_id())).fetchone()
        if not user:
            return error_response("MEMBER_NOT_FOUND", "العضو غير متاح", 404)
        if user["role"] in {"admin", "soc_manager"}:
            return error_response("INHERITED_CASE_ACCESS", "صلاحية المدير تشمل جميع القضايا؛ غيّر دوره من إدارة الفريق أولًا", 409)
        if not get_db().execute("SELECT 1 FROM autopsy_case_context WHERE case_id=?", (case_id,)).fetchone():
            return error_response("LEGACY_CASE_ACCESS", "تتطلب هذه القضية مراجعة صلاحياتها قبل سحب الوصول", 409)
        member = get_db().execute("SELECT responsibility FROM autopsy_case_members WHERE case_id=? AND user_id=?", (case_id, user_id)).fetchone()
        # A lost acknowledgement can be retried. A subsequent grant creates a new
        # membership and must still pass the original case-version guard below.
        if not member:
            return jsonify({"removed": True, "user_id": user_id})
        if case["version"] != data["version"]:
            return error_response("CASE_VERSION_CONFLICT", "تغيرت القضية؛ حدّث قبل الحفظ", 409)
        owns_open_case = case["status"] != "closed" and (case["assignee"] == user_id or member["responsibility"] == "owner")
        if member_has_open_work(case_id, user_id) or owns_open_case:
            return error_response("CASE_MEMBER_HAS_WORK", "سلّم مسؤوليات العضو عبر تسليم المناوبة قبل سحب وصوله", 409)
        get_db().execute("DELETE FROM autopsy_batch_members WHERE user_id=? AND job_id IN (SELECT id FROM ingestion_jobs WHERE case_id=?)", (user_id, case_id))
        get_db().execute("DELETE FROM autopsy_case_members WHERE case_id=? AND user_id=?", (case_id, user_id))
        custody(case_id, "member_access_revoked", {"user_id": user_id, "responsibility": member["responsibility"], "reason": reason})
        touch_case(case_id)
    return jsonify({"removed": True, "user_id": user_id})


@autopsy_api.get("/api/cases/<int:case_id>/custody")
@require_permission("cases.read")
def case_custody(case_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    rows = get_db().execute("SELECT * FROM autopsy_custody WHERE case_id = ? ORDER BY id", (case_id,)).fetchall()
    previous, valid = "0" * 64, True
    for row in rows:
        digest = hashlib.sha256(
            canonical([case_id, row["actor_id"], row["action"], row["details"], row["previous_hash"], row["created_at"]]).encode()
        ).hexdigest()
        valid = valid and row["previous_hash"] == previous and row["entry_hash"] == digest
        previous = row["entry_hash"]
    return jsonify(
        {
            "items": [{**dict(row), "details": json.loads(row["details"])} for row in rows[-100:]],
            "total": len(rows),
            "integrity_valid": valid,
            "scope": "hash chain; not proof against a privileged database administrator",
        }
    )
