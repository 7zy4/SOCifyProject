import hashlib
import json
from typing import Any

from flask import Blueprint, jsonify, request

from .autopsy_domain import KINDS, canonical, custody, text_value, touch_case, validate_record
from .case_counts import cached_case_count, consistent_read
from .cases import _case_row, _case_view, create_case, list_cases
from .db import get_db, inserted_id, transaction
from .security import actor_id, current_user, error_response, has_permission, require_permission, workspace_id
from .timeutils import iso_now

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
        raise ValueError("مستوى إرسال التصعيد لا يطابق دورك")
    target = get_db().execute("SELECT id, role, workspace_id FROM users WHERE id = ? AND is_active = 1", (payload["to_user"],)).fetchone()
    if target is None or target["role"] not in levels[payload["to_level"]] | {"admin", "soc_manager"}:
        raise ValueError("دور المستلم لا يطابق مستوى التصعيد")
    principal = dict(target)
    policy = (
        get_db()
        .execute("SELECT permissions FROM team_role_permissions WHERE workspace_id = ? AND role = ?", (target["workspace_id"], target["role"]))
        .fetchone()
    )
    if policy:
        principal["role_permissions"] = json.loads(policy[0])
    if not has_permission(principal, "cases.read") or not has_permission(principal, "cases.update"):
        raise ValueError("مستقبل التصعيد يحتاج صلاحية قراءة القضية وتحديثها")


def record_view(row) -> dict[str, Any]:
    return {**dict(row), "payload": json.loads(row["payload"])}


def records_for_case(case_id: int, kind: str | None = None, limit: int = 100, before: int | None = None):
    clauses = ["case_id = ?"]
    args: list[Any] = [case_id]
    if kind:
        clauses.append("kind = ?")
        args.append(kind)
    if before:
        clauses.append("id < ?")
        args.append(before)
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
        result.update(counts={}, members=[], tasks=[], history=[], evidence=[], reports=[], archived_reports=[], can_manage=False, can_update=False, can_approve=False)
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
        .execute("SELECT m.*, u.name, u.role FROM autopsy_case_members m JOIN users u ON u.id = m.user_id WHERE m.case_id = ? ORDER BY u.name", (case_id,))
        .fetchall()
    ]
    result["tasks"] = [dict(row) for row in get_db().execute("SELECT * FROM case_tasks WHERE case_id = ? ORDER BY id DESC LIMIT 100", (case_id,)).fetchall()]
    result["history"] = [
        dict(row)
        for row in get_db()
        .execute(
            "SELECT h.*, u.name AS actor_name FROM case_history h LEFT JOIN users u ON u.id = h.actor_id WHERE h.case_id = ? ORDER BY h.id DESC LIMIT 100",
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
    result["can_approve"] = has_permission(current_user(), "reports.approve")
    return jsonify(result)


@autopsy_api.get("/api/cases")
@require_permission("cases.read")
def cases_list():
    return list_cases()


@autopsy_api.post("/api/cases")
@require_permission("cases.create")
def cases_create():
    return create_case()


@autopsy_api.get("/api/cases/<int:case_id>")
@require_permission("cases.read")
def case_get(case_id: int):
    return case_summary(case_id)


@autopsy_api.get("/api/autopsy/catalog")
@require_permission("cases.read")
def catalog():
    from zoneinfo import available_timezones

    from .autopsy_reports import STATES
    from .security import ROLE_PERMISSIONS

    return jsonify(
        {
            "product": "SOCify Digital Autopsy",
            "import_formats": ["auto", "csv", "json", "jsonl", "syslog", "linux_auth", "web", "sysmon_xml", "evtx", "pcap", "pcapng"],
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
                        raise ValueError("تغيير الحفظ القانوني للمدير فقط")
                    result[key] = int(value)
                elif key == "retention_until":
                    from .timeutils import iso_timestamp

                    if not manager() or not isinstance(value, str):
                        raise ValueError("سياسة الاحتفاظ للمدير فقط")
                    result[key] = iso_timestamp(value)
                else:
                    result[key] = text_value(value, 2000 if key == "objective" else 500, True)
            choices = {
                "classification": {"internal", "confidential", "restricted"},
                "attack_outcome": {"successful", "blocked", "partial", "unknown"},
                "alert_verdict": {"malicious", "benign", "false_positive", "undetermined"},
            }
            if any(result[key] not in allowed for key, allowed in choices.items()) or not result["reason"] or not result["objective"]:
                raise ValueError("سبب القضية وهدفها واختياراتها مطلوبة وصالحة")
        except ValueError as exc:
            return error_response("INVALID_CASE_CONTEXT", str(exc), 422)
        get_db().execute(
            "INSERT INTO autopsy_case_context(case_id, reason, objective, classification, attack_outcome, alert_verdict, legal_hold, retention_until, created_at) VALUES (:case_id, :reason, :objective, :classification, :attack_outcome, :alert_verdict, :legal_hold, :retention_until, :created_at) ON CONFLICT(case_id) DO UPDATE SET reason=excluded.reason, objective=excluded.objective, classification=excluded.classification, attack_outcome=excluded.attack_outcome, alert_verdict=excluded.alert_verdict, legal_hold=excluded.legal_hold, retention_until=excluded.retention_until",
            result,
        )
        custody(case_id, "context_updated", {"fields": sorted(fields & data.keys())})
        touch_case(case_id)
    return case_summary(case_id)


@autopsy_api.get("/api/cases/<int:case_id>/records")
@require_permission("cases.read")
def records_list(case_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    try:
        limit = int(request.args.get("limit", 50))
        before = int(request.args["before"]) if "before" in request.args else None
        if not 1 <= limit <= 100 or before is not None and before < 1:
            raise ValueError
    except ValueError:
        return error_response("INVALID_PAGINATION", "قيم الترقيم غير صالحة", 422)
    kind = request.args.get("kind")
    if kind and kind not in KINDS and kind not in {"playbook", "reputation", "analysis"}:
        return error_response("INVALID_RECORD_KIND", "نوع السجل غير صالح", 422)
    items = records_for_case(case_id, kind, limit + 1, before)
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
                    raise ValueError("يبدأ التصعيد بحالة raised")
                payload.update({"from_user": actor_id(), "raised_at": iso_now()})
                get_db().execute(
                    "INSERT INTO autopsy_case_members(case_id, user_id, responsibility, assigned_by, assigned_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(case_id, user_id) DO NOTHING",
                    (case_id, payload["to_user"], payload["to_level"], actor_id(), iso_now()),
                )
        except (ValueError, UnicodeError) as exc:
            return error_response("INVALID_RECORD", str(exc), 422)
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
                    raise ValueError("حافظ على مسار التصعيد؛ أضف تصعيدًا جديدًا أو سلّم المسؤوليات من إدارة الفريق")
                if not manager() and previous["to_user"] != actor_id():
                    return error_response("PERMISSION_DENIED", "الإقرار والاستجابة لمتلقي التصعيد أو المدير", 403)
                transitions = {
                    "raised": {"raised", "acknowledged", "returned"},
                    "acknowledged": {"acknowledged", "resolved", "returned"},
                    "returned": {"returned", "raised"},
                    "resolved": {"resolved"},
                }
                if payload["status"] not in transitions[previous["status"]]:
                    raise ValueError("انتقال التصعيد غير مسموح")
                payload.update({key: value for key, value in previous.items() if key in {"from_user", "raised_at", "acknowledged_at", "responded_at"}})
                if payload["status"] == "acknowledged" and not payload.get("acknowledged_at"):
                    payload["acknowledged_at"] = iso_now()
                if payload["status"] == "resolved":
                    if not payload.get("response"):
                        raise ValueError("سجل الاستجابة قبل إتمام التصعيد")
                    payload.setdefault("responded_at", iso_now())
        except (ValueError, UnicodeError) as exc:
            return error_response("INVALID_RECORD", str(exc), 422)
        serialized = canonical(payload)
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
        or set(data) - {"user_id", "responsibility"}
        or type(data.get("user_id")) is not int
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
        get_db().execute(
            "INSERT INTO autopsy_case_members(case_id, user_id, responsibility, assigned_by, assigned_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(case_id, user_id) DO UPDATE SET responsibility = excluded.responsibility, assigned_by = excluded.assigned_by, assigned_at = excluded.assigned_at",
            (case_id, data["user_id"], data["responsibility"], actor_id(), iso_now()),
        )
        if data["responsibility"] == "owner":
            get_db().execute("UPDATE incident_cases SET assignee = ? WHERE id = ?", (data["user_id"], case_id))
        custody(case_id, "member_assigned", {"user_id": data["user_id"], "responsibility": data["responsibility"]})
        touch_case(case_id)
    return case_summary(case_id)


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
