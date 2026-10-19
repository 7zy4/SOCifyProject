import hashlib
import html
import json
import sqlite3
from datetime import timedelta
from typing import Any

from flask import Blueprint, Response, jsonify, request

from .audit import record_audit, record_training_action
from .db import get_db, inserted_id, transaction
from .schema import insert_outbox
from .security import actor_id, can_access_training_run, current_user, error_response, has_permission, require_permission, training_scope_sql, workspace_id
from .timeutils import iso_now, utc_now

cases_api = Blueprint("cases", __name__)

SEVERITIES = {"critical", "high", "medium", "low"}
PRIORITIES = {"urgent", "high", "medium", "low"}
TRANSITIONS: dict[str, set[str]] = {
    "new": {"open", "triaged", "investigating", "cancelled"},
    "open": {"triaged", "investigating", "escalated", "cancelled"},
    "triaged": {"investigating", "false_positive", "escalated"},
    "investigating": {"contained", "escalated", "false_positive"},
    "contained": {"remediated", "recovered"},
    "remediated": {"recovered"},
    "recovered": {"closed"},
    "escalated": {"investigating", "closed"},
    "false_positive": {"closed", "reopened"},
    "closed": {"reopened"},
    "reopened": {"investigating", "contained"},
    "cancelled": {"reopened"},
}


def _case_row(case_id: int) -> sqlite3.Row | None:
    row = get_db().execute("SELECT * FROM incident_cases WHERE id = ? AND workspace_id = ? AND archived_at IS NULL", (case_id, workspace_id())).fetchone()
    return row if row and can_access_training_run(row["training_run_id"]) else None


def _user_valid(user_id: object) -> bool:
    return isinstance(user_id, int) and get_db().execute("SELECT 1 FROM users WHERE id = ? AND workspace_id = ? AND is_active = 1", (user_id, workspace_id())).fetchone() is not None


def _json_list(value: object, field: str, maximum: int = 50) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > maximum or any(not isinstance(item, str) or len(item) > 100 for item in value):
        raise ValueError(f"{field} must be a list of short strings")
    return value


def _history(connection: sqlite3.Connection, case_id: int, action: str, previous: object = None, new: object = None, reason: str | None = None) -> None:
    from .security import correlation_id
    connection.execute(
        """INSERT INTO case_history
        (case_id, actor_id, action, previous_value, new_value, reason, correlation_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            case_id,
            actor_id(),
            action,
            json.dumps(previous, ensure_ascii=False, separators=(",", ":")) if previous is not None else None,
            json.dumps(new, ensure_ascii=False, separators=(",", ":")) if new is not None else None,
            reason,
            correlation_id(),
            iso_now(),
        ),
    )


def _reference(connection: sqlite3.Connection) -> str:
    year = utc_now().year
    prefix = f"CASE-{year}-"
    count = int(connection.execute("SELECT COUNT(*) FROM incident_cases WHERE workspace_id = ? AND reference LIKE ?", (workspace_id(), prefix + "%")).fetchone()[0])
    return f"{prefix}{count + 1:06d}"


def _attach_event(connection: sqlite3.Connection, case_id: int, event_id: int) -> bool:
    event = connection.execute("SELECT id, event_id, title, raw_hash, provenance, training_run_id FROM security_events WHERE id = ? AND workspace_id = ?", (event_id, workspace_id())).fetchone()
    if not event or not can_access_training_run(event["training_run_id"]):
        return False
    now = iso_now()
    connection.execute("INSERT OR IGNORE INTO case_events (case_id, event_id, attached_by, attached_at) VALUES (?, ?, ?, ?)", (case_id, event_id, actor_id(), now))
    connection.execute(
        """INSERT OR IGNORE INTO case_evidence
        (case_id, evidence_type, reference_id, title, sha256, provenance, added_by, added_at)
        VALUES (?, 'event', ?, ?, ?, ?, ?, ?)""",
        (case_id, str(event_id), event["title"], event["raw_hash"] or hashlib.sha256(str(event["event_id"]).encode()).hexdigest(), event["provenance"] or "{}", actor_id(), now),
    )
    return True


def _attach_alert(connection: sqlite3.Connection, case_id: int, alert_id: int) -> bool:
    alert = connection.execute("SELECT id, alert_id, reason, dedup_key, evidence, training_run_id FROM alerts WHERE id = ? AND workspace_id = ?", (alert_id, workspace_id())).fetchone()
    if not alert or not can_access_training_run(alert["training_run_id"]):
        return False
    now = iso_now()
    connection.execute("INSERT OR IGNORE INTO case_alerts (case_id, alert_id, attached_by, attached_at) VALUES (?, ?, ?, ?)", (case_id, alert_id, actor_id(), now))
    connection.execute(
        """INSERT OR IGNORE INTO case_evidence
        (case_id, evidence_type, reference_id, title, sha256, provenance, added_by, added_at)
        VALUES (?, 'alert', ?, ?, ?, ?, ?, ?)""",
        (case_id, str(alert_id), f"Alert {alert['alert_id']}", hashlib.sha256(str(alert["dedup_key"]).encode()).hexdigest(), alert["evidence"], actor_id(), now),
    )
    event_ids = connection.execute("SELECT event_id FROM alert_events WHERE alert_id = ?", (alert_id,)).fetchall()
    for event in event_ids:
        _attach_event(connection, case_id, int(event["event_id"]))
    return True


def _case_view(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        raise RuntimeError("case disappeared during request")
    item = dict(row)
    item["tags"] = json.loads(item["tags"] or "[]")
    item["mitre_ids"] = json.loads(item["mitre_ids"] or "[]")
    item["overdue"] = bool(item["sla_due_at"] and item["status"] not in {"closed", "cancelled"} and item["sla_due_at"] < iso_now())
    return item


@cases_api.get("/api/incidents")
@require_permission("cases.read")
def list_cases():
    try:
        page = max(int(request.args.get("page", 1)), 1)
        page_size = min(max(int(request.args.get("page_size", 50)), 1), 100)
    except ValueError:
        return error_response("INVALID_PAGINATION", "قيم الترقيم غير صالحة", 400)
    clauses = ["c.workspace_id = ?", "c.archived_at IS NULL"]
    parameters: list[object] = [workspace_id()]
    scope, scope_parameters = training_scope_sql("c.training_run_id")
    if scope:
        clauses.append(scope.removeprefix(" AND "))
        parameters.extend(scope_parameters)
    for parameter, column in (("status", "c.status"), ("severity", "c.severity"), ("priority", "c.priority"), ("assignee", "c.assignee"), ("training_run_id", "c.training_run_id")):
        value = request.args.get(parameter)
        if value:
            clauses.append(f"{column} = ?")
            parameters.append(value)
    query = request.args.get("q", "").strip()
    if query:
        if len(query) > 200:
            return error_response("QUERY_TOO_LONG", "نص البحث طويل جدًا", 422)
        clauses.append("(c.reference LIKE ? OR c.title LIKE ? OR c.description LIKE ?)")
        like = f"%{query}%"
        parameters.extend([like, like, like])
    where = " AND ".join(clauses)
    total = int(get_db().execute(f"SELECT COUNT(*) FROM incident_cases c WHERE {where}", parameters).fetchone()[0])
    rows = get_db().execute(
        f"""SELECT c.*, u.name AS assignee_name,
        (SELECT COUNT(*) FROM case_evidence e WHERE e.case_id = c.id) AS evidence_count,
        (SELECT COUNT(*) FROM case_tasks t WHERE t.case_id = c.id AND t.status != 'completed') AS pending_tasks
        FROM incident_cases c LEFT JOIN users u ON u.id = c.assignee
        WHERE {where} ORDER BY c.updated_at DESC LIMIT ? OFFSET ?""",
        (*parameters, page_size, (page - 1) * page_size),
    ).fetchall()
    return jsonify({"items": [_case_view(row) for row in rows], "total": total, "page": page, "page_size": page_size})


@cases_api.post("/api/incidents")
@require_permission("cases.create")
def create_case():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error_response("INVALID_JSON", "يلزم إرسال كائن JSON صالح", 400)
    return _create_case(data)


def _create_case(data: dict[str, Any]):
    title = data.get("title")
    description = data.get("description", "")
    severity = str(data.get("severity", "medium")).lower()
    priority = str(data.get("priority", severity if severity in PRIORITIES else "medium")).lower()
    assignee = data.get("assignee", data.get("assigned_to"))
    if not isinstance(title, str) or not 3 <= len(title.strip()) <= 255 or not isinstance(description, str) or len(description) > 10000:
        return error_response("INVALID_CASE", "عنوان التحقيق مطلوب ويجب ألا يتجاوز 255 محرفًا", 422)
    if severity not in SEVERITIES or priority not in PRIORITIES:
        return error_response("INVALID_CASE_PRIORITY", "درجة الخطورة أو الأولوية غير صالحة", 422)
    if assignee is not None and not _user_valid(assignee):
        return error_response("INVALID_ASSIGNEE", "المحلل المحدد غير متاح في مساحة العمل", 422)
    try:
        tags = _json_list(data.get("tags"), "tags")
        mitre_ids = _json_list(data.get("mitre_ids"), "mitre_ids", 20)
    except ValueError as exc:
        return error_response("INVALID_CASE_METADATA", str(exc), 422)
    event_ids = data.get("event_ids", [])
    alert_ids = data.get("alert_ids", [])
    if not isinstance(event_ids, list) or any(not isinstance(item, int) for item in event_ids) or len(event_ids) > 100:
        return error_response("INVALID_EVENT_LINKS", "قائمة السجلات غير صالحة", 422)
    if not isinstance(alert_ids, list) or any(not isinstance(item, int) for item in alert_ids) or len(alert_ids) > 100:
        return error_response("INVALID_ALERT_LINKS", "قائمة التنبيهات غير صالحة", 422)
    training_run_id = data.get("training_run_id")
    if training_run_id is None and alert_ids:
        source_alert = get_db().execute("SELECT training_run_id FROM alerts WHERE id = ? AND workspace_id = ?", (alert_ids[0], workspace_id())).fetchone()
        training_run_id = source_alert["training_run_id"] if source_alert else None
    if not can_access_training_run(training_run_id):
        return error_response("TRAINING_RUN_NOT_FOUND", "جلسة التدريب غير موجودة", 404)
    now = iso_now()
    sla_hours = {"urgent": 1, "high": 4, "medium": 24, "low": 72}[priority]
    sla_due = (utc_now() + timedelta(hours=sla_hours)).isoformat().replace("+00:00", "Z")
    user = current_user()
    team = str(data.get("team") or (user.get("team") if user else "") or "")[:120]
    with transaction():
        cursor = get_db().execute(
            """INSERT INTO incident_cases
            (reference, workspace_id, training_run_id, title, description, case_type, severity, priority, status,
            assignee, team, sla_due_at, creator, reporter, tags, mitre_ids, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                _reference(get_db()), workspace_id(), training_run_id, title.strip(), description.strip(), str(data.get("case_type") or "investigation")[:80],
                severity, priority, assignee, team, sla_due,
                actor_id(), actor_id(), json.dumps(tags, ensure_ascii=False), json.dumps(mitre_ids), now, now,
            ),
        )
        case_id = inserted_id(cursor)
        for event_id in event_ids:
            if not _attach_event(get_db(), case_id, event_id):
                raise ValueError(f"event {event_id} is unavailable")
        for alert_id in alert_ids:
            if not _attach_alert(get_db(), case_id, alert_id):
                raise ValueError(f"alert {alert_id} is unavailable")
        get_db().executemany(
            "INSERT INTO case_tasks (case_id, title, required, status, assignee, created_at) VALUES (?, ?, 1, 'pending', ?, ?)",
            [(case_id, "Validate primary evidence", assignee, now), (case_id, "Document response decision", assignee, now)],
        )
        _history(get_db(), case_id, "case_created", None, {"status": "new"})
        record_audit(get_db(), "create", "case", case_id, details={"events": event_ids, "alerts": alert_ids})
        record_training_action(get_db(), training_run_id if isinstance(training_run_id, int) else None, actor_id(), "case_created", "case", case_id, {"alert_ids": alert_ids}, f"case-create:{case_id}")
        insert_outbox(get_db(), workspace_id(), "incident.created", {"id": case_id})
    row = _case_row(case_id)
    return jsonify(_case_view(row)), 201, {"Location": f"/api/incidents/{case_id}"}


@cases_api.post("/api/alerts/<int:alert_id>/case")
@require_permission("cases.create")
def case_from_alert(alert_id: int):
    alert = get_db().execute("SELECT reason, severity, training_run_id, mitre_technique_ids FROM alerts WHERE id = ? AND workspace_id = ?", (alert_id, workspace_id())).fetchone()
    if not alert or not can_access_training_run(alert["training_run_id"]):
        return error_response("ALERT_NOT_FOUND", "التنبيه غير موجود", 404)
    data = request.get_json(silent=True)
    body = data if isinstance(data, dict) else {}
    body.setdefault("title", f"Investigation: {alert['reason'][:180]}")
    body.setdefault("description", alert["reason"])
    body.setdefault("severity", alert["severity"])
    body.setdefault("priority", alert["severity"] if alert["severity"] in PRIORITIES else "medium")
    body["alert_ids"] = [alert_id]
    body["training_run_id"] = alert["training_run_id"]
    body.setdefault("mitre_ids", json.loads(alert["mitre_technique_ids"] or "[]"))
    return _create_case(body)


@cases_api.get("/api/incidents/<int:case_id>")
@require_permission("cases.read")
def case_detail(case_id: int):
    row = _case_row(case_id)
    if not row:
        return error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
    item = _case_view(row)
    item["events"] = [dict(value) for value in get_db().execute("SELECT e.id, e.event_id, e.event_time, e.source, e.severity, e.event_type, e.title, ce.attached_at FROM case_events ce JOIN security_events e ON e.id = ce.event_id WHERE ce.case_id = ? ORDER BY e.event_time", (case_id,)).fetchall()]
    item["alerts"] = [dict(value) for value in get_db().execute("SELECT a.id, a.alert_id, a.severity, a.status, a.reason, ca.attached_at FROM case_alerts ca JOIN alerts a ON a.id = ca.alert_id WHERE ca.case_id = ? ORDER BY a.detected_at", (case_id,)).fetchall()]
    note_scope = "" if has_permission(current_user(), "cases.override") else " AND (n.visibility = 'team' OR n.author_id = ?)"
    note_parameters: tuple[object, ...] = (case_id,) if not note_scope else (case_id, actor_id())
    item["notes"] = [{**dict(value), "note": value["body"]} for value in get_db().execute(f"SELECT n.*, u.name AS author_name FROM case_notes n JOIN users u ON u.id = n.author_id WHERE n.case_id = ?{note_scope} ORDER BY n.created_at", note_parameters).fetchall()]
    item["evidence"] = [dict(value) for value in get_db().execute("SELECT e.*, u.name AS added_by_name FROM case_evidence e JOIN users u ON u.id = e.added_by WHERE e.case_id = ? ORDER BY e.added_at", (case_id,)).fetchall()]
    item["tasks"] = [dict(value) for value in get_db().execute("SELECT * FROM case_tasks WHERE case_id = ? ORDER BY id", (case_id,)).fetchall()]
    item["history"] = [dict(value) for value in get_db().execute("SELECT h.*, u.name AS actor_name FROM case_history h JOIN users u ON u.id = h.actor_id WHERE h.case_id = ? ORDER BY h.created_at", (case_id,)).fetchall()]
    item["reports"] = [dict(value) for value in get_db().execute("SELECT id, revision, format, sha256, created_by, created_at FROM case_reports WHERE case_id = ? ORDER BY revision DESC", (case_id,)).fetchall()]
    return jsonify(item)


@cases_api.patch("/api/incidents/<int:case_id>")
@require_permission("cases.update")
def update_case(case_id: int):
    row = _case_row(case_id)
    if not row:
        return error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error_response("INVALID_JSON", "يلزم إرسال كائن JSON صالح", 400)
    supplied_version = data.get("version")
    if supplied_version is not None and supplied_version != row["version"]:
        return error_response("CASE_VERSION_CONFLICT", "تم تعديل التحقيق في جلسة أخرى. حدّث البيانات ثم أعد المحاولة", 409, {"current_version": row["version"]})
    if "status" in data:
        return _transition(case_id, row, str(data["status"]), str(data.get("reason") or "Legacy status update"), data)
    updates: dict[str, Any] = {}
    for field, maximum in (("title", 255), ("description", 10000), ("team", 120)):
        if field in data:
            value = data[field]
            if not isinstance(value, str) or (field == "title" and len(value.strip()) < 3) or len(value) > maximum:
                return error_response("INVALID_CASE_FIELD", f"الحقل {field} غير صالح", 422)
            updates[field] = value.strip()
    for field, allowed in (("severity", SEVERITIES), ("priority", PRIORITIES)):
        if field in data:
            if data[field] not in allowed:
                return error_response("INVALID_CASE_FIELD", f"الحقل {field} غير صالح", 422)
            updates[field] = data[field]
    if "assigned_to" in data or "assignee" in data:
        assignee = data.get("assignee", data.get("assigned_to"))
        if assignee is not None and not _user_valid(assignee):
            return error_response("INVALID_ASSIGNEE", "المحلل المحدد غير متاح", 422)
        updates["assignee"] = assignee
    for field in ("tags", "mitre_ids"):
        if field in data:
            try:
                updates[field] = json.dumps(_json_list(data[field], field, 20 if field == "mitre_ids" else 50), ensure_ascii=False)
            except ValueError as exc:
                return error_response("INVALID_CASE_FIELD", str(exc), 422)
    if not updates:
        return error_response("NO_CHANGES", "لم تُرسل حقول قابلة للتعديل", 422)
    now = iso_now()
    assignments = ", ".join(f"{field} = ?" for field in updates)
    with transaction():
        get_db().execute(f"UPDATE incident_cases SET {assignments}, updated_at = ?, version = version + 1 WHERE id = ?", (*updates.values(), now, case_id))
        _history(get_db(), case_id, "case_updated", {key: row[key] for key in updates}, updates, str(data.get("reason") or "")[:500] or None)
        record_audit(get_db(), "update", "case", case_id, details={"fields": list(updates)})
        insert_outbox(get_db(), workspace_id(), "incident.updated", {"id": case_id, "version": int(row["version"]) + 1})
    return jsonify(_case_view(_case_row(case_id)))


def _transition(case_id: int, row: sqlite3.Row, target: str, reason: str, data: dict[str, Any]):
    if target not in TRANSITIONS.get(str(row["status"]), set()):
        return error_response("ILLEGAL_CASE_TRANSITION", f"لا يمكن الانتقال من {row['status']} إلى {target}", 409)
    if len(reason.strip()) < 3:
        return error_response("TRANSITION_REASON_REQUIRED", "اذكر سبب تغيير الحالة", 422)
    user = current_user()
    if target == "closed" and not has_permission(user, "cases.close"):
        return error_response("PERMISSION_DENIED", "إغلاق التحقيق يتطلب صلاحية مدير", 403)
    if target == "closed":
        required = {"disposition", "root_cause", "impact", "response_summary", "lessons_learned"}
        missing = [field for field in required if not isinstance(data.get(field), str) or len(str(data[field]).strip()) < 3]
        evidence_count = int(get_db().execute("SELECT COUNT(*) FROM case_evidence WHERE case_id = ?", (case_id,)).fetchone()[0])
        tasks = int(get_db().execute("SELECT COUNT(*) FROM case_tasks WHERE case_id = ? AND required = 1 AND status != 'completed'", (case_id,)).fetchone()[0])
        override = bool(data.get("override")) and has_permission(user, "cases.override") and isinstance(data.get("override_reason"), str) and len(str(data["override_reason"]).strip()) >= 10
        if (missing or evidence_count == 0 or tasks > 0) and not override:
            return error_response("CASE_CLOSURE_INCOMPLETE", "لا يمكن إغلاق التحقيق قبل إكمال الأدلة والمهام والتقرير", 409, {"missing_fields": missing, "evidence_count": evidence_count, "pending_required_tasks": tasks})
    now = iso_now()
    extra: dict[str, Any] = {}
    for field in ("disposition", "root_cause", "impact", "response_summary", "lessons_learned"):
        if isinstance(data.get(field), str):
            extra[field] = str(data[field]).strip()
    if target == "closed":
        extra["closed_at"] = now
        extra["resolved_at"] = row["resolved_at"] or now
    if target == "recovered":
        extra["resolved_at"] = now
    if target == "reopened":
        extra["closed_at"] = None
    assignments = ["status = ?", "updated_at = ?", "version = version + 1"] + [f"{field} = ?" for field in extra]
    with transaction():
        get_db().execute(f"UPDATE incident_cases SET {', '.join(assignments)} WHERE id = ?", (target, now, *extra.values(), case_id))
        _history(get_db(), case_id, "status_changed", row["status"], target, reason)
        record_audit(get_db(), "transition", "case", case_id, details={"from": row["status"], "to": target, "reason": reason})
        record_training_action(get_db(), row["training_run_id"], actor_id(), "case_transition", "case", case_id, {"from": row["status"], "to": target}, f"case-transition:{case_id}:{row['version']}:{target}")
        insert_outbox(get_db(), workspace_id(), "incident.updated", {"id": case_id, "status": target})
    if target == "closed":
        _generate_reports(case_id)
    return jsonify(_case_view(_case_row(case_id)))


@cases_api.post("/api/incidents/<int:case_id>/transitions")
@require_permission("cases.update")
def transition_case(case_id: int):
    row = _case_row(case_id)
    if not row:
        return error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("status"), str):
        return error_response("TARGET_STATUS_REQUIRED", "حدد الحالة الجديدة", 422)
    supplied_version = data.get("version")
    if supplied_version is not None and supplied_version != row["version"]:
        return error_response("CASE_VERSION_CONFLICT", "تم تعديل التحقيق في جلسة أخرى", 409, {"current_version": row["version"]})
    return _transition(case_id, row, data["status"], str(data.get("reason") or ""), data)


@cases_api.post("/api/incidents/<int:case_id>/notes")
@require_permission("notes.add")
def add_note(case_id: int):
    row = _case_row(case_id)
    if not row:
        return error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
    data = request.get_json(silent=True)
    body = data.get("body", data.get("note")) if isinstance(data, dict) else None
    visibility = data.get("visibility", "team") if isinstance(data, dict) else "team"
    if not isinstance(body, str) or not 1 <= len(body.strip()) <= 5000 or visibility not in {"team", "private"}:
        return error_response("INVALID_NOTE", "نص الملاحظة مطلوب وبحد أقصى 5000 محرف", 422)
    now = iso_now()
    with transaction():
        cursor = get_db().execute("INSERT INTO case_notes (case_id, author_id, body, visibility, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)", (case_id, actor_id(), body.strip(), visibility, now, now))
        note_id = inserted_id(cursor)
        _history(get_db(), case_id, "note_added", None, {"note_id": note_id})
        record_audit(get_db(), "create", "case_note", note_id, details={"case_id": case_id})
        record_training_action(get_db(), row["training_run_id"], actor_id(), "note_added", "case", case_id, {}, f"note:{note_id}")
    note = get_db().execute("SELECT n.*, u.name AS author_name FROM case_notes n JOIN users u ON u.id = n.author_id WHERE n.id = ?", (note_id,)).fetchone()
    return jsonify(dict(note)), 201


@cases_api.post("/api/incidents/<int:case_id>/events")
@require_permission("evidence.add")
def add_case_event(case_id: int):
    row = _case_row(case_id)
    if not row:
        return error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
    data = request.get_json(silent=True)
    event_id = data.get("event_id") if isinstance(data, dict) else None
    if not isinstance(event_id, int):
        return error_response("EVENT_ID_REQUIRED", "حدد السجل المطلوب", 422)
    with transaction():
        if not _attach_event(get_db(), case_id, event_id):
            return error_response("EVENT_NOT_FOUND", "السجل غير موجود", 404)
        _history(get_db(), case_id, "evidence_added", None, {"event_id": event_id})
        record_audit(get_db(), "attach", "case_event", event_id, details={"case_id": case_id})
        record_training_action(get_db(), row["training_run_id"], actor_id(), "evidence_added", "event", event_id, {"case_id": case_id}, f"evidence:event:{case_id}:{event_id}")
    return jsonify({"case_id": case_id, "event_id": event_id}), 201


@cases_api.post("/api/incidents/<int:case_id>/alerts")
@require_permission("evidence.add")
def add_case_alert(case_id: int):
    row = _case_row(case_id)
    if not row:
        return error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
    data = request.get_json(silent=True)
    alert_id = data.get("alert_id") if isinstance(data, dict) else None
    if not isinstance(alert_id, int):
        return error_response("ALERT_ID_REQUIRED", "حدد التنبيه المطلوب", 422)
    with transaction():
        if not _attach_alert(get_db(), case_id, alert_id):
            return error_response("ALERT_NOT_FOUND", "التنبيه غير موجود", 404)
        _history(get_db(), case_id, "alert_attached", None, {"alert_id": alert_id})
        record_audit(get_db(), "attach", "case_alert", alert_id, details={"case_id": case_id})
        record_training_action(get_db(), row["training_run_id"], actor_id(), "alert_attached", "alert", alert_id, {"case_id": case_id}, f"evidence:alert:{case_id}:{alert_id}")
    return jsonify({"case_id": case_id, "alert_id": alert_id}), 201


@cases_api.post("/api/incidents/<int:case_id>/evidence")
@require_permission("evidence.add")
def add_evidence(case_id: int):
    row = _case_row(case_id)
    if not row:
        return error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
    if row["status"] == "closed":
        return error_response("CASE_EVIDENCE_LOCKED", "الأدلة مقفلة بعد إغلاق التحقيق", 409)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error_response("INVALID_JSON", "يلزم إرسال كائن JSON صالح", 400)
    evidence_type = data.get("type")
    reference = data.get("reference_id")
    title = data.get("title")
    content = data.get("content")
    if evidence_type not in {"ioc", "training_artifact", "raw_log"} or not isinstance(reference, str) or not 1 <= len(reference) <= 255 or not isinstance(title, str) or not 1 <= len(title) <= 255 or not isinstance(content, str) or len(content.encode()) > 1048576:
        return error_response("INVALID_EVIDENCE", "بيانات الدليل غير صالحة أو تتجاوز الحجم المسموح", 422)
    digest = hashlib.sha256(content.encode()).hexdigest()
    now = iso_now()
    try:
        with transaction():
            cursor = get_db().execute("INSERT INTO case_evidence (case_id, evidence_type, reference_id, title, sha256, provenance, added_by, added_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (case_id, evidence_type, reference, title, digest, json.dumps({"source": "user", "content_length": len(content.encode())}), actor_id(), now))
            evidence_id = inserted_id(cursor)
            _history(get_db(), case_id, "evidence_added", None, {"evidence_id": evidence_id, "sha256": digest})
            record_audit(get_db(), "create", "case_evidence", evidence_id, details={"case_id": case_id, "sha256": digest})
    except sqlite3.IntegrityError:
        return error_response("DUPLICATE_EVIDENCE", "هذا الدليل مرتبط بالتحقيق مسبقًا", 409)
    return jsonify({"id": evidence_id, "sha256": digest}), 201


@cases_api.post("/api/incidents/<int:case_id>/tasks")
@require_permission("cases.update")
def add_task(case_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
    data = request.get_json(silent=True)
    payload = data if isinstance(data, dict) else {}
    title = payload.get("title")
    assignee = payload.get("assignee")
    if not isinstance(title, str) or not 2 <= len(title.strip()) <= 255 or assignee is not None and not _user_valid(assignee):
        return error_response("INVALID_TASK", "بيانات المهمة غير صالحة", 422)
    cursor = get_db().execute("INSERT INTO case_tasks (case_id, title, required, status, assignee, created_at) VALUES (?, ?, ?, 'pending', ?, ?)", (case_id, title.strip(), 1 if payload.get("required") else 0, assignee, iso_now()))
    task_id = inserted_id(cursor)
    _history(get_db(), case_id, "task_added", None, {"task_id": task_id})
    return jsonify({"id": task_id}), 201


@cases_api.patch("/api/incidents/<int:case_id>/tasks/<int:task_id>")
@require_permission("cases.update")
def update_task(case_id: int, task_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
    task = get_db().execute("SELECT * FROM case_tasks WHERE id = ? AND case_id = ?", (task_id, case_id)).fetchone()
    data = request.get_json(silent=True)
    status = data.get("status") if isinstance(data, dict) else None
    if not task or status not in {"pending", "in_progress", "completed", "reviewed"}:
        return error_response("INVALID_TASK_UPDATE", "المهمة أو حالتها غير صالحة", 422)
    completed_at = iso_now() if status in {"completed", "reviewed"} else None
    completed_by = actor_id() if completed_at else None
    get_db().execute("UPDATE case_tasks SET status = ?, completed_by = ?, completed_at = ? WHERE id = ?", (status, completed_by, completed_at, task_id))
    _history(get_db(), case_id, "task_updated", task["status"], status)
    return jsonify({"id": task_id, "status": status})


def _report_payload(case_id: int) -> dict[str, Any]:
    case = _case_row(case_id)
    evidence = [dict(row) for row in get_db().execute("SELECT evidence_type, reference_id, title, sha256, added_at FROM case_evidence WHERE case_id = ? ORDER BY added_at", (case_id,)).fetchall()]
    history = [dict(row) for row in get_db().execute("SELECT action, previous_value, new_value, reason, created_at FROM case_history WHERE case_id = ? ORDER BY created_at", (case_id,)).fetchall()]
    return {"case": _case_view(case), "evidence": evidence, "timeline": history, "generated_at": iso_now()}


def _report_html(payload: dict[str, Any]) -> str:
    case = payload["case"]
    evidence_rows = "".join(f"<tr><td>{html.escape(str(item['evidence_type']))}</td><td>{html.escape(str(item['title']))}</td><td dir=\"ltr\">{html.escape(str(item['sha256']))}</td></tr>" for item in payload["evidence"])
    return f"<!doctype html><html lang=\"ar\" dir=\"rtl\"><head><meta charset=\"utf-8\"><title>{html.escape(str(case['reference']))}</title><style>body{{font-family:Arial,sans-serif;margin:2rem;line-height:1.7}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #bbb;padding:.5rem}}h1{{color:#123b66}}</style></head><body><h1>{html.escape(str(case['reference']))}: {html.escape(str(case['title']))}</h1><p><strong>الحالة:</strong> {html.escape(str(case['status']))}</p><p><strong>السبب الجذري:</strong> {html.escape(str(case.get('root_cause') or 'غير محدد'))}</p><p><strong>الأثر:</strong> {html.escape(str(case.get('impact') or 'غير محدد'))}</p><p><strong>الاستجابة:</strong> {html.escape(str(case.get('response_summary') or 'غير محدد'))}</p><h2>الأدلة</h2><table><thead><tr><th>النوع</th><th>العنوان</th><th>SHA-256</th></tr></thead><tbody>{evidence_rows}</tbody></table><p>وقت التوليد: {html.escape(str(payload['generated_at']))}</p></body></html>"


def _generate_reports(case_id: int) -> None:
    payload = _report_payload(case_id)
    revision = int(get_db().execute("SELECT COALESCE(MAX(revision), 0) + 1 FROM case_reports WHERE case_id = ?", (case_id,)).fetchone()[0])
    json_content = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    html_content = _report_html(payload)
    now = iso_now()
    for report_format, content in (("json", json_content), ("html", html_content)):
        get_db().execute("INSERT INTO case_reports (case_id, revision, format, content, sha256, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (case_id, revision, report_format, content, hashlib.sha256(content.encode()).hexdigest(), actor_id(), now))
    record_audit(get_db(), "generate", "case_report", case_id, details={"revision": revision})


@cases_api.get("/api/incidents/<int:case_id>/report")
@require_permission("cases.read")
def get_report(case_id: int):
    case = _case_row(case_id)
    if not case:
        return error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
    report_format = request.args.get("format", "json")
    if report_format not in {"json", "html"}:
        return error_response("REPORT_FORMAT_UNSUPPORTED", "الصيغ المتاحة هي JSON وHTML", 422)
    row = get_db().execute("SELECT * FROM case_reports WHERE case_id = ? AND format = ? ORDER BY revision DESC LIMIT 1", (case_id, report_format)).fetchone()
    if not row:
        if case["status"] != "closed":
            return error_response("REPORT_NOT_READY", "يتوفر التقرير النهائي بعد إغلاق التحقيق", 409)
        _generate_reports(case_id)
        row = get_db().execute("SELECT * FROM case_reports WHERE case_id = ? AND format = ? ORDER BY revision DESC LIMIT 1", (case_id, report_format)).fetchone()
    if row is None:
        raise RuntimeError("Report generation returned no result")
    mimetype = "application/json" if report_format == "json" else "text/html; charset=utf-8"
    return Response(row["content"], mimetype=mimetype, headers={"Content-Disposition": f"attachment; filename={case['reference']}.{report_format}", "X-Report-SHA256": row["sha256"]})
