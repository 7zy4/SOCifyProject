import hashlib
import hmac
import html
import json
import sqlite3
from datetime import timedelta
from typing import Any

from flask import Blueprint, Response, jsonify, request

from .audit import record_audit, record_training_action
from .db import get_db, inserted_id, transaction
from .operational import case_scope, case_visible, operational_mode
from .report_brand import report_style
from .schema import insert_outbox
from .security import (
    actor_id,
    can_access_training_run,
    current_user,
    decrypt_secret,
    encrypt_secret,
    error_response,
    has_permission,
    require_permission,
    training_scope_sql,
    workspace_id,
)
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
    user = current_user()
    return row if row and user and can_access_training_run(row["training_run_id"]) and case_visible(case_id, user) else None


def _user_valid(user_id: object) -> bool:
    return (
        type(user_id) is int
        and 1 <= user_id <= 9223372036854775807
        and get_db().execute("SELECT 1 FROM users WHERE id = ? AND workspace_id = ? AND is_active = 1", (user_id, workspace_id())).fetchone() is not None
    )


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
    count = int(connection.execute("SELECT COUNT(*) FROM incident_cases WHERE reference LIKE ?", (prefix + "%",)).fetchone()[0])
    return f"{prefix}{count + 1:06d}"


def _source_visible(owner_case_id: int | None, created_by: int | None = None) -> bool:
    if not operational_mode():
        return True
    user = current_user() or {}
    if owner_case_id is None:
        return user.get("role") in {"admin", "soc_manager"} or created_by == actor_id()
    return case_visible(owner_case_id, user)


def _attach_event(connection: sqlite3.Connection, case_id: int, event_id: int) -> bool:
    event = connection.execute(
        "SELECT id, event_id, title, raw_hash, provenance, training_run_id, owner_case_id, created_by FROM security_events WHERE id = ? AND workspace_id = ?",
        (event_id, workspace_id()),
    ).fetchone()
    case = connection.execute("SELECT training_run_id FROM incident_cases WHERE id = ? AND workspace_id = ?", (case_id, workspace_id())).fetchone()
    if not event or not case or event["training_run_id"] != case["training_run_id"] or not can_access_training_run(event["training_run_id"]):
        return False
    already_linked = connection.execute("SELECT 1 FROM case_events WHERE case_id = ? AND event_id = ?", (case_id, event_id)).fetchone()
    if not already_linked and not _source_visible(event["owner_case_id"], event["created_by"]):
        return False
    now = iso_now()
    connection.execute(
        "INSERT OR IGNORE INTO case_events (case_id, event_id, attached_by, attached_at) VALUES (?, ?, ?, ?)", (case_id, event_id, actor_id(), now)
    )
    connection.execute(
        """INSERT OR IGNORE INTO case_evidence
        (case_id, evidence_type, reference_id, title, sha256, provenance, added_by, added_at)
        VALUES (?, 'event', ?, ?, ?, ?, ?, ?)""",
        (
            case_id,
            str(event_id),
            event["title"],
            event["raw_hash"] or hashlib.sha256(str(event["event_id"]).encode()).hexdigest(),
            event["provenance"] or "{}",
            actor_id(),
            now,
        ),
    )
    return True


def _attach_alert(connection: sqlite3.Connection, case_id: int, alert_id: int) -> bool:
    alert = connection.execute(
        "SELECT id, alert_id, reason, dedup_key, evidence, training_run_id, owner_case_id FROM alerts WHERE id = ? AND workspace_id = ?",
        (alert_id, workspace_id()),
    ).fetchone()
    case = connection.execute("SELECT training_run_id FROM incident_cases WHERE id = ? AND workspace_id = ?", (case_id, workspace_id())).fetchone()
    if not alert or not case or alert["training_run_id"] != case["training_run_id"] or not can_access_training_run(alert["training_run_id"]):
        return False
    if not _source_visible(alert["owner_case_id"]):
        return False
    now = iso_now()
    connection.execute(
        "INSERT OR IGNORE INTO case_alerts (case_id, alert_id, attached_by, attached_at) VALUES (?, ?, ?, ?)", (case_id, alert_id, actor_id(), now)
    )
    connection.execute(
        """INSERT OR IGNORE INTO case_evidence
        (case_id, evidence_type, reference_id, title, sha256, provenance, added_by, added_at)
        VALUES (?, 'alert', ?, ?, ?, ?, ?, ?)""",
        (
            case_id,
            str(alert_id),
            f"Alert {alert['alert_id']}",
            hashlib.sha256(str(alert["dedup_key"]).encode()).hexdigest(),
            alert["evidence"],
            actor_id(),
            now,
        ),
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
    context = get_db().execute("SELECT * FROM autopsy_case_context WHERE case_id = ?", (row["id"],)).fetchone()
    item["context"] = dict(context) if context else None
    return item


@cases_api.get("/api/incidents")
@require_permission("cases.read")
def list_cases():
    try:
        page = max(int(request.args.get("page", 1)), 1)
        if page > 1000000:
            raise ValueError
        page_size = min(max(int(request.args.get("page_size", 50)), 1), 100)
    except ValueError:
        return error_response("INVALID_PAGINATION", "قيم الترقيم غير صالحة", 400)
    clauses = ["c.workspace_id = ?", "c.archived_at IS NULL"]
    parameters: list[object] = [workspace_id()]
    visibility, visibility_args = case_scope(current_user() or {})
    if visibility:
        clauses.append(visibility.removeprefix(" AND "))
        parameters.extend(visibility_args)
    scope, scope_parameters = training_scope_sql("c.training_run_id")
    if scope:
        clauses.append(scope.removeprefix(" AND "))
        parameters.extend(scope_parameters)
    for parameter, column in (
        ("status", "c.status"),
        ("severity", "c.severity"),
        ("priority", "c.priority"),
        ("assignee", "c.assignee"),
        ("training_run_id", "c.training_run_id"),
    ):
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
    rows = (
        get_db()
        .execute(
            f"""SELECT c.*, u.name AS assignee_name,
        (SELECT COUNT(*) FROM case_evidence e WHERE e.case_id = c.id) AS evidence_count,
        (SELECT COUNT(*) FROM case_tasks t WHERE t.case_id = c.id AND t.status != 'completed') AS pending_tasks
        FROM incident_cases c LEFT JOIN users u ON u.id = c.assignee
        WHERE {where} ORDER BY c.updated_at DESC LIMIT ? OFFSET ?""",
            (*parameters, page_size, (page - 1) * page_size),
        )
        .fetchall()
    )
    return jsonify({"items": [_case_view(row) for row in rows], "total": total, "page": page, "page_size": page_size})


@cases_api.post("/api/incidents")
@require_permission("cases.create")
def create_case():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error_response("INVALID_JSON", "يلزم إرسال كائن JSON صالح", 400)
    return _create_case(data)


def _create_case(data: dict[str, Any]):
    reason, objective, classification = data.get("reason"), data.get("objective"), data.get("classification", "confidential")
    if operational_mode():
        from .autopsy_domain import text_value

        allowed = {
            "title",
            "reason",
            "objective",
            "classification",
            "description",
            "severity",
            "priority",
            "assignee",
            "event_ids",
            "alert_ids",
            "tags",
            "mitre_ids",
        }
        if set(data) - allowed:
            return error_response("UNKNOWN_CASE_FIELDS", "حقول غير مسموحة في نموذج القضية", 422)
        if not isinstance(reason, str) or not 3 <= len(reason.strip()) <= 500 or not isinstance(objective, str) or not 3 <= len(objective.strip()) <= 2000:
            return error_response("CASE_PURPOSE_REQUIRED", "حدد سبب فتح القضية وهدف التحقيق", 422)
        if not isinstance(classification, str) or classification not in {"internal", "confidential", "restricted"}:
            return error_response("INVALID_CLASSIFICATION", "تصنيف السرية غير صالح", 422)
        try:
            text_value(data.get("title"), 255, True)
            text_value(reason, 500, True)
            text_value(objective, 2000, True)
        except ValueError as exc:
            return error_response("INVALID_CASE", str(exc), 422)
        data.setdefault("assignee", actor_id())
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
    if training_run_id is None and event_ids:
        source_event = (
            get_db().execute("SELECT training_run_id FROM security_events WHERE id = ? AND workspace_id = ?", (event_ids[0], workspace_id())).fetchone()
        )
        training_run_id = source_event["training_run_id"] if source_event else None
    if not can_access_training_run(training_run_id):
        return error_response("TRAINING_RUN_NOT_FOUND", "جلسة التدريب غير موجودة", 404)
    now = iso_now()
    sla_hours = {"urgent": 1, "high": 4, "medium": 24, "low": 72}[priority]
    sla_due = (utc_now() + timedelta(hours=sla_hours)).isoformat().replace("+00:00", "Z")
    user = current_user()
    team = str(data.get("team") or (user.get("team") if user else "") or "")[:120]
    with transaction():
        for event_id in event_ids:
            event = (
                get_db()
                .execute("SELECT training_run_id, owner_case_id, created_by FROM security_events WHERE id = ? AND workspace_id = ?", (event_id, workspace_id()))
                .fetchone()
            )
            if (
                not event
                or event["training_run_id"] != training_run_id
                or not can_access_training_run(event["training_run_id"])
                or not _source_visible(event["owner_case_id"], event["created_by"])
            ):
                return error_response("EVENT_NOT_FOUND", "السجل غير موجود", 404)
        for alert_id in alert_ids:
            alert = (
                get_db().execute("SELECT training_run_id, owner_case_id FROM alerts WHERE id = ? AND workspace_id = ?", (alert_id, workspace_id())).fetchone()
            )
            if (
                not alert
                or alert["training_run_id"] != training_run_id
                or not can_access_training_run(alert["training_run_id"])
                or not _source_visible(alert["owner_case_id"])
            ):
                return error_response("ALERT_NOT_FOUND", "التنبيه غير موجود", 404)
        cursor = get_db().execute(
            """INSERT INTO incident_cases
            (reference, workspace_id, training_run_id, title, description, case_type, severity, priority, status,
            assignee, team, sla_due_at, creator, reporter, tags, mitre_ids, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                _reference(get_db()),
                workspace_id(),
                training_run_id,
                title.strip(),
                description.strip(),
                str(data.get("case_type") or "investigation")[:80],
                severity,
                priority,
                assignee,
                team,
                sla_due,
                actor_id(),
                actor_id(),
                json.dumps(tags, ensure_ascii=False),
                json.dumps(mitre_ids),
                now,
                now,
            ),
        )
        case_id = inserted_id(cursor)
        if operational_mode():
            get_db().execute(
                "INSERT INTO autopsy_case_context(case_id, reason, objective, classification, created_at) VALUES (?, ?, ?, ?, ?)",
                (case_id, str(reason).strip(), str(objective).strip(), classification, now),
            )
            for member in {actor_id(), assignee} - {None}:
                get_db().execute(
                    "INSERT INTO autopsy_case_members(case_id, user_id, responsibility, assigned_by, assigned_at) VALUES (?, ?, 'analyst', ?, ?)",
                    (case_id, member, actor_id(), now),
                )
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
        record_training_action(
            get_db(),
            training_run_id if isinstance(training_run_id, int) else None,
            actor_id(),
            "case_created",
            "case",
            case_id,
            {"alert_ids": alert_ids},
            f"case-create:{case_id}",
        )
        insert_outbox(get_db(), workspace_id(), "incident.created", {"id": case_id})
    row = _case_row(case_id)
    return jsonify(_case_view(row)), 201, {"Location": f"/api/incidents/{case_id}"}


@cases_api.post("/api/alerts/<int:alert_id>/case")
@require_permission("cases.create")
def case_from_alert(alert_id: int):
    alert = (
        get_db()
        .execute("SELECT reason, severity, training_run_id, mitre_technique_ids FROM alerts WHERE id = ? AND workspace_id = ?", (alert_id, workspace_id()))
        .fetchone()
    )
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
    if operational_mode():
        body.pop("training_run_id", None)
    body.setdefault("mitre_ids", json.loads(alert["mitre_technique_ids"] or "[]"))
    return _create_case(body)


@cases_api.get("/api/incidents/<int:case_id>")
@require_permission("cases.read")
def case_detail(case_id: int):
    if operational_mode():
        from .autopsy_api import case_summary

        return case_summary(case_id)
    row = _case_row(case_id)
    if not row:
        return error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
    item = _case_view(row)
    item["events"] = [
        dict(value)
        for value in get_db()
        .execute(
            "SELECT e.id, e.event_id, e.event_time, e.source, e.severity, e.event_type, e.title, ce.attached_at FROM case_events ce JOIN security_events e ON e.id = ce.event_id WHERE ce.case_id = ? ORDER BY e.event_time",
            (case_id,),
        )
        .fetchall()
    ]
    item["alerts"] = [
        dict(value)
        for value in get_db()
        .execute(
            "SELECT a.id, a.alert_id, a.severity, a.status, a.reason, ca.attached_at FROM case_alerts ca JOIN alerts a ON a.id = ca.alert_id WHERE ca.case_id = ? ORDER BY a.detected_at",
            (case_id,),
        )
        .fetchall()
    ]
    note_scope = "" if has_permission(current_user(), "cases.override") else " AND (n.visibility = 'team' OR n.author_id = ?)"
    note_parameters: tuple[object, ...] = (case_id,) if not note_scope else (case_id, actor_id())
    item["notes"] = [
        {**dict(value), "note": value["body"]}
        for value in get_db()
        .execute(
            f"SELECT n.*, u.name AS author_name FROM case_notes n JOIN users u ON u.id = n.author_id WHERE n.case_id = ?{note_scope} ORDER BY n.created_at",
            note_parameters,
        )
        .fetchall()
    ]
    item["evidence"] = [
        dict(value)
        for value in get_db()
        .execute(
            "SELECT e.*, u.name AS added_by_name FROM case_evidence e JOIN users u ON u.id = e.added_by WHERE e.case_id = ? ORDER BY e.added_at", (case_id,)
        )
        .fetchall()
    ]
    item["tasks"] = [dict(value) for value in get_db().execute("SELECT * FROM case_tasks WHERE case_id = ? ORDER BY id", (case_id,)).fetchall()]
    item["history"] = [
        dict(value)
        for value in get_db()
        .execute("SELECT h.*, u.name AS actor_name FROM case_history h JOIN users u ON u.id = h.actor_id WHERE h.case_id = ? ORDER BY h.created_at", (case_id,))
        .fetchall()
    ]
    item["reports"] = [
        dict(value)
        for value in get_db()
        .execute("SELECT id, revision, format, sha256, created_by, created_at FROM case_reports WHERE case_id = ? ORDER BY revision DESC", (case_id,))
        .fetchall()
    ]
    item["technique_annotations"] = [
        dict(value)
        for value in get_db()
        .execute(
            "SELECT a.*, u.name AS author_name FROM case_technique_annotations a JOIN users u ON u.id = a.created_by WHERE a.case_id = ? ORDER BY a.id",
            (case_id,),
        )
        .fetchall()
    ]
    item["observables"] = [
        {**dict(value), "tags": json.loads(value["tags"] or "[]")}
        for value in get_db()
        .execute(
            """SELECT i.id, i.type, i.value, i.confidence, i.source, i.tags,
            MIN(o.created_at) AS first_seen, MAX(o.created_at) AS last_seen, COUNT(DISTINCT o.event_id) AS observation_count
            FROM case_events ce
            JOIN ioc_observations o ON o.event_id = ce.event_id
            JOIN ioc_indicators i ON i.id = o.ioc_id AND i.workspace_id = ?
            WHERE ce.case_id = ?
            GROUP BY i.id, i.type, i.value, i.confidence, i.source, i.tags
            ORDER BY observation_count DESC, last_seen DESC""",
            (workspace_id(), case_id),
        )
        .fetchall()
    ]
    candidates = (
        get_db()
        .execute(
            """SELECT c.id, c.reference, c.title, c.status, c.severity, c.training_run_id,
        COUNT(DISTINCT source_o.ioc_id) AS shared_observables
        FROM case_events source_ce
        JOIN ioc_observations source_o ON source_o.event_id = source_ce.event_id
        JOIN ioc_observations candidate_o ON candidate_o.ioc_id = source_o.ioc_id
        JOIN case_events candidate_ce ON candidate_ce.event_id = candidate_o.event_id
        JOIN incident_cases c ON c.id = candidate_ce.case_id
        WHERE source_ce.case_id = ? AND c.id != ? AND c.workspace_id = ? AND c.archived_at IS NULL
        GROUP BY c.id, c.reference, c.title, c.status, c.severity, c.training_run_id
        ORDER BY shared_observables DESC, c.updated_at DESC
        LIMIT 20""",
            (case_id, case_id, workspace_id()),
        )
        .fetchall()
    )
    item["similar_cases"] = [
        dict(value) for value in candidates if can_access_training_run(value["training_run_id"]) and case_visible(value["id"], current_user() or {})
    ]
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
    if operational_mode():
        allowed = {"version", "title", "description", "team", "severity", "priority", "assignee", "assigned_to", "tags", "mitre_ids", "status", "reason"}
        if set(data) - allowed or type(data.get("version")) is not int:
            return error_response("INVALID_CASE_UPDATE", "أرسل الإصدار والحقول المعروفة", 422)
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
            if not isinstance(data[field], str) or data[field] not in allowed:
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
        changed = get_db().execute(
            f"UPDATE incident_cases SET {assignments}, updated_at = ?, version = version + 1 WHERE id = ? AND version = ?",
            (*updates.values(), now, case_id, row["version"]),
        )
        if changed.rowcount != 1:
            return error_response("CASE_VERSION_CONFLICT", "تم تعديل التحقيق في جلسة أخرى", 409)
        _history(get_db(), case_id, "case_updated", {key: row[key] for key in updates}, updates, str(data.get("reason") or "")[:500] or None)
        record_audit(get_db(), "update", "case", case_id, details={"fields": list(updates)})
        insert_outbox(get_db(), workspace_id(), "incident.updated", {"id": case_id, "version": int(row["version"]) + 1})
    return jsonify(_case_view(_case_row(case_id)))


def _transition(case_id: int, row: sqlite3.Row, target: str, reason: str, data: dict[str, Any]):
    from .operational import operational_mode

    if operational_mode():
        from .autopsy_reports import transition_operational

        return transition_operational(case_id, row, target, reason, data)
    if target not in TRANSITIONS.get(str(row["status"]), set()):
        return error_response("ILLEGAL_CASE_TRANSITION", f"لا يمكن الانتقال من {row['status']} إلى {target}", 409)
    if len(reason.strip()) < 3:
        return error_response("TRANSITION_REASON_REQUIRED", "اذكر سبب تغيير الحالة", 422)
    user = current_user()
    if target == "closed" and not has_permission(user, "cases.close"):
        return error_response("PERMISSION_DENIED", "إغلاق التحقيق يتطلب صلاحية مدير", 403)
    closure_fields = {
        "disposition": 500,
        "root_cause": 2000,
        "impact": 2000,
        "response_summary": 2000,
        "evidence_summary": 5000,
        "lessons_learned": 5000,
        "validation": 2000,
    }
    override = False
    if target == "closed":
        missing = [field for field in closure_fields if not isinstance(data.get(field), str) or len(str(data[field]).strip()) < 3]
        oversized = [field for field, maximum in closure_fields.items() if isinstance(data.get(field), str) and len(str(data[field])) > maximum]
        if oversized:
            return error_response("CASE_CLOSURE_FIELD_INVALID", "حقول تقرير الإغلاق تتجاوز الحد المسموح", 422, {"fields": oversized})
        evidence_count = int(get_db().execute("SELECT COUNT(*) FROM case_evidence WHERE case_id = ?", (case_id,)).fetchone()[0])
        tasks = int(get_db().execute("SELECT COUNT(*) FROM case_tasks WHERE case_id = ? AND required = 1 AND status != 'completed'", (case_id,)).fetchone()[0])
        override = (
            bool(data.get("override"))
            and has_permission(user, "cases.override")
            and isinstance(data.get("override_reason"), str)
            and len(str(data["override_reason"]).strip()) >= 10
        )
        if (missing or evidence_count == 0 or tasks > 0) and not override:
            return error_response(
                "CASE_CLOSURE_INCOMPLETE",
                "لا يمكن إغلاق التحقيق قبل إكمال الأدلة والمهام والتقرير",
                409,
                {"missing_fields": missing, "evidence_count": evidence_count, "pending_required_tasks": tasks},
            )
    now = iso_now()
    extra: dict[str, Any] = {}
    for field in closure_fields:
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
        changed = get_db().execute(
            f"UPDATE incident_cases SET {', '.join(assignments)} WHERE id = ? AND version = ?", (target, now, *extra.values(), case_id, row["version"])
        )
        if changed.rowcount != 1:
            return error_response("CASE_VERSION_CONFLICT", "تم تعديل التحقيق في جلسة أخرى", 409)
        _history(get_db(), case_id, "status_changed", row["status"], target, reason)
        audit_details = {"from": row["status"], "to": target, "reason": reason}
        if override:
            audit_details["override_reason"] = str(data["override_reason"]).strip()
        record_audit(get_db(), "transition", "case", case_id, details=audit_details)
        record_training_action(
            get_db(),
            row["training_run_id"],
            actor_id(),
            "case_transition",
            "case",
            case_id,
            {"from": row["status"], "to": target},
            f"case-transition:{case_id}:{row['version']}:{target}",
        )
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
    from .operational import operational_mode

    if operational_mode() and row["status"] == "closed":
        return error_response("CASE_CLOSED", "القضية مغلقة؛ تابع الإجراءات التصحيحية أو أعد فتحها بسبب موثق", 409)
    data = request.get_json(silent=True)
    body = data.get("body", data.get("note")) if isinstance(data, dict) else None
    visibility = data.get("visibility", "team") if isinstance(data, dict) else "team"
    if not isinstance(body, str) or not 1 <= len(body.strip()) <= 5000 or not isinstance(visibility, str) or visibility not in {"team", "private"}:
        return error_response("INVALID_NOTE", "نص الملاحظة مطلوب وبحد أقصى 5000 محرف", 422)
    now = iso_now()
    with transaction():
        cursor = get_db().execute(
            "INSERT INTO case_notes (case_id, author_id, body, visibility, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (case_id, actor_id(), body.strip(), visibility, now, now),
        )
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
    if row["status"] == "closed":
        return error_response("CASE_EVIDENCE_LOCKED", "الأدلة مقفلة بعد إغلاق التحقيق", 409)
    data = request.get_json(silent=True)
    event_id = data.get("event_id") if isinstance(data, dict) else None
    if not isinstance(event_id, int):
        return error_response("EVENT_ID_REQUIRED", "حدد السجل المطلوب", 422)
    with transaction():
        if not _attach_event(get_db(), case_id, event_id):
            return error_response("EVENT_NOT_FOUND", "السجل غير موجود", 404)
        _history(get_db(), case_id, "evidence_added", None, {"event_id": event_id})
        record_audit(get_db(), "attach", "case_event", event_id, details={"case_id": case_id})
        record_training_action(
            get_db(), row["training_run_id"], actor_id(), "evidence_added", "event", event_id, {"case_id": case_id}, f"evidence:event:{case_id}:{event_id}"
        )
    return jsonify({"case_id": case_id, "event_id": event_id}), 201


@cases_api.post("/api/incidents/<int:case_id>/alerts")
@require_permission("evidence.add")
def add_case_alert(case_id: int):
    row = _case_row(case_id)
    if not row:
        return error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
    if row["status"] == "closed":
        return error_response("CASE_EVIDENCE_LOCKED", "الأدلة مقفلة بعد إغلاق التحقيق", 409)
    data = request.get_json(silent=True)
    alert_id = data.get("alert_id") if isinstance(data, dict) else None
    if not isinstance(alert_id, int):
        return error_response("ALERT_ID_REQUIRED", "حدد التنبيه المطلوب", 422)
    with transaction():
        if not _attach_alert(get_db(), case_id, alert_id):
            return error_response("ALERT_NOT_FOUND", "التنبيه غير موجود", 404)
        _history(get_db(), case_id, "alert_attached", None, {"alert_id": alert_id})
        record_audit(get_db(), "attach", "case_alert", alert_id, details={"case_id": case_id})
        record_training_action(
            get_db(), row["training_run_id"], actor_id(), "alert_attached", "alert", alert_id, {"case_id": case_id}, f"evidence:alert:{case_id}:{alert_id}"
        )
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
    if (
        not isinstance(evidence_type, str)
        or evidence_type not in {"ioc", "training_artifact", "raw_log"}
        or not isinstance(reference, str)
        or not 1 <= len(reference) <= 255
        or not isinstance(title, str)
        or not 1 <= len(title) <= 255
        or not isinstance(content, str)
        or len(content.encode()) > 1048576
    ):
        return error_response("INVALID_EVIDENCE", "بيانات الدليل غير صالحة أو تتجاوز الحجم المسموح", 422)
    digest = hashlib.sha256(content.encode()).hexdigest()
    now = iso_now()
    try:
        with transaction():
            cursor = get_db().execute(
                "INSERT INTO case_evidence (case_id, evidence_type, reference_id, title, sha256, provenance, added_by, added_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (case_id, evidence_type, reference, title, digest, json.dumps({"source": "user", "content_length": len(content.encode())}), actor_id(), now),
            )
            evidence_id = inserted_id(cursor)
            get_db().execute(
                "INSERT INTO case_evidence_content (evidence_id, ciphertext) VALUES (?, ?)",
                (evidence_id, encrypt_secret(content)),
            )
            _history(get_db(), case_id, "evidence_added", None, {"evidence_id": evidence_id, "sha256": digest})
            record_audit(get_db(), "create", "case_evidence", evidence_id, details={"case_id": case_id, "sha256": digest})
    except sqlite3.IntegrityError:
        return error_response("DUPLICATE_EVIDENCE", "هذا الدليل مرتبط بالتحقيق مسبقًا", 409)
    return jsonify({"id": evidence_id, "sha256": digest}), 201


@cases_api.get("/api/incidents/<int:case_id>/evidence/<int:evidence_id>")
@require_permission("cases.read")
def evidence_detail(case_id: int, evidence_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
    evidence = get_db().execute("SELECT * FROM case_evidence WHERE id = ? AND case_id = ?", (evidence_id, case_id)).fetchone()
    if not evidence:
        return error_response("EVIDENCE_NOT_FOUND", "الدليل غير موجود", 404)
    accessed_at = iso_now()
    with transaction():
        get_db().execute("UPDATE case_evidence SET accessed_at = ? WHERE id = ?", (accessed_at, evidence_id))
        _history(get_db(), case_id, "evidence_accessed", None, {"evidence_id": evidence_id, "sha256": evidence["sha256"]})
        record_audit(get_db(), "read", "case_evidence", evidence_id, details={"case_id": case_id, "sha256": evidence["sha256"]})
    result = dict(evidence)
    result["accessed_at"] = accessed_at
    result["provenance"] = json.loads(result["provenance"] or "{}")
    result["content_available"] = get_db().execute("SELECT 1 FROM case_evidence_content WHERE evidence_id = ?", (evidence_id,)).fetchone() is not None
    return jsonify(result)


@cases_api.get("/api/incidents/<int:case_id>/evidence/<int:evidence_id>/content")
@require_permission("cases.read")
def evidence_content(case_id: int, evidence_id: int):
    if operational_mode() and not has_permission(current_user(), "evidence.download"):
        return error_response("PERMISSION_DENIED", "تنزيل الأصل يتطلب صلاحية مستقلة", 403)
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
    evidence = (
        get_db()
        .execute(
            "SELECT e.sha256, c.ciphertext FROM case_evidence e LEFT JOIN case_evidence_content c ON c.evidence_id = e.id WHERE e.id = ? AND e.case_id = ?",
            (evidence_id, case_id),
        )
        .fetchone()
    )
    if not evidence:
        return error_response("EVIDENCE_NOT_FOUND", "الدليل غير موجود", 404)
    if evidence["ciphertext"] is None:
        return error_response("EVIDENCE_CONTENT_UNAVAILABLE", "المحتوى الأصلي غير محفوظ لهذا الدليل؛ راجع مرجع المصدر", 409)
    try:
        content = decrypt_secret(evidence["ciphertext"]).encode()
        if not hmac.compare_digest(hashlib.sha256(content).hexdigest(), evidence["sha256"]):
            raise ValueError("digest mismatch")
    except ValueError:
        record_audit(get_db(), "read", "case_evidence", evidence_id, result="denied", details={"case_id": case_id, "reason": "integrity_failure"})
        return error_response("EVIDENCE_INTEGRITY_FAILURE", "تعذر التحقق من سلامة المحتوى", 409)
    with transaction():
        get_db().execute("UPDATE case_evidence SET accessed_at = ? WHERE id = ?", (iso_now(), evidence_id))
        _history(get_db(), case_id, "evidence_downloaded", None, {"evidence_id": evidence_id, "sha256": evidence["sha256"]})
        record_audit(get_db(), "download", "case_evidence", evidence_id, details={"case_id": case_id, "sha256": evidence["sha256"]})
    return Response(
        content,
        mimetype="application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename=evidence-{evidence_id}.txt",
            "X-Evidence-SHA256": evidence["sha256"],
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@cases_api.post("/api/incidents/<int:case_id>/imports")
@require_permission("evidence.add")
def attach_import(case_id: int):
    from .ingestion import _job_access

    case = _case_row(case_id)
    if not case:
        return error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or type(data.get("job_id")) is not int or type(data.get("after_id", 0)) is not int or data.get("after_id", 0) < 0:
        return error_response("INVALID_IMPORT_LINK", "حدد رقم الاستيراد ومؤشر صفحة صحيحين", 422)
    job = _job_access(data["job_id"])
    if not job or job["training_run_id"] != case["training_run_id"]:
        return error_response("IMPORT_NOT_FOUND", "الاستيراد غير موجود ضمن نطاق القضية", 404)
    if job["status"] != "completed":
        return error_response("IMPORT_NOT_READY", "انتظر اكتمال الاستيراد قبل ربطه", 409)
    rows = (
        get_db()
        .execute(
            "SELECT id FROM security_events WHERE workspace_id = ? AND training_run_id IS ? AND id > ? AND idempotency_key LIKE ? ORDER BY id LIMIT 201",
            (workspace_id(), case["training_run_id"], data.get("after_id", 0), f"import:{job['content_hash']}:%"),
        )
        .fetchall()
    )
    with transaction():
        current = _case_row(case_id)
        if current is None or current["status"] == "closed":
            return error_response("CASE_EVIDENCE_LOCKED", "الأدلة مقفلة بعد إغلاق التحقيق", 409)
        added = 0
        for event in rows[:200]:
            existing = get_db().execute("SELECT 1 FROM case_events WHERE case_id = ? AND event_id = ?", (case_id, event["id"])).fetchone()
            if not _attach_event(get_db(), case_id, event["id"]):
                raise RuntimeError("import event scope changed")
            added += not bool(existing)
        if added:
            _history(get_db(), case_id, "import_attached", None, {"job_id": job["id"], "added": added, "sha256": job["content_hash"]})
            record_audit(get_db(), "attach", "case_import", job["id"], details={"case_id": case_id, "added": added})
    return jsonify({"added": added, "has_more": len(rows) > 200, "next_after_id": rows[min(len(rows), 200) - 1]["id"] if rows else data.get("after_id", 0)})


@cases_api.post("/api/incidents/<int:case_id>/techniques")
@require_permission("cases.update")
def annotate_technique(case_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error_response("INVALID_JSON", "يلزم إرسال كائن JSON", 400)
    technique, reason, assessment, event_id = data.get("technique_id"), data.get("reason"), data.get("assessment"), data.get("event_id")
    if (
        not isinstance(technique, str)
        or not 1 <= len(technique) <= 20
        or not isinstance(reason, str)
        or not 3 <= len(reason.strip()) <= 2000
        or not isinstance(assessment, str)
        or assessment not in {"suggested", "verified", "rejected"}
        or event_id is not None
        and type(event_id) is not int
    ):
        return error_response("INVALID_TECHNIQUE_ANNOTATION", "حدد تقنية وتصنيفًا وسببًا ودليلًا صالحًا", 422)
    technique_row = get_db().execute("SELECT technique_id, attack_version FROM attack_techniques WHERE technique_id = ?", (technique,)).fetchone()
    if not technique_row:
        return error_response("TECHNIQUE_NOT_FOUND", "التقنية غير موجودة في كتالوج ATT&CK", 422)
    if event_id is not None and not get_db().execute("SELECT 1 FROM case_events WHERE case_id = ? AND event_id = ?", (case_id, event_id)).fetchone():
        return error_response("CASE_EVENT_NOT_FOUND", "الدليل غير مرتبط بهذه القضية", 422)
    if assessment == "verified" and event_id is None:
        return error_response("TECHNIQUE_EVIDENCE_REQUIRED", "الربط المتحقق يتطلب سجلًا مرتبطًا بالقضية", 422)
    with transaction():
        case = _case_row(case_id)
        if case is None or case["status"] == "closed":
            return error_response("CASE_EVIDENCE_LOCKED", "أعد فتح القضية قبل إضافة استنتاج جديد", 409)
        cursor = get_db().execute(
            "INSERT INTO case_technique_annotations (case_id, technique_id, attack_version, event_id, assessment, reason, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (case_id, technique, technique_row["attack_version"], event_id, assessment, reason.strip(), actor_id(), iso_now()),
        )
        annotation_id = inserted_id(cursor)
        _history(get_db(), case_id, "technique_annotated", None, {"id": annotation_id, "technique_id": technique, "assessment": assessment}, reason.strip())
        record_audit(
            get_db(), "create", "case_technique_annotation", annotation_id, details={"case_id": case_id, "technique_id": technique, "assessment": assessment}
        )
    return jsonify({"id": annotation_id}), 201


@cases_api.post("/api/incidents/<int:case_id>/tasks")
@require_permission("cases.update")
def add_task(case_id: int):
    case = _case_row(case_id)
    if not case:
        return error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
    if case["status"] == "closed":
        return error_response("CASE_CLOSED", "المهام مقفلة بعد إغلاق القضية", 409)
    data = request.get_json(silent=True)
    payload = data if isinstance(data, dict) else {}
    title = payload.get("title")
    assignee = payload.get("assignee")
    if not isinstance(title, str) or not 2 <= len(title.strip()) <= 255 or assignee is not None and not _user_valid(assignee):
        return error_response("INVALID_TASK", "بيانات المهمة غير صالحة", 422)
    cursor = get_db().execute(
        "INSERT INTO case_tasks (case_id, title, required, status, assignee, created_at) VALUES (?, ?, ?, 'pending', ?, ?)",
        (case_id, title.strip(), 1 if payload.get("required") else 0, assignee, iso_now()),
    )
    task_id = inserted_id(cursor)
    _history(get_db(), case_id, "task_added", None, {"task_id": task_id})
    return jsonify({"id": task_id}), 201


@cases_api.patch("/api/incidents/<int:case_id>/tasks/<int:task_id>")
@require_permission("cases.update")
def update_task(case_id: int, task_id: int):
    case = _case_row(case_id)
    if not case:
        return error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
    if case["status"] == "closed":
        return error_response("CASE_CLOSED", "المهام مقفلة بعد إغلاق القضية", 409)
    task = get_db().execute("SELECT * FROM case_tasks WHERE id = ? AND case_id = ?", (task_id, case_id)).fetchone()
    data = request.get_json(silent=True)
    status = data.get("status") if isinstance(data, dict) else None
    if not task or not isinstance(status, str) or status not in {"pending", "in_progress", "completed", "reviewed"}:
        return error_response("INVALID_TASK_UPDATE", "المهمة أو حالتها غير صالحة", 422)
    assignment = get_db().execute("SELECT assignee FROM team_log_assignments WHERE task_id = ?", (task_id,)).fetchone()
    if assignment and assignment["assignee"] != actor_id() and (current_user() or {}).get("role") not in {"admin", "soc_manager"}:
        return error_response("PERMISSION_DENIED", "المهمة مخصصة لعضو آخر", 403)
    completed_at = iso_now() if status in {"completed", "reviewed"} else None
    completed_by = actor_id() if completed_at else None
    get_db().execute("UPDATE case_tasks SET status = ?, completed_by = ?, completed_at = ? WHERE id = ?", (status, completed_by, completed_at, task_id))
    _history(get_db(), case_id, "task_updated", task["status"], status)
    return jsonify({"id": task_id, "status": status})


def _report_payload(case_id: int) -> dict[str, Any]:
    case = _case_row(case_id)
    evidence = [
        dict(row)
        for row in get_db()
        .execute("SELECT evidence_type, reference_id, title, sha256, added_at FROM case_evidence WHERE case_id = ? ORDER BY added_at", (case_id,))
        .fetchall()
    ]
    history = [
        dict(row)
        for row in get_db()
        .execute("SELECT action, previous_value, new_value, reason, created_at FROM case_history WHERE case_id = ? ORDER BY created_at", (case_id,))
        .fetchall()
    ]
    events = [
        dict(row)
        for row in get_db()
        .execute(
            "SELECT e.id, e.event_id, e.event_time, e.ingested_at, e.source, e.event_type, e.title, e.severity, e.raw_hash, e.mitre_ids FROM case_events ce JOIN security_events e ON e.id = ce.event_id WHERE ce.case_id = ? ORDER BY e.event_time, e.id",
            (case_id,),
        )
        .fetchall()
    ]
    annotations = [dict(row) for row in get_db().execute("SELECT * FROM case_technique_annotations WHERE case_id = ? ORDER BY id", (case_id,)).fetchall()]
    notes = [
        dict(row)
        for row in get_db()
        .execute("SELECT author_id, body, created_at FROM case_notes WHERE case_id = ? AND visibility = 'team' ORDER BY id", (case_id,))
        .fetchall()
    ]
    tasks = [
        dict(row)
        for row in get_db()
        .execute("SELECT title, status, assignee, completed_by, completed_at FROM case_tasks WHERE case_id = ? ORDER BY id", (case_id,))
        .fetchall()
    ]
    alerts = [
        dict(row)
        for row in get_db()
        .execute(
            "SELECT a.alert_id, a.rule_id, a.rule_version, a.reason, a.severity, a.confidence, a.status, a.detected_at FROM case_alerts ca JOIN alerts a ON a.id = ca.alert_id WHERE ca.case_id = ? ORDER BY a.detected_at, a.id",
            (case_id,),
        )
        .fetchall()
    ]
    responses = [
        dict(row)
        for row in get_db()
        .execute("SELECT run_id, state, requested_by, approved_by, started_at, completed_at FROM playbook_runs WHERE case_id = ? ORDER BY id", (case_id,))
        .fetchall()
    ]
    return {
        "case": _case_view(case),
        "evidence": evidence,
        "timeline": history,
        "event_timeline": events,
        "technique_annotations": annotations,
        "notes": notes,
        "tasks": tasks,
        "alerts": alerts,
        "responses": responses,
        "generated_at": iso_now(),
    }


def _report_html(payload: dict[str, Any]) -> str:
    case = payload["case"]
    evidence_rows = "".join(
        f'<tr><td>{html.escape(str(item["evidence_type"]))}</td><td>{html.escape(str(item["title"]))}</td><td dir="ltr">{html.escape(str(item["sha256"]))}</td></tr>'
        for item in payload["evidence"]
    )
    fields = (
        ("التصنيف النهائي", "disposition"),
        ("السبب الجذري", "root_cause"),
        ("الأثر", "impact"),
        ("ملخص الاستجابة", "response_summary"),
        ("ملخص الأدلة", "evidence_summary"),
        ("الدروس المستفادة", "lessons_learned"),
        ("التحقق", "validation"),
    )
    closure = "".join(f"<p><strong>{label}:</strong> {html.escape(str(case.get(field) or 'غير محدد'))}</p>" for label, field in fields)
    for heading, key in (
        ("الخط الزمني للسجلات", "event_timeline"),
        ("تقييم تقنيات ATT&CK", "technique_annotations"),
        ("ملاحظات التحقيق المشتركة", "notes"),
        ("المهام", "tasks"),
        ("التنبيهات", "alerts"),
        ("الاستجابات", "responses"),
        ("سجل النشاط", "timeline"),
    ):
        rows = payload[key]
        closure += f"<h2>{heading}</h2>"
        if rows:
            closure += "".join(
                '<article class="report-record"><dl>'
                + "".join(
                    f"<dt>{html.escape(str(column))}</dt><dd>{html.escape(str(value) if value is not None else '—')}</dd>" for column, value in row.items()
                )
                + "</dl></article>"
                for row in rows
            )
        else:
            closure += "<p>لا توجد عناصر مسجلة</p>"
    return f'<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><title>{html.escape(str(case["reference"]))}</title><style>{report_style()}</style></head><body><h1>{html.escape(str(case["reference"]))}: {html.escape(str(case["title"]))}</h1><p><strong>الحالة:</strong> {html.escape(str(case["status"]))}</p>{closure}<h2>الأدلة</h2><table><thead><tr><th>النوع</th><th>العنوان</th><th>SHA-256</th></tr></thead><tbody>{evidence_rows}</tbody></table><p>وقت التوليد: {html.escape(str(payload["generated_at"]))}</p></body></html>'


def _generate_reports(case_id: int) -> None:
    payload = _report_payload(case_id)
    revision = int(get_db().execute("SELECT COALESCE(MAX(revision), 0) + 1 FROM case_reports WHERE case_id = ?", (case_id,)).fetchone()[0])
    json_content = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    html_content = _report_html(payload)
    now = iso_now()
    for report_format, content in (("json", json_content), ("html", html_content)):
        get_db().execute(
            "INSERT INTO case_reports (case_id, revision, format, content, sha256, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (case_id, revision, report_format, content, hashlib.sha256(content.encode()).hexdigest(), actor_id(), now),
        )
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
    revision_value = request.args.get("revision")
    try:
        revision = int(revision_value) if revision_value is not None else None
        if revision is not None and revision < 1:
            raise ValueError
    except ValueError:
        return error_response("REPORT_REVISION_INVALID", "إصدار التقرير غير صالح", 422)
    row = (
        get_db()
        .execute(
            "SELECT * FROM case_reports WHERE case_id = ? AND format = ? AND (? IS NULL OR revision = ?) ORDER BY revision DESC LIMIT 1",
            (case_id, report_format, revision, revision),
        )
        .fetchone()
    )
    if not row:
        if revision is not None:
            return error_response("REPORT_NOT_FOUND", "إصدار التقرير غير موجود", 404)
        if case["status"] != "closed":
            return error_response("REPORT_NOT_READY", "يتوفر التقرير النهائي بعد إغلاق التحقيق", 409)
        with transaction():
            _generate_reports(case_id)
        row = (
            get_db().execute("SELECT * FROM case_reports WHERE case_id = ? AND format = ? ORDER BY revision DESC LIMIT 1", (case_id, report_format)).fetchone()
        )
    if row is None:
        raise RuntimeError("Report generation returned no result")
    mimetype = "application/json" if report_format == "json" else "text/html; charset=utf-8"
    return Response(
        row["content"],
        mimetype=mimetype,
        headers={"Content-Disposition": f"attachment; filename={case['reference']}.{report_format}", "X-Report-SHA256": row["sha256"]},
    )
