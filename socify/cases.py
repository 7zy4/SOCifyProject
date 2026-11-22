import hashlib
import hmac
import json
import re
import sqlite3
from datetime import timedelta
from typing import Any

from flask import Blueprint, Response, current_app, jsonify, request

from .audit import record_audit
from .autopsy_pipeline import visibility_sql
from .case_policy import case_policy
from .case_titles import localized_case_title
from .db import get_db, inserted_id, transaction
from .file_names import attachment_disposition
from .operational import case_scope, case_visible
from .security import (
    actor_id,
    current_user,
    decrypt_secret,
    encrypt_secret,
    error_response,
    has_permission,
    require_permission,
    workspace_id,
)
from .timeutils import iso_now, utc_now
from .validation import ValidationError, public_error_message

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
    """The case row when it exists in the user's team, is not archived and is visible to them; otherwise None."""
    row = get_db().execute("SELECT * FROM incident_cases WHERE id = ? AND workspace_id = ? AND archived_at IS NULL", (case_id, workspace_id())).fetchone()
    user = current_user()
    return row if row and user and case_visible(case_id, user) else None


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
        raise ValidationError(f"{field} must be a list of short strings")
    return value


def _history(connection: sqlite3.Connection, case_id: int, action: str, previous: object = None, new: object = None, reason: str | None = None) -> None:
    """Append an entry to the case's history with the actor, before and after values, reason and correlation id."""
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
    user = current_user() or {}
    if owner_case_id is None:
        return user.get("role") in {"admin", "soc_manager"} or created_by == actor_id()
    return case_visible(owner_case_id, user)


def _attach_event(connection: sqlite3.Connection, case_id: int, event_id: int) -> bool:
    event = connection.execute(
        "SELECT id, event_id, title, raw_hash, provenance, owner_case_id, created_by, import_job_id FROM security_events WHERE id = ? AND workspace_id = ?",
        (event_id, workspace_id()),
    ).fetchone()
    case = connection.execute("SELECT id FROM incident_cases WHERE id = ? AND workspace_id = ?", (case_id, workspace_id())).fetchone()
    if not event or not case:
        return False
    scope, params = visibility_sql("e", active_only=False)
    if not connection.execute(f"SELECT 1 FROM security_events e WHERE e.id=? AND {scope}", (event_id, *params)).fetchone():
        return False
    already_linked = connection.execute("SELECT 1 FROM case_events WHERE case_id = ? AND event_id = ?", (case_id, event_id)).fetchone()
    if not already_linked and not _source_visible(event["owner_case_id"], event["created_by"]):
        return False
    from .event_identity import visible_provenance

    occurrence = visible_provenance(connection, event_id, current_user())
    provenance = occurrence["provenance"] if occurrence else event["provenance"]
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
            provenance or "{}",
            actor_id(),
            now,
        ),
    )
    return True


def _attach_alert(connection: sqlite3.Connection, case_id: int, alert_id: int) -> bool:
    alert = connection.execute(
        "SELECT id, alert_id, reason, dedup_key, evidence, owner_case_id FROM alerts WHERE id = ? AND workspace_id = ?",
        (alert_id, workspace_id()),
    ).fetchone()
    case = connection.execute("SELECT id FROM incident_cases WHERE id = ? AND workspace_id = ?", (case_id, workspace_id())).fetchone()
    if not alert or not case:
        return False
    if not _source_visible(alert["owner_case_id"]):
        return False
    events = connection.execute(
        "SELECT e.id, e.workspace_id, e.owner_case_id, e.created_by, e.import_job_id FROM alert_events ae JOIN security_events e ON e.id=ae.event_id WHERE ae.alert_id=?",
        (alert_id,),
    ).fetchall()
    if any(
        event["workspace_id"] != workspace_id()
        or not _source_visible(event["owner_case_id"], event["created_by"])
        or not connection.execute(
            f"SELECT 1 FROM security_events e WHERE e.id=? AND {visibility_sql('e', active_only=False)[0]}",
            (event["id"], *visibility_sql("e", active_only=False)[1]),
        ).fetchone()
        for event in events
    ):
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
    for event in events:
        _attach_event(connection, case_id, int(event["id"]))
    return True


def _case_view(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        raise RuntimeError("case disappeared during request")
    item = dict(row)
    # `title` follows the interface language; both stored names stay available for forms and exports.
    item["title_ar"], item["title_en"] = row["title"], row["title_en"]
    item["title"] = localized_case_title(row["title"], row["title_en"])
    item["tags"] = json.loads(item["tags"] or "[]")
    item["mitre_ids"] = json.loads(item["mitre_ids"] or "[]")
    item["overdue"] = bool(item["sla_due_at"] and item["status"] not in {"closed", "cancelled"} and item["sla_due_at"] < iso_now())
    context = get_db().execute("SELECT * FROM autopsy_case_context WHERE case_id = ?", (row["id"],)).fetchone()
    item["context"] = dict(context) if context else None
    from .autopsy_workspace import approval

    item["approval"] = approval(row["id"])
    scope, scope_args = case_scope(current_user() or {})
    item["related_case_ids"] = [
        related[0]
        for related in get_db().execute(
            f"SELECT c.id FROM case_relationships rel JOIN incident_cases c ON c.id=CASE WHEN rel.first_id=? THEN rel.second_id ELSE rel.first_id END WHERE (rel.first_id=? OR rel.second_id=?) AND c.workspace_id=? AND c.archived_at IS NULL{scope}",
            (row["id"], row["id"], row["id"], workspace_id(), *scope_args),
        )
    ]
    from .autopsy_pipeline import case_full_access

    item["full_case_access"] = case_full_access(row["id"])
    if not item["full_case_access"]:
        allowed = {
            "id",
            "reference",
            "title",
            "status",
            "severity",
            "priority",
            "created_at",
            "updated_at",
            "version",
            "context",
            "full_case_access",
            "approval",
            "related_case_ids",
        }
        item = {key: value for key, value in item.items() if key in allowed}
        if item["context"]:
            item["context"] = {key: value for key, value in item["context"].items() if key in {"case_id", "reason", "objective", "confidentiality"}}
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
    for parameter, column in (
        ("status", "c.status"),
        ("severity", "c.severity"),
        ("priority", "c.priority"),
        ("assignee", "c.assignee"),
    ):
        value = request.args.get(parameter)
        if value:
            clauses.append(f"{column} = ?")
            parameters.append(value)
    query = request.args.get("q", "").strip()
    if query:
        if len(query) > 200:
            return error_response("QUERY_TOO_LONG", "نص البحث طويل جدًا", 422)
        like = f"%{query}%"
        clauses.append("(c.reference LIKE ? OR c.title LIKE ? OR c.title_en LIKE ?)")
        parameters.extend([like, like, like])
    where = " AND ".join(clauses)
    total = int(get_db().execute(f"SELECT COUNT(*) FROM incident_cases c WHERE {where}", parameters).fetchone()[0])
    rows = (
        get_db()
        .execute(
            f"""SELECT c.*, socify_user_name(u.name,u.name_ar,u.name_en) AS assignee_name,
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
    key = request.headers.get("Idempotency-Key")
    retry = None
    if key is not None:
        try:
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{8,128}", key):
                raise ValueError
            digest = hashlib.sha256(json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        except (ValueError, TypeError, UnicodeError, RecursionError):
            return error_response("INVALID_CASE_REQUEST", "معرف إعادة المحاولة أو بيانات القضية غير صالحة", 422)
        retry = key, digest
    return _create_case(data, retry)


def _case_creation_receipt(retry: tuple[str, str]):
    row = (
        get_db()
        .execute(
            "SELECT request_hash,case_id FROM case_creation_receipts WHERE workspace_id=? AND actor_id=? AND request_key=?",
            (workspace_id(), actor_id(), retry[0]),
        )
        .fetchone()
    )
    if row is None:
        return None
    if row["request_hash"] != retry[1]:
        return error_response("CASE_REQUEST_CONFLICT", "تغير محتوى الطلب؛ أعد المحاولة كعملية جديدة", 409)
    case = _case_row(row["case_id"])
    if case is None:
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    # Current scope and view apply, including a colleague's later assignment or approval.
    return jsonify(_case_view(case)), 201, {"Location": f"/api/incidents/{case['id']}"}


def _create_case(data: dict[str, Any], retry: tuple[str, str] | None = None):
    if retry is not None:
        recovered = _case_creation_receipt(retry)
        if recovered is not None:
            return recovered
    reason = data["reason"] if "reason" in data and data["reason"] is not None else "tactical_triage"
    objective = data["objective"] if "objective" in data and data["objective"] is not None else "التحقيق الأولي السريع وتحديد المؤشرات والإجراء المناسب"
    classification = data.get("classification", "confidential")
    from .autopsy_domain import text_value

    allowed = {
        "title",
        "title_en",
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
        return error_response("INVALID_CASE", public_error_message(exc, "Check the case fields"), 422)
    data.setdefault("assignee", actor_id())
    title = data.get("title")
    description = data.get("description", "")
    severity = str(data.get("severity", "medium")).lower()
    priority = str(data.get("priority", severity if severity in PRIORITIES else "medium")).lower()
    assignee = data.get("assignee", data.get("assigned_to"))
    if not isinstance(title, str) or not 3 <= len(title.strip()) <= 255 or not isinstance(description, str) or len(description) > 10000:
        return error_response("INVALID_CASE", "عنوان التحقيق مطلوب ويجب ألا يتجاوز 255 محرفًا", 422)
    title_en = data.get("title_en", "")
    if not isinstance(title_en, str) or len(title_en) > 255 or 0 < len(title_en.strip()) < 3:
        return error_response("INVALID_CASE", "اسم القضية بالإنجليزية من 3 إلى 255 محرفًا", 422)
    if severity not in SEVERITIES or priority not in PRIORITIES:
        return error_response("INVALID_CASE_PRIORITY", "درجة الخطورة أو الأولوية غير صالحة", 422)
    if assignee is not None and not _user_valid(assignee):
        return error_response("INVALID_ASSIGNEE", "المحلل المحدد غير متاح في مساحة العمل", 422)
    try:
        tags = _json_list(data.get("tags"), "tags")
        mitre_ids = _json_list(data.get("mitre_ids"), "mitre_ids", 20)
    except ValueError as exc:
        return error_response("INVALID_CASE_METADATA", public_error_message(exc, "Check the case fields"), 422)
    event_ids = data.get("event_ids", [])
    alert_ids = data.get("alert_ids", [])
    if not isinstance(event_ids, list) or any(not isinstance(item, int) for item in event_ids) or len(event_ids) > 100:
        return error_response("INVALID_EVENT_LINKS", "قائمة السجلات غير صالحة", 422)
    if not isinstance(alert_ids, list) or any(not isinstance(item, int) for item in alert_ids) or len(alert_ids) > 100:
        return error_response("INVALID_ALERT_LINKS", "قائمة التنبيهات غير صالحة", 422)
    now = iso_now()
    sla_hours = {"urgent": 1, "high": 4, "medium": 24, "low": 72}[priority]
    sla_due = (utc_now() + timedelta(hours=sla_hours)).isoformat().replace("+00:00", "Z")
    user = current_user()
    team = str(data.get("team") or (user.get("team") if user else "") or "")[:120]
    with transaction():
        if retry is not None:
            recovered = _case_creation_receipt(retry)
            if recovered is not None:
                return recovered
        for event_id in event_ids:
            event = (
                get_db()
                .execute("SELECT owner_case_id, created_by FROM security_events WHERE id = ? AND workspace_id = ?", (event_id, workspace_id()))
                .fetchone()
            )
            if not event or not _source_visible(event["owner_case_id"], event["created_by"]):
                return error_response("EVENT_NOT_FOUND", "السجل غير موجود", 404)
        for alert_id in alert_ids:
            alert = get_db().execute("SELECT owner_case_id FROM alerts WHERE id = ? AND workspace_id = ?", (alert_id, workspace_id())).fetchone()
            if not alert or not _source_visible(alert["owner_case_id"]):
                return error_response("ALERT_NOT_FOUND", "التنبيه غير موجود", 404)
        cursor = get_db().execute(
            """INSERT INTO incident_cases
            (reference, workspace_id, title, title_en, description, case_type, severity, priority, status,
            assignee, team, sla_due_at, creator, reporter, tags, mitre_ids, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                _reference(get_db()),
                workspace_id(),
                title.strip(),
                title_en.strip(),
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
        _record_case_setup(alert_ids, assignee, case_id, classification, event_ids, now, objective, reason)
        if retry is not None:
            get_db().execute(
                "INSERT INTO case_creation_receipts(workspace_id,actor_id,request_key,request_hash,case_id,created_at) VALUES (?,?,?,?,?,?)",
                (workspace_id(), actor_id(), retry[0], retry[1], case_id, now),
            )
    row = _case_row(case_id)
    return jsonify(_case_view(row)), 201, {"Location": f"/api/incidents/{case_id}"}


def _record_case_setup(alert_ids, assignee, case_id, classification, event_ids, now, objective, reason):
    """Write what every new case starts with: its context, approval state, members, linked events and alerts, default tasks, history entry and audit record."""
    get_db().execute(
        "INSERT INTO autopsy_case_context(case_id, reason, objective, classification, created_at) VALUES (?, ?, ?, ?, ?)",
        (case_id, str(reason).strip(), str(objective).strip(), classification, now),
    )
    if current_app.config.get("REQUIRE_CASE_APPROVAL"):
        get_db().execute("INSERT INTO case_approvals(case_id,state,requested_by) VALUES (?,'pending',?)", (case_id, actor_id()))
    else:
        get_db().execute(
            "INSERT INTO case_approvals(case_id,state,requested_by,reviewed_by,reviewed_at,reason,source) VALUES (?,'approved',?,?,?,'Direct tactical investigation','direct_investigation')",
            (case_id, actor_id(), actor_id(), now),
        )
    for member in {actor_id(), assignee} - {None}:
        get_db().execute(
            "INSERT INTO autopsy_case_members(case_id, user_id, responsibility, assigned_by, assigned_at) VALUES (?, ?, 'analyst', ?, ?)",
            (case_id, member, actor_id(), now),
        )
    for event_id in event_ids:
        if not _attach_event(get_db(), case_id, event_id):
            raise ValidationError(f"event {event_id} is unavailable")
    for alert_id in alert_ids:
        if not _attach_alert(get_db(), case_id, alert_id):
            raise ValidationError(f"alert {alert_id} is unavailable")
    get_db().executemany(
        "INSERT INTO case_tasks (case_id, title, system_key, required, status, assignee, created_at) VALUES (?, ?, ?, 1, 'pending', ?, ?)",
        [
            (case_id, "Validate primary evidence", "validate_evidence", assignee, now),
            (case_id, "Document response decision", "document_response", assignee, now),
        ],
    )
    _history(get_db(), case_id, "case_created", None, {"status": "new"})
    record_audit(get_db(), "create", "case", case_id, details={"events": event_ids, "alerts": alert_ids})


@cases_api.post("/api/alerts/<int:alert_id>/case")
@require_permission("cases.create")
def case_from_alert(alert_id: int):
    alert = (
        get_db().execute("SELECT reason, severity, mitre_technique_ids FROM alerts WHERE id = ? AND workspace_id = ?", (alert_id, workspace_id())).fetchone()
    )
    if not alert:
        return error_response("ALERT_NOT_FOUND", "التنبيه غير موجود", 404)
    data = request.get_json(silent=True)
    body = data if isinstance(data, dict) else {}
    body.setdefault("title", f"Investigation: {alert['reason'][:180]}")
    body.setdefault("description", alert["reason"])
    body.setdefault("severity", alert["severity"])
    body.setdefault("priority", alert["severity"] if alert["severity"] in PRIORITIES else "medium")
    body["alert_ids"] = [alert_id]
    body.setdefault("mitre_ids", json.loads(alert["mitre_technique_ids"] or "[]"))
    return _create_case(body)


@cases_api.get("/api/incidents/<int:case_id>")
@case_policy(before_approval={"GET"}, batch_member={"GET"})
@require_permission("cases.read")
def case_detail(case_id: int):
    from .autopsy_api import case_summary

    return case_summary(case_id)


@cases_api.patch("/api/incidents/<int:case_id>")
@require_permission("cases.update")
def update_case(case_id: int):
    row = _case_row(case_id)
    if not row:
        return error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error_response("INVALID_JSON", "يلزم إرسال كائن JSON صالح", 400)
    allowed = {
        "version",
        "title",
        "title_en",
        "description",
        "team",
        "severity",
        "priority",
        "assignee",
        "assigned_to",
        "tags",
        "mitre_ids",
        "status",
        "reason",
    }
    if set(data) - allowed or type(data.get("version")) is not int:
        return error_response("INVALID_CASE_UPDATE", "أرسل الإصدار والحقول المعروفة", 422)
    supplied_version = data.get("version")
    if supplied_version is not None and supplied_version != row["version"]:
        return error_response("CASE_VERSION_CONFLICT", "تم تعديل التحقيق في جلسة أخرى. حدّث البيانات ثم أعد المحاولة", 409, {"current_version": row["version"]})
    if "status" in data:
        return _transition(case_id, row, str(data["status"]), str(data.get("reason") or "Legacy status update"), data)
    updates: dict[str, Any] = {}
    for field, maximum in (("title", 255), ("title_en", 255), ("description", 10000), ("team", 120)):
        if field in data:
            value = data[field]
            # The Arabic name needs three characters; the English name may be blank (older cases) or three or more.
            length = len(value.strip()) if isinstance(value, str) else 0
            short = length < 3 if field == "title" else field == "title_en" and 0 < length < 3
            if not isinstance(value, str) or short or len(value) > maximum:
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
                return error_response("INVALID_CASE_FIELD", public_error_message(exc, "Invalid case field"), 422)
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
    return jsonify(_case_view(_case_row(case_id)))


def _transition(case_id: int, row: sqlite3.Row, target: str, reason: str, data: dict[str, Any]):
    from .autopsy_reports import transition_operational

    return transition_operational(case_id, row, target, reason, data)


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
    if row["status"] == "closed":
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
    note = (
        get_db()
        .execute(
            "SELECT n.*, socify_user_name(u.name,u.name_ar,u.name_en) AS author_name FROM case_notes n JOIN users u ON u.id = n.author_id WHERE n.id = ?",
            (note_id,),
        )
        .fetchone()
    )
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
        or evidence_type not in {"ioc", "artifact", "raw_log"}
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
    if not has_permission(current_user(), "evidence.download"):
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
            raise ValidationError("digest mismatch")
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
            "Content-Disposition": attachment_disposition(f"evidence-{evidence_id}.txt"),
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
    if not job:
        return error_response("IMPORT_NOT_FOUND", "الاستيراد غير موجود ضمن نطاق القضية", 404)
    if job["status"] != "completed":
        return error_response("IMPORT_NOT_READY", "انتظر اكتمال الاستيراد قبل ربطه", 409)
    rows = (
        get_db()
        .execute(
            "SELECT id FROM security_events WHERE workspace_id = ? AND id > ? AND idempotency_key LIKE ? ORDER BY id LIMIT 201",
            (workspace_id(), data.get("after_id", 0), f"import:{job['content_hash']}:%"),
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
    assignment = get_db().execute("SELECT id, assignee FROM team_log_assignments WHERE task_id = ?", (task_id,)).fetchone()
    if assignment:
        if assignment["assignee"] != actor_id() and (current_user() or {}).get("role") not in {"admin", "soc_manager"}:
            return error_response("PERMISSION_DENIED", "المهمة مخصصة لعضو آخر", 403)
        from .teams import update_assignment_status

        return update_assignment_status(assignment["id"], status, data.get("expected_status") if isinstance(data, dict) else None)
    with transaction():
        case = _case_row(case_id)
        if not case:
            return error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
        if case["status"] == "closed":
            return error_response("CASE_CLOSED", "المهام مقفلة بعد إغلاق القضية", 409)
        task = get_db().execute("SELECT * FROM case_tasks WHERE id = ? AND case_id = ?", (task_id, case_id)).fetchone()
        if not task:
            return error_response("INVALID_TASK_UPDATE", "المهمة أو حالتها غير صالحة", 422)
        if status == task["status"]:
            return jsonify({"id": task_id, "status": status, "updated": False, "case_version_before": case["version"], "case_version": case["version"]})
        expected = data.get("expected_status") if isinstance(data, dict) else None
        if expected is not None and expected != task["status"]:
            return error_response("TASK_CHANGED", "تغيرت المهمة. حدّث القائمة قبل المتابعة", 409)
        completed_at = iso_now() if status in {"completed", "reviewed"} else None
        completed_by = actor_id() if completed_at else None
        get_db().execute("UPDATE case_tasks SET status = ?, completed_by = ?, completed_at = ? WHERE id = ?", (status, completed_by, completed_at, task_id))
        _history(get_db(), case_id, "task_updated", task["status"], status)
        version = get_db().execute("SELECT version FROM incident_cases WHERE id=?", (case_id,)).fetchone()[0]
        return jsonify({"id": task_id, "status": status, "updated": True, "case_version_before": case["version"], "case_version": version})


@cases_api.get("/api/incidents/<int:case_id>/report")
@require_permission("cases.read")
def get_report(case_id: int):
    case = _case_row(case_id)
    if not case:
        return error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
    if not has_permission(current_user(), "evidence.download"):
        return error_response("PERMISSION_DENIED", "تنزيل التقرير المؤرشف يتطلب صلاحية تنزيل الأدلة", 403)
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
        return error_response("REPORT_NOT_FOUND", "لا يوجد تقرير مؤرشف؛ أنشئ تقريرًا من مساحة القضية", 404)
    if row is None:
        raise RuntimeError("Report generation returned no result")
    if hashlib.sha256(row["content"].encode()).hexdigest() != row["sha256"]:
        return error_response("REPORT_INTEGRITY_FAILED", "بصمة التقرير المؤرشف غير مطابقة", 409)
    mimetype = "application/json" if report_format == "json" else "text/html; charset=utf-8"
    return Response(
        row["content"],
        mimetype=mimetype,
        headers={"Content-Disposition": attachment_disposition(f"{case['reference']}.{report_format}"), "X-Report-SHA256": row["sha256"]},
    )
