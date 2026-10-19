import csv
import hashlib
import io
import json
import sqlite3
from typing import Any

from flask import Blueprint, Response, jsonify, request

from .audit import record_audit
from .db import get_db, inserted_id, transaction
from .detection import SEVERITIES, evaluate_rules
from .schema import insert_outbox, public_id
from .security import actor_id, can_access_training_run, error_response, require_permission, training_scope_sql, workspace_id
from .timeutils import iso_now, iso_timestamp

events_api = Blueprint("events", __name__)

EVENT_STATUSES = {"open", "investigating", "resolved", "false_positive"}
SORT_FIELDS = {"event_time", "ingested_at", "severity", "source", "event_type", "id"}


def _raw_object(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return {"message": value}
    if value is None:
        return {}
    return {"value": str(value)}


def _string(value: object, maximum: int, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise ValueError("required string is missing")
        return None
    if not isinstance(value, str):
        raise ValueError("value must be a string")
    normalized = value.strip()
    if required and not normalized:
        raise ValueError("required string is empty")
    if len(normalized) > maximum:
        raise ValueError(f"string exceeds {maximum} characters")
    return normalized or None


def normalize_event(data: dict[str, Any]) -> dict[str, Any]:
    raw = _raw_object(data.get("raw_payload", data.get("raw_data")))
    source = _string(data.get("source"), 100, True)
    severity = str(data.get("severity", "medium")).lower()
    if severity not in SEVERITIES:
        raise ValueError("severity must be critical, high, medium, or low")
    category = _string(data.get("category", data.get("event_type", "general")), 100, True)
    event_type = _string(data.get("event_type", raw.get("event_type")), 100) or str(category).lower().replace(" ", "_")
    lowered_category = str(category).casefold()
    if "brute force" in lowered_category or "failed login" in lowered_category or str(raw.get("outcome", "")).casefold() in {"failed", "failure"} and str(raw.get("action", "")).casefold() in {"login", "authenticate"}:
        event_type = "failed_login"
    title = _string(data.get("title", event_type.replace("_", " ").title()), 255, True)
    description = _string(data.get("description", ""), 4000) or ""
    event_time = iso_timestamp(data.get("event_time", data.get("timestamp", iso_now())))
    normalized = data.get("normalized_fields")
    if not isinstance(normalized, dict):
        normalized = {}
    aliases = {
        "source_ip": ("source_ip", "src_ip", "ip"),
        "destination_ip": ("destination_ip", "dst_ip"),
        "username": ("username", "user"),
        "hostname": ("hostname", "host"),
        "process_name": ("process_name", "process"),
        "parent_process": ("parent_process", "parent_process_name"),
        "file_hash": ("file_hash", "sha256"),
        "http_status": ("http_status", "status_code"),
        "action": ("action",),
        "outcome": ("outcome", "result"),
    }
    extracted: dict[str, Any] = {}
    for target, candidates in aliases.items():
        selected = data.get(target)
        if selected is None:
            selected = normalized.get(target)
        if selected is None:
            for candidate in candidates:
                if raw.get(candidate) is not None:
                    selected = raw[candidate]
                    break
        extracted[target] = selected
    for name in ("source_ip", "destination_ip", "username", "hostname", "process_name", "parent_process", "file_hash", "action", "outcome"):
        if extracted[name] is not None:
            extracted[name] = _string(str(extracted[name]), 512)
    if extracted["http_status"] is not None:
        try:
            extracted["http_status"] = int(extracted["http_status"])
        except (TypeError, ValueError) as exc:
            raise ValueError("http_status must be an integer") from exc
    tags = data.get("tags", [])
    mitre_ids = data.get("mitre_ids", [])
    if not isinstance(tags, list) or len(tags) > 50 or any(not isinstance(item, str) or len(item) > 80 for item in tags):
        raise ValueError("tags must be a list of short strings")
    if not isinstance(mitre_ids, list) or len(mitre_ids) > 20 or any(not isinstance(item, str) for item in mitre_ids):
        raise ValueError("mitre_ids must be a list of identifiers")
    merged_normalized = {**normalized, **{key: value for key, value in extracted.items() if value is not None}}
    raw_serialized = json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    external_id = _string(data.get("external_id"), 255)
    idempotency_key = _string(data.get("idempotency_key"), 255)
    return {
        "external_id": external_id,
        "idempotency_key": idempotency_key,
        "source": source,
        "source_type": _string(data.get("source_type"), 80) or "training",
        "severity": severity,
        "category": category,
        "event_type": event_type,
        "title": title,
        "description": description,
        "event_time": event_time,
        "source_ip": extracted["source_ip"],
        "destination_ip": extracted["destination_ip"],
        "username": extracted["username"],
        "hostname": extracted["hostname"],
        "process_name": extracted["process_name"],
        "parent_process": extracted["parent_process"],
        "file_hash": extracted["file_hash"],
        "http_status": extracted["http_status"],
        "action": extracted["action"],
        "outcome": extracted["outcome"],
        "raw_data": raw_serialized,
        "normalized_fields": json.dumps(merged_normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        "tags": json.dumps(tags, ensure_ascii=False, separators=(",", ":")),
        "mitre_ids": json.dumps(mitre_ids, separators=(",", ":")),
        "parser_version": _string(data.get("parser_version"), 80) or "socify-normalizer-2",
        "raw_hash": hashlib.sha256(raw_serialized.encode()).hexdigest(),
        "provenance": json.dumps(data.get("provenance") if isinstance(data.get("provenance"), dict) else {}, ensure_ascii=False, separators=(",", ":")),
    }


def ingest_event(
    connection: sqlite3.Connection,
    data: dict[str, Any],
    actor: int | None,
    workspace: int,
    training_run_id: int | None = None,
) -> tuple[int, list[int], bool]:
    normalized = normalize_event(data)
    mitre_ids = json.loads(str(normalized["mitre_ids"]))
    if mitre_ids:
        placeholders = ",".join("?" for _ in mitre_ids)
        known = {row["technique_id"] for row in connection.execute(f"SELECT technique_id FROM attack_techniques WHERE technique_id IN ({placeholders})", mitre_ids).fetchall()}
        unknown = sorted(set(mitre_ids) - known)
        if unknown:
            raise ValueError(f"unknown ATT&CK technique identifiers: {', '.join(unknown)}")
    idempotency_key = normalized["idempotency_key"]
    if idempotency_key:
        existing = connection.execute("SELECT id FROM security_events WHERE workspace_id = ? AND idempotency_key = ?", (workspace, idempotency_key)).fetchone()
        if existing:
            return int(existing["id"]), [], True
    event_public_id = _string(data.get("event_id"), 80) or public_id("EVT")
    now = iso_now()
    cursor = connection.execute(
        """INSERT INTO security_events
        (event_id, external_id, idempotency_key, workspace_id, training_run_id, source, source_type, severity, category,
        event_type, title, description, event_time, ingested_at, timestamp, source_ip, destination_ip, username,
        hostname, process_name, parent_process, file_hash, http_status, action, outcome, raw_data, normalized_fields,
        tags, mitre_ids, status, assigned_to, created_by, parser_version, raw_hash, provenance)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', NULL, ?, ?, ?, ?)""",
        (
            event_public_id,
            normalized["external_id"],
            idempotency_key,
            workspace,
            training_run_id,
            normalized["source"],
            normalized["source_type"],
            normalized["severity"],
            normalized["category"],
            normalized["event_type"],
            normalized["title"],
            normalized["description"],
            normalized["event_time"],
            now,
            normalized["event_time"],
            normalized["source_ip"],
            normalized["destination_ip"],
            normalized["username"],
            normalized["hostname"],
            normalized["process_name"],
            normalized["parent_process"],
            normalized["file_hash"],
            normalized["http_status"],
            normalized["action"],
            normalized["outcome"],
            normalized["raw_data"],
            normalized["normalized_fields"],
            normalized["tags"],
            normalized["mitre_ids"],
            actor,
            normalized["parser_version"],
            normalized["raw_hash"],
            normalized["provenance"],
        ),
    )
    event_id = inserted_id(cursor)
    alerts = evaluate_rules(connection, event_id)
    insert_outbox(connection, workspace, "event.created", {"id": event_id, "event_id": event_public_id, "severity": normalized["severity"], "alert_ids": alerts})
    return event_id, alerts, False


def _event_view(row: sqlite3.Row, include_raw: bool = False) -> dict[str, Any]:
    item = dict(row)
    for field, fallback in (("normalized_fields", {}), ("tags", []), ("mitre_ids", []), ("provenance", {})):
        try:
            item[field] = json.loads(item.get(field) or json.dumps(fallback))
        except json.JSONDecodeError:
            item[field] = fallback
    if include_raw:
        item["raw_payload"] = _raw_object(item.pop("raw_data", None))
    else:
        item.pop("raw_data", None)
    return item


@events_api.get("/api/events")
@require_permission("events.read")
def list_events():
    try:
        page = max(int(request.args.get("page", 1)), 1)
        page_size = min(max(int(request.args.get("page_size", request.args.get("limit", 50))), 1), 100)
    except ValueError:
        return error_response("INVALID_PAGINATION", "قيم الترقيم غير صالحة", 400)
    clauses = ["workspace_id = ?"]
    parameters: list[object] = [workspace_id()]
    if request.args.get("include_derived") != "1":
        clauses.append("source != 'rules_engine'")
    scope, scope_parameters = training_scope_sql("training_run_id")
    if scope:
        clauses.append(scope.removeprefix(" AND "))
        parameters.extend(scope_parameters)
    filters = {"severity": "severity", "status": "status", "source": "source", "event_type": "event_type", "training_run_id": "training_run_id"}
    for query_name, column in filters.items():
        value = request.args.get(query_name)
        if value:
            clauses.append(f"{column} = ?")
            parameters.append(value)
    start = request.args.get("start")
    end = request.args.get("end")
    if start:
        try:
            start = iso_timestamp(start)
        except ValueError as exc:
            return error_response("INVALID_TIME_RANGE", str(exc), 422)
        clauses.append("event_time >= ?")
        parameters.append(start)
    if end:
        try:
            end = iso_timestamp(end)
        except ValueError as exc:
            return error_response("INVALID_TIME_RANGE", str(exc), 422)
        clauses.append("event_time <= ?")
        parameters.append(end)
    query_text = request.args.get("q", "").strip()
    if query_text:
        if len(query_text) > 200:
            return error_response("QUERY_TOO_LONG", "نص البحث يتجاوز الحد المسموح", 422)
        clauses.append("(title LIKE ? OR description LIKE ? OR source_ip LIKE ? OR username LIKE ? OR hostname LIKE ?)")
        escaped = "%" + query_text.replace("%", "\\%").replace("_", "\\_") + "%"
        parameters.extend([escaped] * 5)
    sort = request.args.get("sort", "event_time")
    direction = request.args.get("direction", "desc").lower()
    if sort not in SORT_FIELDS or direction not in {"asc", "desc"}:
        return error_response("INVALID_SORT", "حقل الفرز أو اتجاهه غير مسموح", 422)
    where = " AND ".join(clauses)
    total = int(get_db().execute(f"SELECT COUNT(*) FROM security_events WHERE {where}", parameters).fetchone()[0])
    rows = get_db().execute(
        f"SELECT * FROM security_events WHERE {where} ORDER BY {sort} {direction.upper()}, id DESC LIMIT ? OFFSET ?",
        (*parameters, page_size, (page - 1) * page_size),
    ).fetchall()
    return jsonify({"items": [_event_view(row) for row in rows], "total": total, "page": page, "page_size": page_size})


@events_api.post("/api/events")
@require_permission("events.create")
def create_event():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error_response("INVALID_JSON", "يلزم إرسال كائن JSON صالح", 400)
    header_key = request.headers.get("Idempotency-Key")
    if header_key:
        data["idempotency_key"] = header_key
    try:
        with transaction():
            training_run_id = data.get("training_run_id") if isinstance(data.get("training_run_id"), int) else None
            if not can_access_training_run(training_run_id):
                return error_response("TRAINING_RUN_NOT_FOUND", "جلسة التدريب غير موجودة", 404)
            event_id, alerts, duplicate = ingest_event(get_db(), data, actor_id(), workspace_id(), training_run_id)
            if not duplicate:
                record_audit(get_db(), "create", "event", event_id, details={"source": data.get("source"), "alerts": alerts})
    except ValueError as exc:
        return error_response("INVALID_EVENT", str(exc), 422)
    row = get_db().execute("SELECT event_id FROM security_events WHERE id = ?", (event_id,)).fetchone()
    status = 200 if duplicate else 201
    return jsonify({"id": event_id, "event_id": row["event_id"], "detections": alerts, "duplicate": duplicate}), status, {"Location": f"/api/events/{event_id}"}


@events_api.post("/api/lab/event")
@require_permission("training.run")
def create_lab_event():
    response = create_event()
    if isinstance(response, tuple) and len(response) == 3 and isinstance(response[1], int) and response[1] < 300:
        return response[0], 200, response[2]
    return response


@events_api.get("/api/events/<int:event_id>")
@require_permission("events.read")
def event_detail(event_id: int):
    row = get_db().execute("SELECT * FROM security_events WHERE id = ? AND workspace_id = ?", (event_id, workspace_id())).fetchone()
    if not row or not can_access_training_run(row["training_run_id"]):
        return error_response("EVENT_NOT_FOUND", "السجل غير موجود", 404)
    return jsonify(_event_view(row))


@events_api.get("/api/events/<int:event_id>/raw")
@require_permission("events.read")
def event_raw(event_id: int):
    row = get_db().execute("SELECT * FROM security_events WHERE id = ? AND workspace_id = ?", (event_id, workspace_id())).fetchone()
    if not row or not can_access_training_run(row["training_run_id"]):
        return error_response("EVENT_NOT_FOUND", "السجل غير موجود", 404)
    return jsonify(_event_view(row, include_raw=True))


@events_api.put("/api/events/<int:event_id>")
@require_permission("alerts.triage")
def update_event(event_id: int):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error_response("INVALID_JSON", "يلزم إرسال كائن JSON صالح", 400)
    row = get_db().execute("SELECT status, severity, assigned_to, training_run_id FROM security_events WHERE id = ? AND workspace_id = ?", (event_id, workspace_id())).fetchone()
    if not row or not can_access_training_run(row["training_run_id"]):
        return error_response("EVENT_NOT_FOUND", "السجل غير موجود", 404)
    updates: dict[str, Any] = {}
    if "status" in data:
        if data["status"] not in EVENT_STATUSES:
            return error_response("INVALID_EVENT_STATUS", "حالة السجل غير صالحة", 422)
        updates["status"] = data["status"]
    if "assigned_to" in data:
        assignee = data["assigned_to"]
        if assignee is not None and (not isinstance(assignee, int) or not get_db().execute("SELECT 1 FROM users WHERE id = ? AND workspace_id = ? AND is_active = 1", (assignee, workspace_id())).fetchone()):
            return error_response("INVALID_ASSIGNEE", "المحلل المحدد غير متاح", 422)
        updates["assigned_to"] = assignee
    if "severity" in data:
        if data["severity"] not in SEVERITIES:
            return error_response("INVALID_SEVERITY", "درجة الخطورة غير صالحة", 422)
        updates["severity"] = data["severity"]
    if not updates:
        return error_response("NO_CHANGES", "لم تُرسل حقول قابلة للتعديل", 422)
    assignments = ", ".join(f"{field} = ?" for field in updates)
    get_db().execute(f"UPDATE security_events SET {assignments} WHERE id = ?", (*updates.values(), event_id))
    record_audit(get_db(), "update", "event", event_id, details={"changed_fields": list(updates)})
    return jsonify({"id": event_id, **updates})


@events_api.delete("/api/events/<int:event_id>")
@require_permission("events.delete")
def delete_event(event_id: int):
    row = get_db().execute("SELECT id, training_run_id FROM security_events WHERE id = ? AND workspace_id = ?", (event_id, workspace_id())).fetchone()
    if not row or not can_access_training_run(row["training_run_id"]):
        return error_response("EVENT_NOT_FOUND", "السجل غير موجود", 404)
    record_audit(get_db(), "delete_denied", "event", event_id, "denied", {"reason": "immutable_evidence_policy"})
    return error_response("EVENT_IMMUTABLE", "السجلات أدلة غير قابلة للحذف؛ استخدم سياسة الاحتفاظ المعتمدة", 409)


def _csv_cell(value: object) -> str:
    text = "" if value is None else str(value)
    if text.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


@events_api.get("/api/events/export")
@require_permission("events.read")
def export_events():
    scope, parameters = training_scope_sql("training_run_id")
    rows = get_db().execute(
        f"""SELECT event_id, event_time, source, severity, event_type, title, source_ip, destination_ip, username, hostname, status
        FROM security_events WHERE workspace_id = ?{scope} ORDER BY event_time DESC LIMIT 10000""",
        (workspace_id(), *parameters),
    ).fetchall()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    fields = ["event_id", "event_time", "source", "severity", "event_type", "title", "source_ip", "destination_ip", "username", "hostname", "status"]
    writer.writerow(fields)
    for row in rows:
        writer.writerow([_csv_cell(row[field]) for field in fields])
    record_audit(get_db(), "export", "events", None, details={"count": len(rows)})
    return Response(buffer.getvalue(), mimetype="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=socify-events.csv", "X-Content-Type-Options": "nosniff"})
