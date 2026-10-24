import csv
import io
import json
import re
from collections.abc import Iterator
from typing import Any

from flask import Blueprint, Response, current_app, jsonify, request, stream_with_context
from werkzeug.utils import secure_filename

from .autopsy_domain import custody, touch_case
from .cases import _attach_event, _case_row
from .db import connect_readonly, get_db, transaction
from .events import _event_view
from .ingestion import _job_content, _job_view, cancel_import, create_import, preview_import, resume_import
from .security import actor_id, current_user, error_response, has_permission, require_permission
from .timeutils import iso_timestamp

autopsy_ingestion_api = Blueprint("autopsy_ingestion", __name__)


def _job_for_case(case_id: int, job_id: int):
    if not _case_row(case_id):
        return None
    return get_db().execute("SELECT * FROM ingestion_jobs WHERE case_id = ? AND id = ?", (case_id, job_id)).fetchone()


@autopsy_ingestion_api.post("/api/cases/<int:case_id>/imports/preview")
@require_permission("evidence.add")
def case_import_preview(case_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    return preview_import()


@autopsy_ingestion_api.post("/api/cases/<int:case_id>/imports")
@require_permission("evidence.add")
def case_import_create(case_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    return create_import()


@autopsy_ingestion_api.get("/api/cases/<int:case_id>/imports")
@require_permission("cases.read")
def case_import_list(case_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    rows = get_db().execute("SELECT * FROM ingestion_jobs WHERE case_id = ? ORDER BY id DESC LIMIT 100", (case_id,)).fetchall()
    return jsonify({"items": [_job_view(row) for row in rows]})


@autopsy_ingestion_api.get("/api/cases/<int:case_id>/imports/<int:job_id>")
@require_permission("cases.read")
def case_import_detail(case_id: int, job_id: int):
    job = _job_for_case(case_id, job_id)
    if not job:
        return error_response("IMPORT_NOT_FOUND", "الاستيراد غير متاح في القضية", 404)
    errors = [
        dict(row)
        for row in get_db().execute("SELECT row_number, error_code, message FROM ingestion_errors WHERE job_id = ? ORDER BY id LIMIT 100", (job_id,)).fetchall()
    ]
    return jsonify(
        {
            **_job_view(job),
            "errors": errors,
            "errors_total": get_db().execute("SELECT COUNT(*) FROM ingestion_errors WHERE job_id = ?", (job_id,)).fetchone()[0],
        }
    )


@autopsy_ingestion_api.post("/api/cases/<int:case_id>/imports/<int:job_id>/resume")
@require_permission("evidence.add")
def case_import_resume(case_id: int, job_id: int):
    if not _job_for_case(case_id, job_id):
        return error_response("IMPORT_NOT_FOUND", "الاستيراد غير متاح في القضية", 404)
    return resume_import(job_id)


@autopsy_ingestion_api.post("/api/cases/<int:case_id>/imports/<int:job_id>/cancel")
@require_permission("evidence.add")
def case_import_cancel(case_id: int, job_id: int):
    if not _job_for_case(case_id, job_id):
        return error_response("IMPORT_NOT_FOUND", "الاستيراد غير متاح في القضية", 404)
    return cancel_import(job_id)


@autopsy_ingestion_api.get("/api/cases/<int:case_id>/imports/<int:job_id>/original")
@require_permission("evidence.download")
def original_import(case_id: int, job_id: int):
    job = _job_for_case(case_id, job_id)
    if not job:
        return error_response("IMPORT_NOT_FOUND", "الدليل غير متاح في القضية", 404)
    try:
        content = _job_content(job)
    except ValueError:
        return error_response("EVIDENCE_INTEGRITY_FAILURE", "تعذر التحقق من سلامة الأصل", 409)
    with transaction():
        custody(case_id, "original_downloaded", {"job_id": job_id, "sha256": job["content_hash"]})
    return Response(
        content,
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={secure_filename(job['filename']) or 'evidence.bin'}", "X-Evidence-SHA256": job["content_hash"]},
    )


def log_query(case_id: int) -> tuple[str, list[Any]]:
    clauses = ["ce.case_id = ?"]
    args: list[Any] = [case_id]
    query = request.args.get("q", "").strip()
    if len(query) > 200:
        raise ValueError("نص البحث يتجاوز الحد المسموح")
    if query:
        words = [word for word in re.findall(r"[\w.-]+", query) if any(char.isalnum() for char in word)][:20]
        if words:
            clauses.append("e.id IN (SELECT rowid FROM autopsy_log_search WHERE autopsy_log_search MATCH ?)")
            args.append(" AND ".join('"' + word + '"' for word in words))
        else:
            clauses.append("0 = 1")
    for key, operator in (("start", ">="), ("end", "<=")):
        if request.args.get(key):
            clauses.append(f"e.event_time {operator} ?")
            args.append(iso_timestamp(request.args[key]))
    if request.args.get("severity"):
        severity = request.args["severity"]
        if severity not in {"critical", "high", "medium", "low"}:
            raise ValueError("الخطورة غير صالحة")
        clauses.append("e.severity = ?")
        args.append(severity)
    return " AND ".join(clauses), args


@autopsy_ingestion_api.get("/api/cases/<int:case_id>/logs")
@require_permission("cases.read")
def case_logs(case_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    try:
        page, limit = int(request.args.get("page", 1)), int(request.args.get("limit", 50))
        if not 1 <= page <= 1000000 or not 1 <= limit <= 100:
            raise ValueError("قيم الترقيم غير صالحة")
        where, args = log_query(case_id)
    except ValueError as exc:
        return error_response("INVALID_LOG_FILTER", str(exc), 422)
    total = get_db().execute(f"SELECT COUNT(*) FROM case_events ce JOIN security_events e ON e.id = ce.event_id WHERE {where}", args).fetchone()[0]
    rows = (
        get_db()
        .execute(
            f"SELECT e.* FROM case_events ce JOIN security_events e ON e.id = ce.event_id WHERE {where} ORDER BY e.event_time, e.id LIMIT ? OFFSET ?",
            (*args, limit, (page - 1) * limit),
        )
        .fetchall()
    )
    return jsonify({"items": [_event_view(row) for row in rows], "total": total, "page": page, "limit": limit})


@autopsy_ingestion_api.get("/api/cases/<int:case_id>/logs/<int:event_id>")
@require_permission("cases.read")
def case_log_detail(case_id: int, event_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    row = (
        get_db()
        .execute("SELECT e.* FROM case_events ce JOIN security_events e ON e.id = ce.event_id WHERE ce.case_id = ? AND ce.event_id = ?", (case_id, event_id))
        .fetchone()
    )
    return jsonify(_event_view(row, include_raw=True)) if row else error_response("EVENT_NOT_FOUND", "السجل غير متاح في القضية", 404)


@autopsy_ingestion_api.post("/api/cases/<int:case_id>/logs/<int:event_id>/exhibit")
@require_permission("evidence.add")
def select_log_exhibit(case_id: int, event_id: int):
    with transaction():
        case = _case_row(case_id)
        if not case:
            return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
        if case["status"] == "closed":
            return error_response("CASE_CLOSED", "أعد فتح القضية قبل تغيير أدلتها", 409)
        if not get_db().execute("SELECT 1 FROM case_events WHERE case_id = ? AND event_id = ?", (case_id, event_id)).fetchone():
            return error_response("EVENT_NOT_FOUND", "السجل غير متاح في القضية", 404)
        prior = (
            get_db()
            .execute("SELECT id FROM case_evidence WHERE case_id = ? AND evidence_type = 'event' AND reference_id = ?", (case_id, str(event_id)))
            .fetchone()
        )
        if not _attach_event(get_db(), case_id, event_id):
            return error_response("EVENT_NOT_FOUND", "السجل غير متاح", 404)
        evidence = (
            get_db()
            .execute("SELECT id, sha256 FROM case_evidence WHERE case_id = ? AND evidence_type = 'event' AND reference_id = ?", (case_id, str(event_id)))
            .fetchone()
        )
        if not prior:
            custody(
                case_id,
                "log_selected_as_exhibit",
                {"event_id": event_id, "evidence_id": evidence["id"], "sha256": evidence["sha256"], "selected_by": actor_id()},
            )
            touch_case(case_id)
    return jsonify({"id": evidence["id"], "sha256": evidence["sha256"], "duplicate": bool(prior)}), 200 if prior else 201


def _redacted_event(row) -> dict[str, Any]:
    item = _event_view(row)
    return {
        "event_id": item["event_id"],
        "event_time": item["event_time"],
        "severity": item["severity"],
        "redaction_policy": "metadata_only_v1",
        "title": "[REDACTED]",
        "source": "[REDACTED]",
        "event_time_known": item["normalized_fields"].get("event_time_known", None),
    }


def _csv_cell(value: object) -> str:
    serialized = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value) if value is not None else ""
    return "'" + serialized if serialized.lstrip(" \t\r\n\v\f\ufeff\u200b").startswith(("=", "+", "-", "@")) else serialized


@autopsy_ingestion_api.get("/api/cases/<int:case_id>/logs/export")
@require_permission("cases.export")
def export_case_logs(case_id: int):
    case = _case_row(case_id)
    if not case:
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    format_name, redaction = request.args.get("format", "jsonl"), request.args.get("redacted", "1")
    if format_name not in {"json", "jsonl", "csv"} or redaction not in {"0", "1"}:
        return error_response("INVALID_EXPORT", "حدد JSON أو JSONL أو CSV وسياسة الحجب", 422)
    if redaction == "0" and not has_permission(current_user(), "evidence.download"):
        return error_response("PERMISSION_DENIED", "تصدير القيم الأصلية يتطلب صلاحية مستقلة", 403)
    try:
        where, args = log_query(case_id)
    except ValueError as exc:
        return error_response("INVALID_LOG_FILTER", str(exc), 422)
    identifiers = [
        row[0]
        for row in get_db()
        .execute(f"SELECT e.id FROM case_events ce JOIN security_events e ON e.id = ce.event_id WHERE {where} ORDER BY e.event_time, e.id LIMIT 100001", args)
        .fetchall()
    ]
    count = len(identifiers)
    if count > 100000:
        return error_response("EXPORT_LIMIT_EXCEEDED", "حدّد نطاقًا أو فترة أصغر؛ الحد الحالي 100000 سجل لكل تصدير", 413)
    with transaction():
        custody(case_id, "logs_exported", {"format": format_name, "redacted": redaction == "1", "rows": count})
    database = str(current_app.config["DATABASE"])

    def snapshot_rows():
        connection = connect_readonly(database)
        try:
            for start in range(0, len(identifiers), 500):
                batch = identifiers[start : start + 500]
                placeholders = ",".join("?" for _ in batch)
                yield from connection.execute(
                    f"SELECT e.* FROM case_events ce JOIN security_events e ON e.id = ce.event_id WHERE ce.case_id = ? AND e.id IN ({placeholders}) ORDER BY e.event_time, e.id",
                    (case_id, *batch),
                )
        finally:
            connection.close()

    def generate() -> Iterator[str]:
        if format_name == "json":
            yield "["
        columns = ["event_id", "event_time", "severity", "title", "source", "source_ip", "destination_ip", "username", "hostname", "raw_payload"]
        if format_name == "csv":
            buffer = io.StringIO()
            writer = csv.writer(buffer, lineterminator="\r\n")
            writer.writerow(columns)
            yield "\ufeff" + buffer.getvalue()
        first = True
        for row in snapshot_rows():
            item = _redacted_event(row) if redaction == "1" else _event_view(row, include_raw=True)
            if format_name == "csv":
                buffer = io.StringIO()
                csv.writer(buffer, lineterminator="\r\n").writerow([_csv_cell(item.get(column)) for column in columns])
                yield buffer.getvalue()
            elif format_name == "json":
                yield ("" if first else ",") + json.dumps(item, ensure_ascii=False)
            else:
                yield json.dumps(item, ensure_ascii=False) + "\n"
            first = False
        if format_name == "json":
            yield "]"

    media = {"csv": "text/csv", "json": "application/json", "jsonl": "application/x-ndjson"}[format_name]
    return Response(
        stream_with_context(generate()),
        mimetype=media,
        headers={
            "Content-Disposition": f"attachment; filename={secure_filename(case['reference'])}-logs.{format_name}",
            "X-Redaction-Policy": "metadata_only_v1" if redaction == "1" else "unredacted",
        },
    )
