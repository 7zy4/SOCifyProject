import csv
import io
import json
import re
from collections.abc import Iterator
from typing import Any

from flask import Blueprint, Response, current_app, jsonify, request, stream_with_context
from werkzeug.utils import secure_filename

from .autopsy_domain import custody, touch_case
from .autopsy_pipeline import activate_import, event_visible, job_visible, visibility_sql
from .cases import _attach_event, _case_row
from .chronology_time import sql_utc_key, utc_key
from .db import connect_readonly, get_db, transaction
from .events import _event_view
from .ingestion import _job_content, _job_view, cancel_import, create_import, preview_import, resume_import
from .security import actor_id, current_user, error_response, has_permission, require_permission
from .timeutils import iso_now

autopsy_ingestion_api = Blueprint("autopsy_ingestion", __name__)
SEARCH_COUNT_LIMIT = 10000
FTS_PREDICATE = "autopsy_log_search MATCH ?"


def import_view(row):
    item = _job_view(row)
    access = get_db().execute("SELECT restricted FROM autopsy_batch_access WHERE job_id = ?", (row["id"],)).fetchone()
    item["restricted"] = bool(access and access[0])
    if (current_user() or {}).get("role") in {"admin", "soc_manager"}:
        item["batch_members"] = [
            entry[0] for entry in get_db().execute("SELECT user_id FROM autopsy_batch_members WHERE job_id = ? ORDER BY user_id", (row["id"],))
        ]
    return item


def _job_for_case(case_id: int, job_id: int):
    if not _case_row(case_id):
        return None
    if not job_visible(job_id):
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
    return jsonify({"items": [import_view(row) for row in rows if job_visible(row["id"])]})


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
            **import_view(job),
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


@autopsy_ingestion_api.post("/api/cases/<int:case_id>/imports/<int:job_id>/activate")
@require_permission("cases.assign")
def case_import_activate(case_id: int, job_id: int):
    data = request.get_json(silent=True)
    if (
        not isinstance(data, dict)
        or set(data) != {"version", "reason"}
        or type(data.get("version")) is not int
        or not isinstance(data.get("reason"), str)
        or not 3 <= len(data["reason"].strip()) <= 1000
    ):
        return error_response("INVALID_ACTIVATION", "حدد إصدار القضية وسبب اختيار نسخة المعالجة", 422)
    with transaction():
        case = _case_row(case_id)
        job = _job_for_case(case_id, job_id)
        if not case or not job:
            return error_response("IMPORT_NOT_FOUND", "النسخة غير متاحة في القضية", 404)
        if case["status"] == "closed" or case["version"] != data["version"]:
            return error_response("CASE_VERSION_CONFLICT", "القضية مغلقة أو تغيرت؛ حدّث البيانات", 409)
        try:
            activate_import(job)
        except ValueError as exc:
            return error_response("IMPORT_NOT_ACTIVATABLE", str(exc), 409)
        custody(case_id, "derived_import_activation_reason", {"job_id": job_id, "reason": data["reason"].strip()})
    return jsonify({"id": job_id, "active_version": True, "detection_rescan_required": True})


@autopsy_ingestion_api.put("/api/cases/<int:case_id>/imports/<int:job_id>/access")
@require_permission("cases.assign")
def case_import_access(case_id: int, job_id: int):
    data = request.get_json(silent=True)
    if (
        not isinstance(data, dict)
        or set(data) != {"restricted", "members", "reason"}
        or type(data.get("restricted")) is not bool
        or not isinstance(data.get("members"), list)
        or len(data["members"]) > 100
        or any(type(value) is not int for value in data["members"])
        or not isinstance(data.get("reason"), str)
        or not 3 <= len(data["reason"].strip()) <= 1000
    ):
        return error_response("INVALID_BATCH_ACCESS", "حدد نطاق الدفعة وأعضاءها وسبب التغيير", 422)
    with transaction():
        case, job = _case_row(case_id), _job_for_case(case_id, job_id)
        if not case or not job:
            return error_response("IMPORT_NOT_FOUND", "الدفعة غير متاحة في القضية", 404)
        for user_id in set(data["members"]):
            if not get_db().execute("SELECT 1 FROM users WHERE id = ? AND workspace_id = ? AND is_active = 1", (user_id, case["workspace_id"])).fetchone():
                return error_response("MEMBER_NOT_FOUND", "أحد الأعضاء غير متاح في الفريق", 422)
        get_db().execute(
            "INSERT INTO autopsy_batch_access(job_id,restricted,changed_by,changed_at) VALUES (?,?,?,?) ON CONFLICT(job_id) DO UPDATE SET restricted = excluded.restricted, changed_by = excluded.changed_by, changed_at = excluded.changed_at",
            (job_id, int(data["restricted"]), actor_id(), iso_now()),
        )
        get_db().execute("DELETE FROM autopsy_batch_members WHERE job_id = ?", (job_id,))
        for user_id in set(data["members"]):
            get_db().execute("INSERT INTO autopsy_batch_members(job_id,user_id) VALUES (?,?)", (job_id, user_id))
            get_db().execute(
                "INSERT INTO autopsy_case_members(case_id,user_id,responsibility,assigned_by,assigned_at) VALUES (?,?,'investigator',?,?) ON CONFLICT(case_id,user_id) DO NOTHING",
                (case_id, user_id, actor_id(), iso_now()),
            )
        custody(
            case_id,
            "import_batch_access_changed",
            {"job_id": job_id, "restricted": data["restricted"], "members": sorted(set(data["members"])), "reason": data["reason"].strip()},
        )
        touch_case(case_id)
    return jsonify({"id": job_id, "restricted": data["restricted"], "members": sorted(set(data["members"]))})


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
    scope, parameters = visibility_sql("ce")
    clauses.append(scope)
    args.extend(parameters)
    selected_job = request.args.get("job_id")
    if selected_job:
        if not selected_job.isascii() or not selected_job.isdecimal() or not 1 <= int(selected_job) <= 2**63 - 1:
            raise ValueError("معرف نسخة الاستيراد غير صالح")
        if not _job_for_case(case_id, int(selected_job)):
            raise ValueError("نسخة الاستيراد غير متاحة في القضية")
        clauses.append("ce.import_job_id = ?")
        args.append(int(selected_job))
    else:
        clauses.append("ce.active_event = 1")
    query = request.args.get("q", "").strip()
    if len(query) > 200:
        raise ValueError("نص البحث يتجاوز الحد المسموح")
    if query:
        words = [word for word in re.findall(r"[\w.-]+", query) if any(char.isalnum() for char in word)][:20]
        if words:
            clauses.append(FTS_PREDICATE)
            args.append(" AND ".join('"' + word + '"' for word in words))
        else:
            clauses.append("0 = 1")
    ranges = {}
    for key, operator in (("start", ">="), ("end", "<=")):
        if request.args.get(key):
            ranges[key] = utc_key(request.args[key])
            clauses.append(f"{sql_utc_key('ce.event_time')} {operator} ?")
            args.append(ranges[key])
    if ranges:
        clauses.append("ce.time_known=1")
    if ranges.get("start") and ranges.get("end") and ranges["start"] > ranges["end"]:
        raise ValueError("بداية الفترة تتجاوز نهايتها")
    if request.args.get("severity"):
        severity = request.args["severity"]
        if severity not in {"critical", "high", "medium", "low"}:
            raise ValueError("الخطورة غير صالحة")
        clauses.append("ce.event_severity = ?")
        args.append(severity)
    return " AND ".join(clauses), args


def metadata_source(where):
    return "case_events ce JOIN autopsy_log_search ON autopsy_log_search.rowid=ce.event_id" if FTS_PREDICATE in where else "case_events ce"


def metadata_scope(where, args):
    source = metadata_source(where)
    if FTS_PREDICATE in where:
        count = get_db().execute(f"SELECT COUNT(*) FROM (SELECT 1 FROM {source} WHERE {where} LIMIT ?)", (*args, SEARCH_COUNT_LIMIT + 1)).fetchone()[0]
        if count > SEARCH_COUNT_LIMIT:
            predicate = "EXISTS (SELECT 1 FROM autopsy_log_search WHERE autopsy_log_search.rowid=ce.event_id AND autopsy_log_search MATCH ?)"
            return "case_events ce", where.replace(FTS_PREDICATE, predicate), SEARCH_COUNT_LIMIT, "gte"
        return source, where, count, "eq"
    return source, where, get_db().execute(f"SELECT COUNT(*) FROM {source} WHERE {where}", args).fetchone()[0], "eq"


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
    source, where, total, relation = metadata_scope(where, args)
    rows = (
        get_db()
        .execute(
            f"WITH page AS MATERIALIZED (SELECT ce.event_id,ce.event_time FROM {source} WHERE {where} ORDER BY ce.event_time,ce.event_id LIMIT ? OFFSET ?) SELECT e.* FROM page JOIN security_events e ON e.id=page.event_id ORDER BY page.event_time,page.event_id",
            (*args, limit + 1, (page - 1) * limit),
        )
        .fetchall()
    )
    return jsonify(
        {
            "items": [_event_view(row) for row in rows[:limit]],
            "total": total,
            "total_relation": relation,
            "has_next": len(rows) > limit,
            "page": page,
            "limit": limit,
        }
    )


@autopsy_ingestion_api.get("/api/cases/<int:case_id>/logs/<int:event_id>")
@require_permission("cases.read")
def case_log_detail(case_id: int, event_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    if not event_visible(case_id, event_id, active_only=False):
        return error_response("EVENT_NOT_FOUND", "السجل غير متاح في القضية", 404)
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
        if not event_visible(case_id, event_id):
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
        .execute(f"SELECT ce.event_id FROM {metadata_source(where)} WHERE {where} ORDER BY ce.event_time,ce.event_id LIMIT 100001", args)
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
