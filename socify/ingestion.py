import csv
import hashlib
import io
import json
import re
import sqlite3
import tempfile
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from defusedxml import ElementTree
from flask import Blueprint, current_app, jsonify, request
from werkzeug.utils import secure_filename

from .audit import record_audit
from .db import get_db, inserted_id, transaction
from .events import ingest_event
from .schema import public_id
from .security import actor_id, can_access_training_run, error_response, require_permission, training_scope_sql, workspace_id
from .timeutils import iso_now

ingestion_api = Blueprint("ingestion", __name__)

SYSLOG_5424 = re.compile(r"^<(?P<pri>\d{1,3})>1\s+(?P<timestamp>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<proc>\S+)\s+(?P<msgid>\S+)\s+(?:-|\[[^]]*\])\s*(?P<message>.*)$")
SYSLOG_3164 = re.compile(r"^<(?P<pri>\d{1,3})>(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<app>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$")
WEB_LOG = re.compile(r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?$')
AUTH_LOG = re.compile(r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<service>[\w-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$")


def _depth(value: object, level: int = 0) -> int:
    if level > 20:
        return level
    if isinstance(value, dict):
        return max([level] + [_depth(item, level + 1) for item in value.values()])
    if isinstance(value, list):
        return max([level] + [_depth(item, level + 1) for item in value])
    return level


def _detect_format(filename: str, content: bytes) -> str:
    suffix = Path(filename).suffix.lower()
    sample = content[:4096].lstrip()
    if suffix == ".evtx":
        return "evtx"
    if suffix in {".xml"} or sample.startswith(b"<"):
        return "sysmon_xml"
    if suffix == ".csv":
        return "csv"
    if suffix in {".jsonl", ".ndjson"}:
        return "jsonl"
    if suffix == ".json" or sample.startswith((b"[", b"{")):
        return "json"
    text = sample.decode("utf-8", errors="ignore")
    if WEB_LOG.match(text.splitlines()[0] if text.splitlines() else ""):
        return "web"
    if AUTH_LOG.match(text.splitlines()[0] if text.splitlines() else "") and "sshd" in text:
        return "linux_auth"
    return "syslog"


def _decode(content: bytes) -> str:
    if b"\x00" in content[:4096]:
        raise ValueError("binary content is not valid for the selected text format")
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("file must use UTF-8 encoding") from exc


def _record_from_mapping(record: dict[str, Any], row_number: int, source_name: str, content_hash: str) -> dict[str, Any]:
    if _depth(record) > 12:
        raise ValueError("JSON nesting exceeds 12 levels")
    event_time = record.get("event_time", record.get("timestamp", record.get("time", iso_now())))
    event_type = record.get("event_type", record.get("category", "imported_event"))
    title = record.get("title", str(event_type).replace("_", " ").title())
    raw = dict(record)
    return {
        **record,
        "source": str(record.get("source") or source_name),
        "source_type": str(record.get("source_type") or "import"),
        "severity": str(record.get("severity") or "medium").lower(),
        "category": str(record.get("category") or event_type),
        "event_type": str(event_type),
        "title": str(title),
        "description": str(record.get("description") or "Imported training log record"),
        "event_time": event_time,
        "raw_payload": raw,
        "external_id": str(record.get("external_id") or record.get("id") or f"row-{row_number}"),
        "idempotency_key": f"import:{content_hash}:{row_number}",
        "parser_version": "socify-import-2",
        "provenance": {"file_sha256": content_hash, "row": row_number, "format": "structured"},
    }


def _csv_records(text: str, source_name: str, content_hash: str) -> Iterator[dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or len(reader.fieldnames) > 200:
        raise ValueError("CSV requires a header with at most 200 columns")
    for row_number, record in enumerate(reader, 2):
        yield _record_from_mapping(dict(record), row_number, source_name, content_hash)


def _json_records(text: str, source_name: str, content_hash: str, json_lines: bool) -> Iterator[dict[str, Any]]:
    if json_lines:
        for row_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            if len(line.encode()) > 1048576:
                raise ValueError(f"line {row_number} exceeds 1 MiB")
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"line {row_number} must contain an object")
            yield _record_from_mapping(value, row_number, source_name, content_hash)
        return
    value = json.loads(text)
    records = value if isinstance(value, list) else [value]
    if not all(isinstance(item, dict) for item in records):
        raise ValueError("JSON must contain an object or an array of objects")
    for row_number, record in enumerate(records, 1):
        yield _record_from_mapping(record, row_number, source_name, content_hash)


def _priority_severity(priority: int) -> str:
    numeric = priority % 8
    if numeric <= 2:
        return "critical"
    if numeric == 3:
        return "high"
    if numeric == 4:
        return "medium"
    return "low"


def _syslog_records(text: str, source_name: str, content_hash: str) -> Iterator[dict[str, Any]]:
    for row_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        match = SYSLOG_5424.match(line)
        if match:
            values = match.groupdict()
            yield _record_from_mapping({"source": source_name, "source_type": "syslog", "event_time": values["timestamp"], "hostname": values["host"], "process_name": values["app"], "severity": _priority_severity(int(values["pri"])), "event_type": "syslog", "title": f"{values['app']} syslog event", "description": values["message"], "raw_message": line}, row_number, source_name, content_hash)
            continue
        legacy = SYSLOG_3164.match(line)
        if not legacy:
            raise ValueError(f"row {row_number} is not RFC 3164 or RFC 5424 syslog")
        values = legacy.groupdict()
        assumed = datetime.strptime(f"{utc_now_year()} {values['month']} {values['day']} {values['time']}", "%Y %b %d %H:%M:%S").replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")
        yield _record_from_mapping({"source": source_name, "source_type": "syslog", "event_time": assumed, "hostname": values["host"], "process_name": values["app"], "severity": _priority_severity(int(values["pri"])), "event_type": "syslog", "title": f"{values['app']} syslog event", "description": values["message"], "raw_message": line, "timestamp_assumption": "current_year_utc"}, row_number, source_name, content_hash)


def utc_now_year() -> int:
    return datetime.now(UTC).year


def _web_records(text: str, source_name: str, content_hash: str) -> Iterator[dict[str, Any]]:
    for row_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        match = WEB_LOG.match(line)
        if not match:
            raise ValueError(f"row {row_number} is not a supported Apache/Nginx combined log")
        values = match.groupdict()
        event_time = datetime.strptime(values["time"], "%d/%b/%Y:%H:%M:%S %z").isoformat()
        status = int(values["status"])
        severity = "high" if status >= 500 else "medium" if status >= 400 else "low"
        yield _record_from_mapping({"source": source_name, "source_type": "web", "event_time": event_time, "source_ip": values["ip"], "username": None if values["user"] == "-" else values["user"], "http_status": status, "action": values["method"], "event_type": "web_request", "category": "web", "severity": severity, "title": f"{values['method']} {values['path']}", "description": line, "path": values["path"], "user_agent": values.get("agent")}, row_number, source_name, content_hash)


def _auth_records(text: str, source_name: str, content_hash: str) -> Iterator[dict[str, Any]]:
    for row_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        match = AUTH_LOG.match(line)
        if not match:
            raise ValueError(f"row {row_number} is not a supported Linux auth log")
        values = match.groupdict()
        assumed = datetime.strptime(f"{utc_now_year()} {values['month']} {values['day']} {values['time']}", "%Y %b %d %H:%M:%S").replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")
        message = values["message"]
        failed = "failed password" in message.casefold() or "authentication failure" in message.casefold()
        ip_match = re.search(r"\b(?:from|rhost=)([0-9a-fA-F:.]+)", message)
        user_match = re.search(r"(?:for invalid user|for|user=)(?:\s*)?([\w.@-]+)", message)
        yield _record_from_mapping({"source": source_name, "source_type": "linux_auth", "event_time": assumed, "hostname": values["host"], "process_name": values["service"], "source_ip": ip_match.group(1) if ip_match else None, "username": user_match.group(1) if user_match else None, "action": "login", "outcome": "failed" if failed else "success", "event_type": "failed_login" if failed else "authentication", "category": "authentication", "severity": "medium" if failed else "low", "title": "Failed Linux login" if failed else "Linux authentication", "description": message, "timestamp_assumption": "current_year_utc"}, row_number, source_name, content_hash)


def _sysmon_xml_records(content: bytes, source_name: str, content_hash: str) -> Iterator[dict[str, Any]]:
    upper = content[:8192].upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ValueError("XML document types and entities are not allowed")
    root = ElementTree.fromstring(content)
    events = [root] if root.tag.endswith("Event") else [item for item in root.iter() if item.tag.endswith("Event")]
    for row_number, event in enumerate(events, 1):
        system: dict[str, str] = {}
        event_data: dict[str, str] = {}
        for item in event.iter():
            local = item.tag.rsplit("}", 1)[-1]
            if local in {"EventID", "Computer", "TimeCreated"}:
                system[local] = item.attrib.get("SystemTime", item.text or "")
            if local == "Data":
                event_data[item.attrib.get("Name", f"field_{len(event_data)}")] = item.text or ""
        event_id = system.get("EventID", "unknown")
        record = {"source": source_name, "source_type": "sysmon", "event_time": system.get("TimeCreated", iso_now()), "hostname": system.get("Computer"), "event_type": f"sysmon_{event_id}", "category": "windows", "severity": "medium", "title": f"Sysmon Event {event_id}", "description": event_data.get("RuleName", "Imported Sysmon event"), "process_name": event_data.get("Image"), "parent_process": event_data.get("ParentImage"), "source_ip": event_data.get("SourceIp"), "destination_ip": event_data.get("DestinationIp"), "username": event_data.get("User"), "file_hash": event_data.get("Hashes"), "raw_payload": event_data}
        yield _record_from_mapping(record, row_number, source_name, content_hash)


def _evtx_records(content: bytes, source_name: str, content_hash: str) -> Iterator[dict[str, Any]]:
    try:
        from Evtx.Evtx import Evtx
    except ImportError as exc:
        raise ValueError("EVTX parser is not installed") from exc
    with tempfile.NamedTemporaryFile(suffix=".evtx") as temporary:
        temporary.write(content)
        temporary.flush()
        with Evtx(temporary.name) as log:
            for row_number, record in enumerate(log.records(), 1):
                xml = record.xml().encode()
                parsed = list(_sysmon_xml_records(xml, source_name, content_hash))
                for item in parsed:
                    item["idempotency_key"] = f"import:{content_hash}:{row_number}"
                    yield item


def parse_records(filename: str, content: bytes, selected_format: str | None, source_name: str) -> tuple[str, Iterable[dict[str, Any]]]:
    if len(content) > int(current_app.config["MAX_CONTENT_LENGTH"]):
        raise ValueError("file exceeds the configured upload limit")
    content_hash = hashlib.sha256(content).hexdigest()
    format_name = selected_format or "auto"
    if format_name == "auto":
        format_name = _detect_format(filename, content)
    if format_name == "csv":
        return format_name, _csv_records(_decode(content), source_name, content_hash)
    if format_name in {"jsonl", "ndjson"}:
        return "jsonl", _json_records(_decode(content), source_name, content_hash, True)
    if format_name == "json":
        return format_name, _json_records(_decode(content), source_name, content_hash, False)
    if format_name == "syslog":
        return format_name, _syslog_records(_decode(content), source_name, content_hash)
    if format_name == "web":
        return format_name, _web_records(_decode(content), source_name, content_hash)
    if format_name == "linux_auth":
        return format_name, _auth_records(_decode(content), source_name, content_hash)
    if format_name in {"sysmon_xml", "xml"}:
        return "sysmon_xml", _sysmon_xml_records(content, source_name, content_hash)
    if format_name == "evtx":
        return format_name, _evtx_records(content, source_name, content_hash)
    raise ValueError("selected format is not supported")


def _upload_payload() -> tuple[str, bytes, str | None, int | None, int | None]:
    if request.files:
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            raise ValueError("file is required")
        filename = secure_filename(uploaded.filename) or "import.log"
        content = uploaded.stream.read(int(current_app.config["MAX_CONTENT_LENGTH"]) + 1)
        selected_format = request.form.get("format", "auto")
        source_id = int(request.form["source_id"]) if request.form.get("source_id") else None
        training_run_id = int(request.form["training_run_id"]) if request.form.get("training_run_id") else None
        return filename, content, selected_format, source_id, training_run_id
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("content"), str):
        raise ValueError("multipart file or textual content is required")
    filename = secure_filename(str(data.get("filename") or "import.log")) or "import.log"
    return filename, data["content"].encode(), str(data.get("format") or "auto"), data.get("source_id") if isinstance(data.get("source_id"), int) else None, data.get("training_run_id") if isinstance(data.get("training_run_id"), int) else None


@ingestion_api.post("/api/imports/preview")
@require_permission("events.create")
def preview_import():
    try:
        filename, content, selected_format, source_id, training_run_id = _upload_payload()
        if not can_access_training_run(training_run_id):
            return error_response("TRAINING_RUN_NOT_FOUND", "جلسة التدريب غير موجودة", 404)
        source = get_db().execute("SELECT name FROM event_sources WHERE id = ? AND workspace_id = ?", (source_id, workspace_id())).fetchone() if source_id else None
        format_name, records = parse_records(filename, content, selected_format, source["name"] if source else "file-import")
        preview = []
        for index, record in enumerate(records):
            if index >= 20:
                break
            preview.append(record)
        return jsonify({"filename": filename, "format": format_name, "content_hash": hashlib.sha256(content).hexdigest(), "preview": preview, "commit_required": True})
    except (ValueError, json.JSONDecodeError, csv.Error, ElementTree.ParseError) as exc:
        return error_response("IMPORT_PREVIEW_FAILED", str(exc), 422)


@ingestion_api.post("/api/imports")
@require_permission("events.create")
def create_import():
    try:
        filename, content, selected_format, source_id, training_run_id = _upload_payload()
    except (ValueError, OverflowError) as exc:
        return error_response("INVALID_IMPORT", str(exc), 422)
    if len(content) > int(current_app.config["MAX_CONTENT_LENGTH"]):
        return error_response("UPLOAD_TOO_LARGE", "الملف يتجاوز الحجم المسموح", 413)
    if not can_access_training_run(training_run_id):
        return error_response("TRAINING_RUN_NOT_FOUND", "جلسة التدريب غير موجودة", 404)
    source = get_db().execute("SELECT id, name FROM event_sources WHERE id = ? AND workspace_id = ? AND is_active = 1", (source_id, workspace_id())).fetchone() if source_id else None
    if source_id and not source:
        return error_response("SOURCE_NOT_FOUND", "المصدر غير موجود أو معطل", 404)
    source_name = source["name"] if source else "file-import"
    content_hash = hashlib.sha256(content).hexdigest()
    duplicate = get_db().execute("SELECT * FROM ingestion_jobs WHERE workspace_id = ? AND content_hash = ? AND training_run_id IS ?", (workspace_id(), content_hash, training_run_id)).fetchone()
    if duplicate:
        return jsonify({**dict(duplicate), "duplicate": True})
    try:
        format_name, records = parse_records(filename, content, selected_format, source_name)
    except (ValueError, json.JSONDecodeError, csv.Error, ElementTree.ParseError) as exc:
        return error_response("IMPORT_FORMAT_ERROR", str(exc), 422)
    now = iso_now()
    with transaction():
        cursor = get_db().execute(
            """INSERT INTO ingestion_jobs
            (job_id, workspace_id, source_id, training_run_id, filename, format, content_hash, status, parser_version,
            created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'processing', 'socify-import-2', ?, ?)""",
            (public_id("IMP"), workspace_id(), source_id, training_run_id, filename, format_name, content_hash, actor_id(), now),
        )
        job_database_id = inserted_id(cursor)
    accepted = 0
    rejected = 0
    skipped = 0
    total = 0
    maximum_rows = int(current_app.config["MAX_IMPORT_ROWS"])
    iterator = iter(records)
    while total < maximum_rows:
        try:
            record = next(iterator)
        except StopIteration:
            break
        except (ValueError, json.JSONDecodeError, csv.Error, ElementTree.ParseError) as exc:
            total += 1
            rejected += 1
            get_db().execute("INSERT INTO ingestion_errors (job_id, row_number, error_code, message, sample, created_at) VALUES (?, ?, 'PARSE_ERROR', ?, NULL, ?)", (job_database_id, total, str(exc)[:500], iso_now()))
            continue
        total += 1
        try:
            with transaction():
                _, _, was_duplicate = ingest_event(get_db(), record, actor_id(), workspace_id(), training_run_id)
            if was_duplicate:
                skipped += 1
            else:
                accepted += 1
        except (ValueError, sqlite3.Error) as exc:
            rejected += 1
            get_db().execute("INSERT INTO ingestion_errors (job_id, row_number, error_code, message, sample, created_at) VALUES (?, ?, 'VALIDATION_ERROR', ?, ?, ?)", (job_database_id, total, str(exc)[:500], json.dumps(record, ensure_ascii=False)[:1000], iso_now()))
    sentinel = object()
    overflow = next(iterator, sentinel)
    if overflow is not sentinel:
        rejected += 1
        get_db().execute("INSERT INTO ingestion_errors (job_id, row_number, error_code, message, sample, created_at) VALUES (?, ?, 'ROW_LIMIT', ?, NULL, ?)", (job_database_id, total + 1, f"row limit {maximum_rows} exceeded", iso_now()))
    completed = iso_now()
    status = "completed" if rejected == 0 else "completed_with_errors"
    get_db().execute("UPDATE ingestion_jobs SET status = ?, accepted = ?, rejected = ?, skipped = ?, total = ?, progress = 1, completed_at = ? WHERE id = ?", (status, accepted, rejected, skipped, total, completed, job_database_id))
    if source_id:
        error_rate = rejected / total if total else 0
        get_db().execute("UPDATE event_sources SET rows_ingested = rows_ingested + ?, error_rate = ?, last_sync = ?, status = ?, updated_at = ? WHERE id = ?", (accepted, error_rate, completed, "connected" if accepted else "failed", completed, source_id))
    record_audit(get_db(), "complete", "import", job_database_id, details={"accepted": accepted, "rejected": rejected, "skipped": skipped, "format": format_name})
    job = get_db().execute("SELECT * FROM ingestion_jobs WHERE id = ?", (job_database_id,)).fetchone()
    return jsonify(dict(job)), 201, {"Location": f"/api/imports/{job_database_id}"}


@ingestion_api.get("/api/imports")
@require_permission("events.read")
def list_imports():
    scope, parameters = training_scope_sql("training_run_id")
    rows = get_db().execute(f"SELECT * FROM ingestion_jobs WHERE workspace_id = ?{scope} ORDER BY created_at DESC LIMIT 100", (workspace_id(), *parameters)).fetchall()
    return jsonify({"items": [dict(row) for row in rows]})


@ingestion_api.get("/api/imports/<int:job_id>")
@require_permission("events.read")
def import_detail(job_id: int):
    row = get_db().execute("SELECT * FROM ingestion_jobs WHERE id = ? AND workspace_id = ?", (job_id, workspace_id())).fetchone()
    if not row or not can_access_training_run(row["training_run_id"]):
        return error_response("IMPORT_NOT_FOUND", "مهمة الاستيراد غير موجودة", 404)
    item = dict(row)
    item["errors"] = [dict(error) for error in get_db().execute("SELECT row_number, error_code, message, sample, created_at FROM ingestion_errors WHERE job_id = ? ORDER BY id LIMIT 1000", (job_id,)).fetchall()]
    return jsonify(item)
