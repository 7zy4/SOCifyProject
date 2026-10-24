import base64
import binascii
import csv
import hashlib
import io
import json
import re
import sqlite3
import tempfile
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from defusedxml import ElementTree
from flask import Blueprint, Response, current_app, jsonify, request
from werkzeug.utils import secure_filename

from .audit import record_audit
from .db import get_db, inserted_id, transaction
from .events import ingest_event
from .operational import case_visible, operational_mode
from .schema import public_id
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

ingestion_api = Blueprint("ingestion", __name__)
IMPORT_CHUNK_SIZE = 100

SYSLOG_5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>1\s+(?P<timestamp>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<proc>\S+)\s+(?P<msgid>\S+)\s+(?:-|\[[^]]*\])\s*(?P<message>.*)$"
)
SYSLOG_3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<app>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)
WEB_LOG = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?$'
)
AUTH_LOG = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<service>[\w-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)


def _depth(value: object, level: int = 0) -> int:
    if level > 20:
        return level
    if isinstance(value, dict):
        return max([level] + [_depth(item, level + 1) for item in value.values()])
    if isinstance(value, list):
        return max([level] + [_depth(item, level + 1) for item in value])
    return level


def _detect_format(filename: str, content: bytes) -> str:
    if content[:4] in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}:
        return "pcapng" if content[:4] == b"\x0a\x0d\x0d\x0a" else "pcap"
    suffix = Path(filename).suffix.lower()
    sample = content[:4096].lstrip()
    if sample.startswith(b"ElfFile\x00"):
        return "evtx"
    if sample.startswith(b"<"):
        return "sysmon_xml"
    if suffix in {".jsonl", ".ndjson"} and sample.startswith(b"{"):
        return "jsonl"
    if suffix == ".json" or sample.startswith((b"[", b"{")):
        return "json"
    text = sample.decode("utf-8", errors="ignore")
    if WEB_LOG.match(text.splitlines()[0] if text.splitlines() else ""):
        return "web"
    if AUTH_LOG.match(text.splitlines()[0] if text.splitlines() else "") and "sshd" in text:
        return "linux_auth"
    if suffix == ".csv" and any(value in (text.splitlines()[0] if text.splitlines() else "") for value in (",", ";", "\t", "|")):
        return "csv"
    return "syslog"


def _decode(content: bytes) -> str:
    if b"\x00" in content[:4096]:
        raise ValueError("binary content is not valid for the selected text format")
    if any(len(line) > 1048576 for line in content.splitlines()):
        raise ValueError("text line exceeds 1 MiB")
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


def _csv_records(text: str, source_name: str, content_hash: str, delimiter: str = ",") -> Iterator[dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    if (
        not reader.fieldnames
        or len(reader.fieldnames) > 200
        or len(set(reader.fieldnames)) != len(reader.fieldnames)
        or any(not field.strip() for field in reader.fieldnames)
    ):
        raise ValueError("CSV requires a header with at most 200 columns")
    for row_number, record in enumerate(reader, 2):
        yield _record_from_mapping(dict(record), row_number, source_name, content_hash)


def _json_records(text: str, source_name: str, content_hash: str, json_lines: bool, tolerant: bool = False) -> Iterator[dict[str, Any]]:
    if json_lines:
        for row_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            if len(line.encode()) > 1048576:
                raise ValueError(f"line {row_number} exceeds 1 MiB")
            try:
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"line {row_number} must contain an object")
                yield _record_from_mapping(value, row_number, source_name, content_hash)
            except (ValueError, RecursionError) as exc:
                if not tolerant:
                    raise ValueError(f"invalid JSON record at line {row_number}") from exc
                yield {"__parse_error": f"invalid JSON record at line {row_number}", "provenance": {"file_sha256": content_hash, "row": row_number}}
        return
    try:
        value = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise ValueError("invalid JSON document") from exc
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
            yield _record_from_mapping(
                {
                    "source": source_name,
                    "source_type": "syslog",
                    "event_time": values["timestamp"],
                    "hostname": values["host"],
                    "process_name": values["app"],
                    "severity": _priority_severity(int(values["pri"])),
                    "event_type": "syslog",
                    "title": f"{values['app']} syslog event",
                    "description": values["message"],
                    "raw_message": line,
                },
                row_number,
                source_name,
                content_hash,
            )
            continue
        legacy = SYSLOG_3164.match(line)
        if not legacy:
            raise ValueError(f"row {row_number} is not RFC 3164 or RFC 5424 syslog")
        values = legacy.groupdict()
        assumed = (
            datetime.strptime(f"{utc_now_year()} {values['month']} {values['day']} {values['time']}", "%Y %b %d %H:%M:%S")
            .replace(tzinfo=UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )
        yield _record_from_mapping(
            {
                "source": source_name,
                "source_type": "syslog",
                "event_time": assumed,
                "hostname": values["host"],
                "process_name": values["app"],
                "severity": _priority_severity(int(values["pri"])),
                "event_type": "syslog",
                "title": f"{values['app']} syslog event",
                "description": values["message"],
                "raw_message": line,
                "timestamp_assumption": "current_year_utc",
            },
            row_number,
            source_name,
            content_hash,
        )


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
        yield _record_from_mapping(
            {
                "source": source_name,
                "source_type": "web",
                "event_time": event_time,
                "source_ip": values["ip"],
                "username": None if values["user"] == "-" else values["user"],
                "http_status": status,
                "action": values["method"],
                "event_type": "web_request",
                "category": "web",
                "severity": severity,
                "title": f"{values['method']} {values['path']}",
                "description": line,
                "path": values["path"],
                "user_agent": values.get("agent"),
            },
            row_number,
            source_name,
            content_hash,
        )


def _auth_records(text: str, source_name: str, content_hash: str) -> Iterator[dict[str, Any]]:
    for row_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        match = AUTH_LOG.match(line)
        if not match:
            raise ValueError(f"row {row_number} is not a supported Linux auth log")
        values = match.groupdict()
        assumed = (
            datetime.strptime(f"{utc_now_year()} {values['month']} {values['day']} {values['time']}", "%Y %b %d %H:%M:%S")
            .replace(tzinfo=UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )
        message = values["message"]
        failed = "failed password" in message.casefold() or "authentication failure" in message.casefold()
        ip_match = re.search(r"\b(?:from|rhost=)([0-9a-fA-F:.]+)", message)
        user_match = re.search(r"(?:for invalid user|for|user=)(?:\s*)?([\w.@-]+)", message)
        yield _record_from_mapping(
            {
                "source": source_name,
                "source_type": "linux_auth",
                "event_time": assumed,
                "hostname": values["host"],
                "process_name": values["service"],
                "source_ip": ip_match.group(1) if ip_match else None,
                "username": user_match.group(1) if user_match else None,
                "action": "login",
                "outcome": "failed" if failed else "success",
                "event_type": "failed_login" if failed else "authentication",
                "category": "authentication",
                "severity": "medium" if failed else "low",
                "title": "Failed Linux login" if failed else "Linux authentication",
                "description": message,
                "timestamp_assumption": "current_year_utc",
            },
            row_number,
            source_name,
            content_hash,
        )


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
        record = {
            "source": source_name,
            "source_type": "sysmon",
            "event_time": system.get("TimeCreated", iso_now()),
            "hostname": system.get("Computer"),
            "event_type": f"sysmon_{event_id}",
            "category": "windows",
            "severity": "medium",
            "title": f"Sysmon Event {event_id}",
            "description": event_data.get("RuleName", "Imported Sysmon event"),
            "process_name": event_data.get("Image"),
            "parent_process": event_data.get("ParentImage"),
            "source_ip": event_data.get("SourceIp"),
            "destination_ip": event_data.get("DestinationIp"),
            "username": event_data.get("User"),
            "file_hash": event_data.get("Hashes"),
            "raw_payload": event_data,
        }
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


def parse_records(
    filename: str, content: bytes, selected_format: str | None, source_name: str, options: dict[str, Any] | None = None
) -> tuple[str, Iterable[dict[str, Any]]]:
    if len(content) > int(current_app.config["MAX_CONTENT_LENGTH"]):
        raise ValueError("file exceeds the configured upload limit")
    content_hash = hashlib.sha256(content).hexdigest()
    options = options or {}
    format_name = selected_format or "auto"
    if format_name == "auto":
        format_name = _detect_format(filename, content)
    if format_name in {"pcap", "pcapng"}:
        from .packet_ingestion import packet_records

        return format_name, _mapped_records(packet_records(content, source_name, int(current_app.config["MAX_IMPORT_ROWS"]) + 1), options, source_name)
    if format_name == "evtx":
        return format_name, _mapped_records(_evtx_records(content, source_name, content_hash), options, source_name)
    if format_name in {"sysmon_xml", "xml"}:
        return "sysmon_xml", _mapped_records(_sysmon_xml_records(content, source_name, content_hash), options, source_name)
    encoding = options.get("encoding", "utf-8-sig")
    if encoding != "utf-8-sig":
        try:
            text = content.decode(encoding)
        except UnicodeError as exc:
            raise ValueError("file encoding does not match the selected encoding") from exc
        if "\x00" in text or any(len(line.encode()) > 1048576 for line in text.splitlines()):
            raise ValueError("invalid binary text or oversized line")
    else:
        text = _decode(content)
    if format_name == "csv":
        records = _csv_records(text, source_name, content_hash, options.get("delimiter", ","))
        return format_name, _mapped_records(records, options, source_name)
    if format_name in {"jsonl", "ndjson"}:
        return "jsonl", _mapped_records(_json_records(text, source_name, content_hash, True, bool(options)), options, source_name)
    if format_name == "json":
        return format_name, _mapped_records(_json_records(text, source_name, content_hash, False), options, source_name)
    if format_name == "syslog":
        return format_name, _mapped_records(_syslog_records(text, source_name, content_hash), options, source_name)
    if format_name == "web":
        return format_name, _mapped_records(_web_records(text, source_name, content_hash), options, source_name)
    if format_name == "linux_auth":
        return format_name, _mapped_records(_auth_records(text, source_name, content_hash), options, source_name)
    raise ValueError("selected format is not supported")


def _mapped_records(records: Iterable[dict[str, Any]], options: dict[str, Any], source: str) -> Iterator[dict[str, Any]]:
    for record in records:
        if not options or record.get("__parse_error"):
            yield record
            continue
        raw_value = record.get("raw_payload")
        raw: dict[str, Any] = raw_value if isinstance(raw_value, dict) else {}
        known_time = (
            any(key in raw and raw[key] not in (None, "") for key in ("event_time", "timestamp", "time")) or record.get("source_type") == "packet_capture"
        )
        for source_field, destination in options.get("mapping", {}).items():
            if source_field in raw:
                record[destination] = raw[source_field]
                if destination == "event_time":
                    known_time = True
        try:
            value = record.get("event_time")
            if isinstance(value, bool):
                raise ValueError("boolean timestamps are invalid")
            if isinstance(value, str):
                moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if moment.tzinfo is None:
                    zone = ZoneInfo(options.get("source_timezone", "UTC"))
                    if moment.replace(tzinfo=zone, fold=0).utcoffset() != moment.replace(tzinfo=zone, fold=1).utcoffset():
                        raise ValueError("ambiguous or nonexistent local time; supply an explicit UTC offset")
                    moment = moment.replace(tzinfo=zone)
                record["event_time"] = moment.astimezone(UTC).isoformat().replace("+00:00", "Z")
            record["source"] = source
            normalized_value = record.get("normalized_fields")
            normalized: dict[str, Any] = normalized_value if isinstance(normalized_value, dict) else {}
            record["normalized_fields"] = {**normalized, "event_time_known": known_time}
            record["provenance"] = {
                **record.get("provenance", {}),
                "pipeline_options": options,
                "event_time_basis": "source" if known_time else "ingestion_fallback_not_observed_time",
            }
        except (ValueError, TypeError, ZoneInfoNotFoundError):
            record = {"__parse_error": "invalid, ambiguous or nonexistent source timestamp"}
        yield record


def _estimated_rows(format_name: str, content: bytes, options: dict[str, Any] | None = None) -> int:
    if options and options.get("encoding", "utf-8-sig") != "utf-8-sig":
        return 0
    if format_name == "json":
        try:
            value = json.loads(_decode(content))
        except (ValueError, RecursionError):
            return 1
        return len(value) if isinstance(value, list) else 1
    if format_name == "sysmon_xml":
        root = ElementTree.fromstring(content)
        return 1 if root.tag.rsplit("}", 1)[-1] == "Event" else sum(1 for item in root.iter() if item.tag.rsplit("}", 1)[-1] == "Event")
    if format_name in {"evtx", "pcap", "pcapng"}:
        return 0
    lines = sum(1 for line in _decode(content).splitlines() if line.strip())
    return max(lines - 1, 0) if format_name == "csv" else lines


def _job_view(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    if "autopsy_options" in item:
        item["autopsy_options"] = json.loads(item["autopsy_options"])
    available = bool(item.pop("evidence_ciphertext", None))
    item["raw_evidence"] = {
        "available": available,
        "sha256": item["content_hash"],
        "size": item["raw_size"],
    }
    return item


def _job_access(job_id: int, write: bool = False) -> sqlite3.Row | None:
    row = get_db().execute("SELECT * FROM ingestion_jobs WHERE id = ? AND workspace_id = ?", (job_id, workspace_id())).fetchone()
    if not row or not can_access_training_run(row["training_run_id"]):
        return None
    if operational_mode() and row["case_id"] is not None and not case_visible(row["case_id"], current_user() or {}):
        return None
    if write and row["created_by"] != actor_id() and not has_permission(current_user(), "sources.manage"):
        return None
    return row


def _job_content(row: sqlite3.Row) -> bytes:
    ciphertext = row["evidence_ciphertext"]
    if not ciphertext:
        raise ValueError("raw import evidence is unavailable")
    try:
        content = base64.b64decode(decrypt_secret(str(ciphertext)), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("raw import evidence cannot be decrypted") from exc
    if len(content) != int(row["raw_size"]) or not hashlib.sha256(content).hexdigest() == row["content_hash"]:
        raise ValueError("raw import evidence failed integrity validation")
    return content


def _mark_job_failed(job_id: int, message: str) -> None:
    now = iso_now()
    get_db().execute(
        "UPDATE ingestion_jobs SET status = 'failed', worker_id = NULL, lease_expires_at = NULL, last_error = ?, updated_at = ? WHERE id = ?",
        (message[:500], now, job_id),
    )
    get_db().execute(
        "INSERT INTO ingestion_errors (job_id, row_number, error_code, message, sample, created_at) VALUES (?, NULL, 'JOB_FAILURE', ?, NULL, ?)",
        (job_id, message[:500], now),
    )


def _process_job(job_id: int, worker_id: str | None = None, lease_seconds: int = 60) -> sqlite3.Row:
    job = get_db().execute("SELECT * FROM ingestion_jobs WHERE id = ?", (job_id,)).fetchone()
    if job is None:
        raise RuntimeError("import job disappeared during processing")
    if worker_id is not None and (job["status"] != "processing" or job["worker_id"] != worker_id):
        raise RuntimeError("import job is not leased by this worker")
    try:
        content = _job_content(job)
        _, records = parse_records(job["filename"], content, job["format"], job["source_name"], json.loads(job["autopsy_options"]))
    except (ValueError, json.JSONDecodeError, csv.Error, ElementTree.ParseError) as exc:
        _mark_job_failed(job_id, str(exc))
        failed = get_db().execute("SELECT * FROM ingestion_jobs WHERE id = ?", (job_id,)).fetchone()
        if failed is None:
            raise RuntimeError("import job disappeared after failure") from exc
        return failed
    accepted = int(job["accepted"])
    rejected = int(job["rejected"])
    skipped = int(job["skipped"])
    checkpoint = int(job["checkpoint"])
    maximum_rows = int(current_app.config["MAX_IMPORT_ROWS"])
    iterator = iter(records)
    exhausted = False
    for _ in range(checkpoint):
        try:
            next(iterator)
        except StopIteration:
            exhausted = True
            break
        except (ValueError, json.JSONDecodeError, csv.Error, ElementTree.ParseError):
            exhausted = True
            break
    now = iso_now()
    get_db().execute("UPDATE ingestion_jobs SET status = 'processing', started_at = COALESCE(started_at, ?), updated_at = ? WHERE id = ?", (now, now, job_id))
    while checkpoint < maximum_rows and not exhausted:
        batch: list[tuple[int, dict[str, Any] | None, Exception | None]] = []
        while len(batch) < IMPORT_CHUNK_SIZE and checkpoint + len(batch) < maximum_rows:
            row_number = checkpoint + len(batch) + 1
            try:
                batch.append((row_number, next(iterator), None))
            except StopIteration:
                exhausted = True
                break
            except (ValueError, json.JSONDecodeError, csv.Error, ElementTree.ParseError) as exc:
                batch.append((row_number, None, exc))
                exhausted = True
                break
        if not batch:
            break
        with transaction():
            if job["case_id"] is not None and not _import_case_authorized(job):
                _mark_job_failed(job_id, "case closed, archived or import creator no longer authorized")
                failed = get_db().execute("SELECT * FROM ingestion_jobs WHERE id = ?", (job_id,)).fetchone()
                if failed is None:
                    raise RuntimeError("import job disappeared after authorization failure")
                return failed
            if worker_id is not None:
                lease = (utc_now() + timedelta(seconds=lease_seconds)).isoformat().replace("+00:00", "Z")
                owned = get_db().execute(
                    "UPDATE ingestion_jobs SET lease_expires_at = ? WHERE id = ? AND status = 'processing' AND worker_id = ?",
                    (lease, job_id, worker_id),
                )
                if owned.rowcount != 1:
                    raise RuntimeError("import worker lease was lost")
            for row_number, record, parse_error in batch:
                if parse_error is not None:
                    rejected += 1
                    get_db().execute(
                        "INSERT INTO ingestion_errors (job_id, row_number, error_code, message, sample, created_at) VALUES (?, ?, 'PARSE_ERROR', ?, NULL, ?)",
                        (job_id, row_number, str(parse_error)[:500], iso_now()),
                    )
                    continue
                if record is None:
                    raise RuntimeError("import batch contains no record")
                get_db().execute("SAVEPOINT import_row")
                try:
                    if record.get("__parse_error"):
                        raise ValueError(str(record["__parse_error"]))
                    if job["case_id"] is not None:
                        record["idempotency_key"] = (
                            f"pipeline:{hashlib.sha256(job['autopsy_options'].encode()).hexdigest()}:{record.get('idempotency_key', row_number)}"
                        )
                    event_id, alerts, was_duplicate = ingest_event(
                        get_db(), record, int(job["created_by"]), int(job["workspace_id"]), job["training_run_id"], job["case_id"]
                    )
                    if job["case_id"] is not None:
                        _attach_import_result(job, event_id, alerts)
                    get_db().execute("RELEASE SAVEPOINT import_row")
                    if was_duplicate:
                        skipped += 1
                    else:
                        accepted += 1
                except (ValueError, OverflowError, sqlite3.Error) as exc:
                    get_db().execute("ROLLBACK TO SAVEPOINT import_row")
                    get_db().execute("RELEASE SAVEPOINT import_row")
                    rejected += 1
                    get_db().execute(
                        "INSERT INTO ingestion_errors (job_id, row_number, error_code, message, sample, created_at) VALUES (?, ?, 'VALIDATION_ERROR', ?, ?, ?)",
                        (job_id, row_number, str(exc)[:500], json.dumps(record, ensure_ascii=True)[:1000], iso_now()),
                    )
            checkpoint += len(batch)
            estimated = max(min(int(job["estimated_total"]), maximum_rows), 1)
            progress = min(checkpoint / estimated, 0.9999)
            get_db().execute(
                "UPDATE ingestion_jobs SET accepted = ?, rejected = ?, skipped = ?, total = ?, checkpoint = ?, progress = ?, updated_at = ? WHERE id = ?",
                (accepted, rejected, skipped, checkpoint, checkpoint, progress, iso_now(), job_id),
            )
            if job["case_id"] is not None:
                from .autopsy_domain import touch_case

                touch_case(job["case_id"])
        state = get_db().execute("SELECT status FROM ingestion_jobs WHERE id = ?", (job_id,)).fetchone()
        if state and state["status"] == "cancel_requested":
            get_db().execute(
                "UPDATE ingestion_jobs SET status = 'cancelled', worker_id = NULL, lease_expires_at = NULL, updated_at = ?, completed_at = ? WHERE id = ?",
                (iso_now(), iso_now(), job_id),
            )
            cancelled = get_db().execute("SELECT * FROM ingestion_jobs WHERE id = ?", (job_id,)).fetchone()
            if cancelled is None:
                raise RuntimeError("import job disappeared after cancellation")
            return cancelled
    if checkpoint >= maximum_rows and not exhausted:
        sentinel = object()
        overflow = next(iterator, sentinel)
        if overflow is not sentinel:
            rejected += 1
            get_db().execute(
                "INSERT INTO ingestion_errors (job_id, row_number, error_code, message, sample, created_at) VALUES (?, ?, 'ROW_LIMIT', ?, NULL, ?)",
                (job_id, checkpoint + 1, f"row limit {maximum_rows} exceeded", iso_now()),
            )
    completed = iso_now()
    status = "completed" if rejected == 0 else "completed_with_errors"
    get_db().execute(
        """UPDATE ingestion_jobs SET status = ?, accepted = ?, rejected = ?, skipped = ?, total = ?, checkpoint = ?, progress = 1,
        worker_id = NULL, lease_expires_at = NULL, last_error = NULL, updated_at = ?, completed_at = ? WHERE id = ?""",
        (status, accepted, rejected, skipped, checkpoint, checkpoint, completed, completed, job_id),
    )
    if job["source_id"]:
        error_rate = rejected / checkpoint if checkpoint else 0
        get_db().execute(
            "UPDATE event_sources SET rows_ingested = rows_ingested + ?, error_rate = ?, last_sync = ?, status = ?, updated_at = ? WHERE id = ?",
            (accepted, error_rate, completed, "connected" if accepted else "failed", completed, job["source_id"]),
        )
    record_audit(
        get_db(),
        "complete",
        "import",
        job_id,
        details={"accepted": accepted, "rejected": rejected, "skipped": skipped, "format": job["format"]},
        actor=int(job["created_by"]),
        workspace=int(job["workspace_id"]),
    )
    if job["case_id"] is not None:
        from .autopsy_domain import custody

        with transaction():
            custody(
                job["case_id"],
                "import_completed",
                {"job_id": job_id, "accepted": accepted, "rejected": rejected, "sha256": job["content_hash"]},
                actor=job["created_by"],
            )
    result = get_db().execute("SELECT * FROM ingestion_jobs WHERE id = ?", (job_id,)).fetchone()
    if result is None:
        raise RuntimeError("import job disappeared after completion")
    return result


def _import_case_authorized(job: sqlite3.Row) -> bool:
    case = (
        get_db().execute("SELECT status, archived_at FROM incident_cases WHERE id = ? AND workspace_id = ?", (job["case_id"], job["workspace_id"])).fetchone()
    )
    user = get_db().execute("SELECT id, workspace_id, role FROM users WHERE id = ? AND is_active = 1", (job["created_by"],)).fetchone()
    if not case or case["status"] == "closed" or case["archived_at"] or not user:
        return False
    principal = dict(user)
    policy = (
        get_db().execute("SELECT permissions FROM team_role_permissions WHERE workspace_id = ? AND role = ?", (user["workspace_id"], user["role"])).fetchone()
    )
    if policy:
        principal["role_permissions"] = json.loads(policy["permissions"])
    return has_permission(principal, "events.create") and case_visible(job["case_id"], principal)


def _attach_import_result(job: sqlite3.Row, event_id: int, alert_ids: list[int]) -> None:
    now = iso_now()
    get_db().execute(
        "INSERT OR IGNORE INTO case_events(case_id, event_id, attached_by, attached_at) VALUES (?, ?, ?, ?)", (job["case_id"], event_id, job["created_by"], now)
    )
    for alert_id in alert_ids:
        alert = get_db().execute("SELECT reason, dedup_key, evidence FROM alerts WHERE id = ? AND owner_case_id = ?", (alert_id, job["case_id"])).fetchone()
        if not alert:
            continue
        get_db().execute(
            "INSERT OR IGNORE INTO case_alerts(case_id, alert_id, attached_by, attached_at) VALUES (?, ?, ?, ?)",
            (job["case_id"], alert_id, job["created_by"], now),
        )
        get_db().execute(
            "INSERT OR IGNORE INTO case_evidence(case_id, evidence_type, reference_id, title, sha256, provenance, added_by, added_at) VALUES (?, 'alert', ?, ?, ?, ?, ?, ?)",
            (job["case_id"], str(alert_id), alert["reason"][:255], alert["dedup_key"], alert["evidence"], job["created_by"], now),
        )


def _safe_import_filename(value: str) -> str:
    name = secure_filename(value) or "import.log"
    suffix = Path(value).suffix.lower()
    if suffix in {".csv", ".json", ".jsonl", ".ndjson", ".log", ".txt", ".xml", ".evtx", ".pcap", ".pcapng"} and not name.lower().endswith(suffix):
        return "import" + suffix
    return name


def _upload_payload() -> tuple[str, bytes, str | None, int | None, int | None]:
    if request.files:
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            raise ValueError("file is required")
        filename = _safe_import_filename(uploaded.filename)
        content = uploaded.stream.read(int(current_app.config["MAX_CONTENT_LENGTH"]) + 1)
        selected_format = request.form.get("format", "auto")
        source_id = int(request.form["source_id"]) if request.form.get("source_id") else None
        training_run_id = int(request.form["training_run_id"]) if request.form.get("training_run_id") else None
        return filename, content, selected_format, source_id, training_run_id
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("content"), str):
        raise ValueError("multipart file or textual content is required")
    filename = _safe_import_filename(str(data.get("filename") or "import.log"))
    return (
        filename,
        data["content"].encode(),
        str(data.get("format") or "auto"),
        data.get("source_id") if isinstance(data.get("source_id"), int) else None,
        data.get("training_run_id") if isinstance(data.get("training_run_id"), int) else None,
    )


def _upload_options() -> tuple[int | None, dict[str, Any]]:
    if not operational_mode():
        return None, {}
    from .autopsy_domain import text_value
    from .cases import _case_row

    case_id = (request.view_args or {}).get("case_id")
    case = _case_row(case_id) if type(case_id) is int else None
    if not case or case["status"] == "closed":
        raise ValueError("an open, authorized case is required")
    data = request.form.to_dict() if request.files else request.get_json(silent=True)
    allowed = {"filename", "content", "format", "source_id", "source_label", "mapping", "source_timezone", "encoding", "delimiter"}
    if not isinstance(data, dict) or set(data) - allowed:
        raise ValueError("unknown import parameters")
    if not request.files and not isinstance(data.get("filename", "import.log"), str):
        raise ValueError("filename must be a string")
    mapping: Any = data.get("mapping", {})
    if isinstance(mapping, str) and len(mapping) <= 10000:
        mapping = json.loads(mapping)
    fields = {
        "event_time",
        "title",
        "event_type",
        "category",
        "severity",
        "description",
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
    }
    if (
        not isinstance(mapping, dict)
        or len(mapping) > 50
        or any(not isinstance(key, str) or not 1 <= len(key) <= 100 or not isinstance(value, str) or value not in fields for key, value in mapping.items())
    ):
        raise ValueError("field mapping contains invalid source/destination fields")
    if len(set(mapping.values())) != len(mapping):
        raise ValueError("map each destination field only once")
    encoding, delimiter = data.get("encoding", "utf-8-sig"), data.get("delimiter", ",")
    if encoding not in ("utf-8-sig", "utf-8", "utf-16", "latin-1") or delimiter not in (",", ";", "\t", "|"):
        raise ValueError("unsupported encoding or delimiter")
    zone = text_value(data.get("source_timezone", "UTC"), 100, True)
    if not re.fullmatch(r"[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*", zone):
        raise ValueError("invalid source timezone")
    try:
        ZoneInfo(zone)
    except ZoneInfoNotFoundError as exc:
        raise ValueError("source timezone is not available locally") from exc
    options = {"mapping": mapping, "source_timezone": zone, "encoding": encoding, "delimiter": delimiter}
    if data.get("source_label"):
        options["source_label"] = text_value(data["source_label"], 100, True)
    if "source_id" in data and data["source_id"] not in (None, ""):
        if request.files:
            if not str(data["source_id"]).isdecimal() or not 1 <= int(data["source_id"]) <= 9223372036854775807:
                raise ValueError("source id must be an integer")
        elif type(data["source_id"]) is not int or not 1 <= data["source_id"] <= 9223372036854775807:
            raise ValueError("source id must be an integer")
    return case_id, options


@ingestion_api.post("/api/imports/preview")
@require_permission("events.create")
def preview_import():
    try:
        _, options = _upload_options()
        filename, content, selected_format, source_id, training_run_id = _upload_payload()
        if not can_access_training_run(training_run_id):
            return error_response("TRAINING_RUN_NOT_FOUND", "جلسة التدريب غير موجودة", 404)
        source = (
            get_db().execute("SELECT name FROM event_sources WHERE id = ? AND workspace_id = ?", (source_id, workspace_id())).fetchone() if source_id else None
        )
        format_name, records = parse_records(
            filename, content, selected_format, options.get("source_label") or (source["name"] if source else "file-import"), options
        )
        preview = []
        for index, record in enumerate(records):
            if index >= 20:
                break
            preview.append(record)
        return jsonify(
            {"filename": filename, "format": format_name, "content_hash": hashlib.sha256(content).hexdigest(), "preview": preview, "commit_required": True}
        )
    except (ValueError, json.JSONDecodeError, csv.Error, ElementTree.ParseError) as exc:
        return error_response("IMPORT_PREVIEW_FAILED", str(exc), 422)


@ingestion_api.post("/api/imports")
@require_permission("events.create")
def create_import():
    try:
        case_id, options = _upload_options()
        filename, content, selected_format, source_id, training_run_id = _upload_payload()
    except (ValueError, OverflowError) as exc:
        return error_response("INVALID_IMPORT", str(exc), 422)
    if len(content) > int(current_app.config["MAX_CONTENT_LENGTH"]):
        return error_response("UPLOAD_TOO_LARGE", "الملف يتجاوز الحجم المسموح", 413)
    if not can_access_training_run(training_run_id):
        return error_response("TRAINING_RUN_NOT_FOUND", "جلسة التدريب غير موجودة", 404)
    source = (
        get_db().execute("SELECT id, name FROM event_sources WHERE id = ? AND workspace_id = ? AND is_active = 1", (source_id, workspace_id())).fetchone()
        if source_id
        else None
    )
    if source_id and not source:
        return error_response("SOURCE_NOT_FOUND", "المصدر غير موجود أو معطل", 404)
    source_name = options.get("source_label") or (source["name"] if source else "file-import")
    serialized_options = json.dumps(options, sort_keys=True, separators=(",", ":"))
    content_hash = hashlib.sha256(content).hexdigest()
    duplicate = (
        get_db()
        .execute(
            "SELECT * FROM ingestion_jobs WHERE workspace_id = ? AND content_hash = ? AND training_run_id IS ? AND case_id IS ? AND autopsy_options = ?",
            (workspace_id(), content_hash, training_run_id, case_id, serialized_options),
        )
        .fetchone()
    )
    if duplicate:
        return jsonify({**_job_view(duplicate), "duplicate": True})
    queued = int(
        get_db()
        .execute(
            "SELECT COUNT(*) FROM ingestion_jobs WHERE workspace_id = ? AND status IN ('queued', 'processing', 'interrupted')",
            (workspace_id(),),
        )
        .fetchone()[0]
    )
    if queued >= int(current_app.config["MAX_PENDING_IMPORT_JOBS"]):
        return error_response("IMPORT_QUEUE_FULL", "قائمة مهام الاستيراد ممتلئة؛ أعد المحاولة لاحقًا", 429)
    try:
        format_name, _ = parse_records(filename, content, selected_format, source_name, options)
        estimated_total = _estimated_rows(format_name, content, options)
    except (ValueError, json.JSONDecodeError, csv.Error, ElementTree.ParseError) as exc:
        return error_response("IMPORT_FORMAT_ERROR", str(exc), 422)
    now = iso_now()
    original_filename = request.files["file"].filename if request.files else (request.get_json(silent=True) or {}).get("filename", filename)
    if operational_mode():
        from .autopsy_domain import text_value

        try:
            original_filename = text_value(original_filename, 255, True)
        except ValueError as exc:
            return error_response("INVALID_FILENAME", str(exc), 422)
    ciphertext = encrypt_secret(base64.b64encode(content).decode())
    with transaction():
        cursor = get_db().execute(
            """INSERT INTO ingestion_jobs
            (job_id, workspace_id, source_id, training_run_id, filename, format, content_hash, evidence_ciphertext,
            raw_size, estimated_total, source_name, status, parser_version, created_by, created_at, updated_at, available_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', 'socify-import-2', ?, ?, ?, ?)""",
            (
                public_id("IMP"),
                workspace_id(),
                source_id,
                training_run_id,
                filename,
                format_name,
                content_hash,
                ciphertext,
                len(content),
                estimated_total,
                source_name,
                actor_id(),
                now,
                now,
                now,
            ),
        )
        job_database_id = inserted_id(cursor)
        get_db().execute(
            "UPDATE ingestion_jobs SET case_id = ?, autopsy_options = ?, original_filename = ? WHERE id = ?",
            (case_id, serialized_options, original_filename, job_database_id),
        )
        if case_id is not None:
            from .autopsy_domain import custody, touch_case

            get_db().execute(
                "INSERT INTO autopsy_case_imports(case_id, job_id, attached_by, attached_at) VALUES (?, ?, ?, ?)", (case_id, job_database_id, actor_id(), now)
            )
            get_db().execute(
                "INSERT INTO case_evidence(case_id, evidence_type, reference_id, title, sha256, provenance, added_by, added_at) VALUES (?, 'import', ?, ?, ?, ?, ?, ?)",
                (
                    case_id,
                    str(job_database_id),
                    filename,
                    content_hash,
                    json.dumps({"source": source_name, "options": options, "format": format_name}),
                    actor_id(),
                    now,
                ),
            )
            custody(case_id, "original_import_received", {"job_id": job_database_id, "sha256": content_hash, "bytes": len(content)})
            touch_case(case_id)
        record_audit(get_db(), "create", "import", job_database_id, details={"format": format_name, "sha256": content_hash, "size": len(content)})
    if request.args.get("defer") == "1" or not current_app.config["IMPORT_INLINE_EXECUTION"] or case_id is not None and format_name in {"pcap", "pcapng"}:
        queued = get_db().execute("SELECT * FROM ingestion_jobs WHERE id = ?", (job_database_id,)).fetchone()
        if queued is None:
            raise RuntimeError("import job disappeared after creation")
        return jsonify(_job_view(queued)), 202, {"Location": f"/api/imports/{job_database_id}"}
    return jsonify(_job_view(_process_job(job_database_id))), 201, {"Location": f"/api/imports/{job_database_id}"}


@ingestion_api.get("/api/imports")
@require_permission("events.read")
def list_imports():
    scope, parameters = training_scope_sql("training_run_id")
    rows = (
        get_db()
        .execute(f"SELECT * FROM ingestion_jobs WHERE workspace_id = ?{scope} ORDER BY created_at DESC LIMIT 100", (workspace_id(), *parameters))
        .fetchall()
    )
    return jsonify({"items": [_job_view(row) for row in rows]})


@ingestion_api.get("/api/imports/<int:job_id>")
@require_permission("events.read")
def import_detail(job_id: int):
    row = _job_access(job_id)
    if not row:
        return error_response("IMPORT_NOT_FOUND", "مهمة الاستيراد غير موجودة", 404)
    item = _job_view(row)
    item["errors"] = [
        dict(error)
        for error in get_db()
        .execute("SELECT row_number, error_code, message, sample, created_at FROM ingestion_errors WHERE job_id = ? ORDER BY id LIMIT 1000", (job_id,))
        .fetchall()
    ]
    return jsonify(item)


@ingestion_api.post("/api/imports/<int:job_id>/resume")
@require_permission("events.create")
def resume_import(job_id: int):
    row = _job_access(job_id, True)
    if not row:
        return error_response("IMPORT_NOT_FOUND", "مهمة الاستيراد غير موجودة", 404)
    if row["status"] not in {"queued", "interrupted", "failed"}:
        return error_response("IMPORT_NOT_RESUMABLE", "مهمة الاستيراد ليست في حالة قابلة للاستئناف", 409)
    get_db().execute(
        """UPDATE ingestion_jobs SET status = 'queued', retry_count = retry_count + 1, completed_at = NULL,
        available_at = ?, worker_id = NULL, lease_expires_at = NULL, updated_at = ? WHERE id = ?""",
        (iso_now(), iso_now(), job_id),
    )
    record_audit(get_db(), "resume", "import", job_id, details={"checkpoint": row["checkpoint"], "retry": int(row["retry_count"]) + 1})
    if not current_app.config["IMPORT_INLINE_EXECUTION"]:
        queued = get_db().execute("SELECT * FROM ingestion_jobs WHERE id = ?", (job_id,)).fetchone()
        if queued is None:
            raise RuntimeError("import job disappeared after resume")
        return jsonify(_job_view(queued)), 202
    return jsonify(_job_view(_process_job(job_id)))


@ingestion_api.post("/api/imports/<int:job_id>/cancel")
@require_permission("events.create")
def cancel_import(job_id: int):
    row = _job_access(job_id, True)
    if not row:
        return error_response("IMPORT_NOT_FOUND", "مهمة الاستيراد غير موجودة", 404)
    if row["status"] not in {"queued", "processing", "interrupted", "failed"}:
        return error_response("IMPORT_NOT_CANCELLABLE", "مهمة الاستيراد ليست في حالة قابلة للإلغاء", 409)
    status = "cancel_requested" if row["status"] == "processing" else "cancelled"
    completed_at = None if status == "cancel_requested" else iso_now()
    get_db().execute("UPDATE ingestion_jobs SET status = ?, updated_at = ?, completed_at = ? WHERE id = ?", (status, iso_now(), completed_at, job_id))
    record_audit(get_db(), "cancel", "import", job_id, details={"status": status})
    updated = get_db().execute("SELECT * FROM ingestion_jobs WHERE id = ?", (job_id,)).fetchone()
    if updated is None:
        raise RuntimeError("import job disappeared after cancellation")
    return jsonify(_job_view(updated))


@ingestion_api.get("/api/imports/<int:job_id>/evidence")
@require_permission("events.read")
def import_evidence(job_id: int):
    row = _job_access(job_id)
    if not row:
        return error_response("IMPORT_NOT_FOUND", "مهمة الاستيراد غير موجودة", 404)
    try:
        content = _job_content(row)
    except ValueError as exc:
        return error_response("IMPORT_EVIDENCE_INVALID", str(exc), 409)
    record_audit(get_db(), "read", "import_evidence", job_id, details={"sha256": row["content_hash"]})
    response = Response(content, mimetype="application/octet-stream")
    response.headers["Content-Disposition"] = f"attachment; filename={row['filename']}"
    response.headers["Digest"] = f"sha-256={base64.b64encode(bytes.fromhex(row['content_hash'])).decode()}"
    return response
