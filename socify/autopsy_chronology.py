import json
import re
from heapq import merge
from itertools import islice
from typing import Any

from flask import Blueprint, jsonify, request

from .autopsy_api import manager, record_view, records_for_case
from .autopsy_ingestion import log_query, metadata_scope
from .autopsy_pipeline import case_full_access
from .case_counts import read_snapshot
from .cases import _case_row
from .chronology_time import record_clock, sql_utc_key, utc_key
from .db import get_db
from .security import actor_id, current_user, error_response, has_permission, require_permission
from .timeutils import parse_timestamp, utc_now

autopsy_chronology_api = Blueprint("autopsy_chronology", __name__)
CHRONOLOGY_KINDS = ("timeline", "war_room", "response", "bookmark", "escalation")
RECORD_KINDS = "('timeline','war_room','response','bookmark','escalation')"


def migrate(connection):
    connection.execute(
        f"CREATE INDEX IF NOT EXISTS idx_autopsy_chronology_logs ON case_events(case_id,active_event,time_known DESC,({sql_utc_key('event_time')}),event_id)"
    )
    connection.execute(f"CREATE INDEX IF NOT EXISTS idx_autopsy_chronology_records ON autopsy_records(case_id,({sql_utc_key(record_clock())}),id)")
    connection.execute(f"CREATE INDEX IF NOT EXISTS idx_autopsy_chronology_notes ON case_notes(case_id,({sql_utc_key('created_at')}),id)")


def record_entry(row):
    record = record_view(row) if isinstance(row["payload"], str) else dict(row)
    payload, kind = record["payload"], record["kind"]
    moment, basis = record["created_at"], "documentation_time"
    if kind == "timeline":
        moment = payload["event_time"]
        basis = "hypothesis_time" if payload["category"] == "hypothesis" else "investigator_observation_time"
    elif kind == "response" and payload["status"] in {"succeeded", "failed"} and payload.get("performed_at"):
        moment, basis = payload["performed_at"], "reported_action_time"
    elif kind == "escalation" and payload.get("raised_at"):
        moment, basis = payload["raised_at"], "escalation_time"
    return {
        "id": record["id"],
        "key": f"record:{record['id']}",
        "entry_type": "record",
        "kind": kind,
        "title": payload.get("title", "ملاحظة تحقيق"),
        "event_time": moment,
        "time_basis": basis,
        "observed_time_known": basis != "documentation_time",
        "actor_id": record["created_by"],
        "updated_at": record["updated_at"],
        "version": record["version"],
        "future_time": parse_timestamp(moment) > utc_now(),
        "record": record,
    }


def note_entry(row):
    return {
        "id": row["id"],
        "key": f"note:{row['id']}",
        "entry_type": "note",
        "kind": "legacy_note",
        "title": "ملاحظة تحقيق محفوظة",
        "event_time": row["created_at"],
        "time_basis": "documentation_time",
        "observed_time_known": False,
        "actor_id": row["author_id"],
        "updated_at": row["updated_at"],
        "version": row["version"],
        "body": row["body"],
    }


def report_chronology(payload):
    entries = []
    for row in payload.get("evidenced_timeline", []):
        normalized = json.loads(row["normalized_fields"] or "{}")
        provenance = json.loads(row["provenance"] or "{}")
        known = normalized.get("event_time_known") is True
        entries.append(
            {
                "entry_type": "log",
                "id": row["id"],
                "title": row["title"],
                "event_time": row["event_time"] if known else None,
                "time_basis": provenance.get("event_time_basis", "unknown_source_time"),
                "raw_sha256": row["raw_hash"],
            }
        )
    for kind in CHRONOLOGY_KINDS:
        for row in payload.get("records", {}).get(kind, []):
            entry = record_entry(row)
            entries.append(
                {
                    **{key: value for key, value in entry.items() if key != "record"},
                    "evidence_id": row["payload"].get("evidence_id"),
                    "task_id": row["payload"].get("task_id"),
                }
            )
    for row in payload.get("shared_notes", []):
        entries.append({key: value for key, value in note_entry(row).items() if key != "body"})
    entries.sort(key=lambda entry: (entry["event_time"] is None, utc_key(entry["event_time"]) if entry["event_time"] else "", entry["entry_type"], entry["id"]))
    return {
        "entries": entries,
        "scope": "سجلات اختيرت كأدلة وملاحظات وإجراءات مشتركة فقط؛ الملف الكامل للسجلات يصدر منفصلًا. وقت التوثيق والفرضية لا يثبت وقت وقوع الهجوم، والطوابع المجهولة في النهاية.",
    }


def source_filter(case_id, source, clock, private_clause):
    alias = "r" if source == "autopsy_records" else "n"
    clauses, args = [f"{alias}.case_id=?", private_clause], [case_id]
    if source == "autopsy_records":
        clauses.append(f"r.kind IN {RECORD_KINDS}")
    if "?" in private_clause:
        args.append(actor_id())
    query = request.args.get("q", "").strip()
    if query:
        words = [word for word in re.findall(r"[\w.-]+", query) if any(char.isalnum() for char in word)][:20]
        text = (
            "n.body"
            if source == "case_notes"
            else "COALESCE(json_extract(r.payload,'$.title'),'')||' '||COALESCE(json_extract(r.payload,'$.body'),'')||' '||COALESCE(json_extract(r.payload,'$.details'),'')||' '||COALESCE(json_extract(r.payload,'$.notes'),'')||' '||COALESCE(json_extract(r.payload,'$.decision'),'')"
        )
        if not words:
            clauses.append("0=1")
        for word in words:
            clauses.append(f"({text}) LIKE ? ESCAPE '\\'")
            args.append("%" + word.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    for key, operator in (("start", ">="), ("end", "<=")):
        if request.args.get(key):
            clauses.append(f"{sql_utc_key(clock)} {operator} ?")
            args.append(utc_key(request.args[key]))
    return " AND ".join(clauses), args


def metadata_page(source, where, args, record_where, record_args, note_where, note_args, page, limit):
    queries = (
        (
            f"SELECT 'log' AS entry_type,ce.event_id AS id,ce.time_known AS known,{sql_utc_key('ce.event_time')} AS time_key FROM {source} WHERE {where} ORDER BY ce.time_known DESC,{sql_utc_key('ce.event_time')},ce.event_id",
            args,
        ),
        (
            f"SELECT 'record' AS entry_type,r.id,1 AS known,{sql_utc_key(record_clock('r'))} AS time_key FROM autopsy_records r INDEXED BY idx_autopsy_chronology_records WHERE {record_where} ORDER BY {sql_utc_key(record_clock('r'))},r.id",
            record_args,
        ),
        (
            f"SELECT 'note' AS entry_type,n.id,1 AS known,{sql_utc_key('n.created_at')} AS time_key FROM case_notes n WHERE {note_where} ORDER BY {sql_utc_key('n.created_at')},n.id",
            note_args,
        ),
    )
    cursors = []
    try:
        for sql, parameters in queries:
            cursors.append(get_db().execute(sql, parameters))
        ordered = merge(*cursors, key=lambda row: (-row["known"], row["time_key"], row["entry_type"], row["id"]))
        offset = (page - 1) * limit
        return list(islice(ordered, offset, offset + limit + 1))
    finally:
        for cursor in cursors:
            cursor.close()


def chronology_page(case_id, page, limit):
    where, args = log_query(case_id)
    source, where, total, relation = metadata_scope(where, args)
    record_private = "1=1" if manager() else "(COALESCE(json_extract(r.payload,'$.visibility'),'team')!='private' OR r.created_by=?)"
    note_private = "1=1" if has_permission(current_user(), "cases.override") else "(n.visibility='team' OR n.author_id=?)"
    record_where, record_args = source_filter(case_id, "autopsy_records", record_clock("r"), record_private)
    note_where, note_args = source_filter(case_id, "case_notes", "n.created_at", note_private)
    for table, alias, predicate, parameters in (("autopsy_records", "r", record_where, record_args), ("case_notes", "n", note_where, note_args)):
        count = get_db().execute(f"SELECT COUNT(*) FROM (SELECT 1 FROM {table} {alias} WHERE {predicate} LIMIT 10001)", parameters).fetchone()[0]
        total += min(count, 10000)
        if count > 10000:
            relation = "gte"
    metadata = metadata_page(source, where, args, record_where, record_args, note_where, note_args, page, limit)
    details: dict[str, dict[int, dict[str, Any]]] = {kind: {} for kind in ("log", "record", "note")}
    for kind in details:
        ids = [row["id"] for row in metadata[:limit] if row["entry_type"] == kind]
        if not ids:
            continue
        placeholders = ",".join("?" for _ in ids)
        if kind == "log":
            rows = (
                get_db()
                .execute(
                    f"SELECT e.id,e.title,e.event_time,e.ingested_at,e.source,e.event_type,e.severity,ce.time_known,json_extract(e.provenance,'$.event_time_basis') AS time_basis FROM security_events e JOIN case_events ce ON ce.event_id=e.id AND ce.case_id=? WHERE e.id IN ({placeholders})",
                    (case_id, *ids),
                )
                .fetchall()
            )
            for event in rows:
                known = bool(event["time_known"])
                details[kind][event["id"]] = {
                    **dict(event),
                    "key": f"log:{event['id']}",
                    "entry_type": "log",
                    "observed_time_known": known,
                    "event_time": event["event_time"] if known else None,
                }
        else:
            table = "autopsy_records" if kind == "record" else "case_notes"
            for row in get_db().execute(f"SELECT * FROM {table} WHERE case_id=? AND id IN ({placeholders})", (case_id, *ids)).fetchall():
                details[kind][row["id"]] = record_entry(row) if kind == "record" else note_entry(row)
    items = [details[row["entry_type"]][row["id"]] for row in metadata[:limit]]
    return {
        "items": items,
        "total": total,
        "total_relation": relation,
        "has_next": len(metadata) > limit,
        "page": page,
        "limit": limit,
        "bookmarks": records_for_case(case_id, "bookmark", 500),
        "views": records_for_case(case_id, "timeline_view", 100),
        "limits": "توقيت التوثيق والفرضية والإجراء يميز عن زمن المصدر. مرشح الخطورة يخص السجلات فقط؛ ملاحظات التحقيق بلا درجة خطورة. البحث كلمات مفهرسة للسجلات وكلمات نصية للملاحظات. الطوابع المجهولة في النهاية؛ لا يُستنتج ترتيب سببي.",
    }


@autopsy_chronology_api.get("/api/cases/<int:case_id>/chronology")
@require_permission("cases.read")
def case_chronology(case_id):
    with read_snapshot():
        if not _case_row(case_id):
            return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
        if not case_full_access(case_id):
            return error_response("BATCH_SCOPE_REQUIRED", "الخط الشامل يحتاج نطاق القضية الكامل؛ استخدم خط السجلات المصرح بها", 403)
        try:
            if set(request.args) - {"q", "severity", "start", "end", "page", "limit"}:
                raise ValueError("مرشح غير معروف للخط الشامل")
            page, limit = int(request.args.get("page", 1)), int(request.args.get("limit", 50))
            if not 1 <= page <= 1000000 or not 1 <= limit <= 100:
                raise ValueError("الترقيم خارج النطاق")
            return jsonify(chronology_page(case_id, page, limit))
        except ValueError as exc:
            return error_response("INVALID_CHRONOLOGY_FILTER", str(exc), 422)
