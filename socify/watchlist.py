import hashlib
import ipaddress
import json
import re
import sqlite3
from typing import Any
from urllib.parse import urlparse

from flask import Blueprint, jsonify, request

from .audit import record_audit
from .db import get_db, inserted_id, transaction
from .detection import SEVERITIES
from .schema import public_id
from .security import actor_id, error_response, require_permission, workspace_id
from .timeutils import iso_now

watchlist_api = Blueprint("watchlist", __name__)

INDICATOR_TYPES = {"email", "ip", "cidr", "domain", "url", "sha256"}
EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")
DOMAIN_PATTERN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
IPV4_IN_TEXT = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
WATCHLIST_RULE_NAME = "[SOCify Watchlist] Indicator Match"


def migrate(connection: sqlite3.Connection) -> None:
    connection.execute(
        """CREATE TABLE IF NOT EXISTS watchlist_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER NOT NULL REFERENCES training_workspaces(id),
            indicator_type TEXT NOT NULL CHECK(indicator_type IN ('email', 'ip', 'cidr', 'domain', 'url', 'sha256')),
            value TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'high',
            note TEXT NOT NULL DEFAULT '',
            source_case_id INTEGER REFERENCES incident_cases(id),
            is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
            hits_count INTEGER NOT NULL DEFAULT 0,
            last_hit_at TEXT,
            last_hit_case_id INTEGER REFERENCES incident_cases(id),
            created_by INTEGER NOT NULL REFERENCES users(id),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(workspace_id, indicator_type, value)
        )"""
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_watchlist_ws_active ON watchlist_entries(workspace_id, is_active, indicator_type)")


def _normalize_ip_obj(raw: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    cleaned = raw.strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]
    addr = ipaddress.ip_address(cleaned)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def normalize_watchlist_indicator(indicator_type: str, raw_value: str) -> str:
    kind = (indicator_type or "").strip().lower()
    val = (raw_value or "").strip()
    if kind not in INDICATOR_TYPES:
        raise ValueError("نوع المؤشر غير مدعوم؛ استخدم email أو ip أو cidr أو domain أو url أو sha256")
    if not val or len(val) > 512:
        raise ValueError("قيمة المؤشر مطلوبة وبحد أقصى 512 محرفًا")
    if kind == "email":
        lowered = val.lower()
        if not EMAIL_PATTERN.match(lowered):
            raise ValueError("صيغة البريد الإلكتروني غير صالحة")
        return lowered
    if kind == "ip":
        try:
            return str(_normalize_ip_obj(val))
        except ValueError as exc:
            raise ValueError("عنوان IP غير صالح") from exc
    if kind == "cidr":
        try:
            net = ipaddress.ip_network(val, strict=False)
            return str(net)
        except ValueError as exc:
            raise ValueError("نطاق CIDR غير صالح") from exc
    if kind == "domain":
        lowered = val.lower().rstrip(".")
        if not DOMAIN_PATTERN.match(lowered):
            raise ValueError("اسم النطاق غير صالح")
        return lowered
    if kind == "url":
        parsed = urlparse(val)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ValueError("الرابط يجب أن يبدأ بـ http:// أو https://")
        return val
    if kind == "sha256":
        lowered = val.lower()
        if not SHA256_PATTERN.match(lowered):
            raise ValueError("بصمة SHA-256 يجب أن تتكون من 64 محرفًا سداسيًا عشريًا")
        return lowered
    raise ValueError("نوع المؤشر غير صالح")


def _entry_view(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["is_active"] = bool(data["is_active"])
    return data


def _ensure_watchlist_rule_id(connection: sqlite3.Connection, ws_id: int, fallback_actor: int | None) -> int | None:
    existing = connection.execute(
        "SELECT id FROM rules WHERE workspace_id = ? AND name = ? LIMIT 1",
        (ws_id, WATCHLIST_RULE_NAME),
    ).fetchone()
    if existing:
        return int(existing["id"])
    creator = fallback_actor
    if creator is None:
        user_row = connection.execute("SELECT id FROM users WHERE workspace_id = ? ORDER BY id LIMIT 1", (ws_id,)).fetchone()
        if not user_row:
            user_row = connection.execute("SELECT id FROM users ORDER BY id LIMIT 1").fetchone()
        if not user_row:
            return None
        creator = int(user_row["id"])
    now = iso_now()
    dsl = {"condition": {"field": "event_type", "operator": "equals", "value": "__watchlist_sentinel__"}, "mitre_ids": []}
    action = {"type": "alert", "severity": "high", "confidence": 0.95}
    cursor = connection.execute(
        """INSERT INTO rules
           (workspace_id, name, description, condition_type, condition_value, dsl_json, action_type, action_value,
            version, is_active, deployment_state, match_count, false_positive_count, suppressions,
            average_evaluation_ms, created_by, created_at, updated_at)
           VALUES (?, ?, 'Automatic correlation against workspace Suspicious Emails & IPs Watchlist.',
                   'dsl', ?, ?, 'create_alert', ?, 1, 0, 'published', 0, 0, 0, 0, ?, ?, ?)""",
        (ws_id, WATCHLIST_RULE_NAME, json.dumps(dsl), json.dumps(dsl), json.dumps(action), creator, now, now),
    )
    rule_id = inserted_id(cursor)
    connection.execute(
        """INSERT INTO rule_versions (rule_id, version, dsl_json, action_json, change_summary, created_by, created_at)
           VALUES (?, 1, ?, ?, 'Seed SOCify V6 Watchlist correlation sentinel rule', ?, ?)""",
        (rule_id, json.dumps(dsl), json.dumps(action), creator, now),
    )
    return rule_id


def _event_matches_watchlist_entry(
    event_row: sqlite3.Row, entry: sqlite3.Row, parsed_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address], blob_lower: str
) -> tuple[bool, str]:
    kind = str(entry["indicator_type"])
    target = str(entry["value"])
    if kind == "ip":
        try:
            target_ip = _normalize_ip_obj(target)
        except ValueError:
            return False, ""
        if any(ip_obj == target_ip for ip_obj in parsed_ips):
            return True, f"ip={target}"
        return False, ""
    if kind == "cidr":
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return False, ""
        for ip_obj in parsed_ips:
            if ip_obj.version == net.version and ip_obj in net:
                return True, f"ip={ip_obj} in cidr={target}"
        return False, ""
    if kind == "email":
        t_low = target.lower()
        uname = str(event_row["username"] or "").strip().lower()
        if uname == t_low or t_low in blob_lower:
            return True, f"email={t_low}"
        return False, ""
    if kind == "domain":
        t_low = target.lower()
        host = str(event_row["hostname"] or "").strip().lower()
        if host == t_low or host.endswith(f".{t_low}") or t_low in blob_lower:
            return True, f"domain={t_low}"
        return False, ""
    if kind == "url":
        if target.lower() in blob_lower:
            return True, f"url={target}"
        return False, ""
    if kind == "sha256":
        t_low = target.lower()
        fhash = str(event_row["file_hash"] or "").strip().lower()
        if fhash == t_low or t_low in blob_lower:
            return True, f"sha256={t_low}"
        return False, ""
    return False, ""


def evaluate_watchlist_for_event(connection: sqlite3.Connection, event_id: int) -> list[int]:
    row = connection.execute("SELECT * FROM security_events WHERE id = ?", (event_id,)).fetchone()
    if not row or row["source"] == "rules_engine" or not row["autopsy_active"] or row["source_type"] == "training":
        return []
    ws_id = int(row["workspace_id"])
    entries = connection.execute(
        "SELECT * FROM watchlist_entries WHERE workspace_id = ? AND is_active = 1 ORDER BY id LIMIT 1000",
        (ws_id,),
    ).fetchall()
    if not entries:
        return []

    candidate_ip_strs: list[str] = []
    for col in ("source_ip", "destination_ip"):
        if row[col]:
            candidate_ip_strs.append(str(row[col]))
    blob_lower = " \n ".join(str(row[col] or "") for col in ("title", "description", "username", "hostname", "file_hash", "raw_data")).lower()
    candidate_ip_strs.extend(IPV4_IN_TEXT.findall(blob_lower))

    parsed_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    seen_ips: set[str] = set()
    for raw_ip in candidate_ip_strs:
        try:
            ip_obj = _normalize_ip_obj(raw_ip)
            key = str(ip_obj)
            if key not in seen_ips:
                seen_ips.add(key)
                parsed_ips.append(ip_obj)
        except ValueError:
            continue

    rule_id: int | None = None
    created_alert_ids: list[int] = []
    now = iso_now()
    owner_case_id = row["owner_case_id"]

    for entry in entries:
        matched, match_detail = _event_matches_watchlist_entry(row, entry, parsed_ips, blob_lower)
        if not matched:
            continue
        dedup_material = f"watchlist|{entry['id']}|event|{event_id}|{row['training_run_id'] or ''}"
        dedup_key = hashlib.sha256(dedup_material.encode()).hexdigest()
        if connection.execute("SELECT 1 FROM alerts WHERE dedup_key = ?", (dedup_key,)).fetchone():
            continue
        if rule_id is None:
            rule_id = _ensure_watchlist_rule_id(connection, ws_id, row["created_by"])
            if rule_id is None:
                return created_alert_ids
        sev = str(entry["severity"] or "high").lower()
        if sev not in SEVERITIES:
            sev = "high"
        note_suffix = f" ({entry['note']})" if entry["note"] else ""
        reason = f"[Watchlist Match] {entry['indicator_type'].upper()} {entry['value']}{note_suffix} matched event #{event_id}"
        alert_pub_id = public_id("ALT")
        trace = {
            "policy": "v6_watchlist_match",
            "watchlist_id": entry["id"],
            "indicator_type": entry["indicator_type"],
            "indicator_value": entry["value"],
            "detail": match_detail,
            "matched_event_ids": [event_id],
        }
        cursor = connection.execute(
            """INSERT INTO alerts
               (alert_id, workspace_id, training_run_id, rule_id, rule_version, reason, evidence, severity,
                confidence, detected_at, status, mitre_technique_ids, dedup_key, trace)
               VALUES (?, ?, ?, ?, 1, ?, ?, ?, 0.95, ?, 'untriaged', '[]', ?, ?)""",
            (
                alert_pub_id,
                ws_id,
                row["training_run_id"],
                rule_id,
                reason[:500],
                json.dumps({"event_ids": [event_id], "watchlist_id": entry["id"]}, separators=(",", ":")),
                sev,
                now,
                dedup_key,
                json.dumps(trace, ensure_ascii=False, separators=(",", ":")),
            ),
        )
        alert_id = inserted_id(cursor)
        if owner_case_id is not None:
            connection.execute("UPDATE alerts SET owner_case_id = ? WHERE id = ?", (owner_case_id, alert_id))
        connection.execute("INSERT OR IGNORE INTO alert_events (alert_id, event_id) VALUES (?, ?)", (alert_id, event_id))
        connection.execute(
            "UPDATE watchlist_entries SET hits_count = hits_count + 1, last_hit_at = ?, last_hit_case_id = COALESCE(?, last_hit_case_id), updated_at = ? WHERE id = ?",
            (now, owner_case_id, now, entry["id"]),
        )
        created_alert_ids.append(alert_id)

    return created_alert_ids


@watchlist_api.get("/api/watchlist")
@require_permission("cases.read")
def list_watchlist():
    kind_filter = (request.args.get("type") or "").strip().lower()
    query = (request.args.get("q") or "").strip().lower()
    active_only = request.args.get("active_only") == "1"

    sql = "SELECT * FROM watchlist_entries WHERE workspace_id = ?"
    params: list[Any] = [workspace_id()]
    if kind_filter:
        if kind_filter not in INDICATOR_TYPES:
            return error_response("INVALID_INDICATOR_TYPE", "نوع المؤشر غير مدعوم", 422)
        sql += " AND indicator_type = ?"
        params.append(kind_filter)
    if active_only:
        sql += " AND is_active = 1"
    if query:
        sql += " AND (LOWER(value) LIKE ? OR LOWER(note) LIKE ?)"
        params.extend([f"%{query}%", f"%{query}%"])
    sql += " ORDER BY is_active DESC, hits_count DESC, id DESC LIMIT 500"
    rows = get_db().execute(sql, params).fetchall()
    return jsonify({"items": [_entry_view(row) for row in rows], "total": len(rows)})


@watchlist_api.post("/api/watchlist")
@require_permission("cases.update")
def create_watchlist_entry():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return error_response("INVALID_JSON", "يلزم إرسال كائن JSON صالح", 400)
    try:
        kind = str(body.get("indicator_type") or body.get("type") or "").strip().lower()
        normalized_val = normalize_watchlist_indicator(kind, str(body.get("value") or ""))
    except ValueError as exc:
        return error_response("INVALID_WATCHLIST_INDICATOR", str(exc), 422)

    severity = str(body.get("severity") or "high").strip().lower()
    if severity not in SEVERITIES:
        return error_response("INVALID_SEVERITY", "درجة الخطورة غير صالحة", 422)
    note = str(body.get("note") or "").strip()
    if len(note) > 500:
        return error_response("INVALID_NOTE", "الملاحظة تتجاوز 500 محرف", 422)
    source_case_id = body.get("source_case_id")
    if source_case_id is not None:
        from .cases import _case_row

        if type(source_case_id) is not int or not _case_row(source_case_id):
            return error_response("CASE_NOT_FOUND", "القضية المرجعية غير متاحة", 404)

    now = iso_now()
    ws_id = workspace_id()
    with transaction():
        existing = (
            get_db()
            .execute(
                "SELECT * FROM watchlist_entries WHERE workspace_id = ? AND indicator_type = ? AND value = ?",
                (ws_id, kind, normalized_val),
            )
            .fetchone()
        )
        if existing:
            get_db().execute(
                "UPDATE watchlist_entries SET is_active = 1, severity = ?, note = COALESCE(NULLIF(?, ''), note), updated_at = ? WHERE id = ?",
                (severity, note, now, existing["id"]),
            )
            updated = get_db().execute("SELECT * FROM watchlist_entries WHERE id = ?", (existing["id"],)).fetchone()
            return jsonify({**_entry_view(updated), "duplicate": True}), 200
        cursor = get_db().execute(
            """INSERT INTO watchlist_entries
               (workspace_id, indicator_type, value, severity, note, source_case_id, is_active, hits_count, created_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, 1, 0, ?, ?, ?)""",
            (ws_id, kind, normalized_val, severity, note, source_case_id, actor_id(), now, now),
        )
        entry_id = inserted_id(cursor)
        record_audit(get_db(), "create", "watchlist", entry_id, details={"type": kind, "value": normalized_val, "severity": severity})
    row = get_db().execute("SELECT * FROM watchlist_entries WHERE id = ?", (entry_id,)).fetchone()
    return jsonify(_entry_view(row)), 201


@watchlist_api.patch("/api/watchlist/<int:entry_id>")
@require_permission("cases.update")
def update_watchlist_entry(entry_id: int):
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return error_response("INVALID_JSON", "يلزم إرسال كائن JSON صالح", 400)
    row = get_db().execute("SELECT * FROM watchlist_entries WHERE id = ? AND workspace_id = ?", (entry_id, workspace_id())).fetchone()
    if not row:
        return error_response("WATCHLIST_NOT_FOUND", "عنصر قائمة المراقبة غير موجود", 404)

    is_active = int(row["is_active"])
    if "is_active" in body:
        if not isinstance(body["is_active"], bool):
            return error_response("INVALID_STATE", "is_active يجب أن تكون قيمة منطقية", 422)
        is_active = 1 if body["is_active"] else 0
    severity = str(body.get("severity", row["severity"])).strip().lower()
    if severity not in SEVERITIES:
        return error_response("INVALID_SEVERITY", "درجة الخطورة غير صالحة", 422)
    note = str(body.get("note", row["note"])).strip()
    if len(note) > 500:
        return error_response("INVALID_NOTE", "الملاحظة تتجاوز 500 محرف", 422)

    with transaction():
        get_db().execute(
            "UPDATE watchlist_entries SET is_active = ?, severity = ?, note = ?, updated_at = ? WHERE id = ?",
            (is_active, severity, note, iso_now(), entry_id),
        )
        record_audit(get_db(), "update", "watchlist", entry_id, details={"is_active": bool(is_active), "severity": severity})
    updated = get_db().execute("SELECT * FROM watchlist_entries WHERE id = ?", (entry_id,)).fetchone()
    return jsonify(_entry_view(updated)), 200


@watchlist_api.delete("/api/watchlist/<int:entry_id>")
@require_permission("cases.update")
def delete_watchlist_entry(entry_id: int):
    row = get_db().execute("SELECT * FROM watchlist_entries WHERE id = ? AND workspace_id = ?", (entry_id, workspace_id())).fetchone()
    if not row:
        return error_response("WATCHLIST_NOT_FOUND", "عنصر قائمة المراقبة غير موجود", 404)
    with transaction():
        get_db().execute("DELETE FROM watchlist_entries WHERE id = ?", (entry_id,))
        record_audit(get_db(), "delete", "watchlist", entry_id, details={"type": row["indicator_type"], "value": row["value"]})
    return jsonify({"deleted": True, "id": entry_id}), 200


@watchlist_api.post("/api/cases/<int:case_id>/watchlist-scan")
@require_permission("cases.update")
def scan_case_against_watchlist(case_id: int):
    from .autopsy_domain import custody, touch_case
    from .cases import _case_row

    case = _case_row(case_id)
    if not case:
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    if case["status"] == "closed":
        return error_response("CASE_CLOSED", "القضية مغلقة", 409)

    events = (
        get_db()
        .execute(
            "SELECT id FROM security_events WHERE workspace_id = ? AND owner_case_id = ? AND autopsy_active = 1 AND source != 'rules_engine' ORDER BY id LIMIT 5000",
            (workspace_id(), case_id),
        )
        .fetchall()
    )
    matches: list[dict[str, Any]] = []
    alerts_created = 0
    now = iso_now()
    user_id = actor_id()

    with transaction():
        for ev in events:
            new_alert_ids = evaluate_watchlist_for_event(get_db(), int(ev["id"]))
            for alert_id in new_alert_ids:
                alert = get_db().execute("SELECT reason, dedup_key, evidence, trace FROM alerts WHERE id = ?", (alert_id,)).fetchone()
                if not alert:
                    continue
                get_db().execute(
                    "INSERT OR IGNORE INTO case_alerts(case_id, alert_id, attached_by, attached_at) VALUES (?, ?, ?, ?)",
                    (case_id, alert_id, user_id, now),
                )
                get_db().execute(
                    "INSERT OR IGNORE INTO case_evidence(case_id, evidence_type, reference_id, title, sha256, provenance, added_by, added_at) VALUES (?, 'alert', ?, ?, ?, ?, ?, ?)",
                    (case_id, str(alert_id), alert["reason"][:255], alert["dedup_key"], alert["evidence"], user_id, now),
                )
                trace_obj = json.loads(alert["trace"])
                matches.append(
                    {
                        "alert_id": alert_id,
                        "event_id": int(ev["id"]),
                        "watchlist_id": trace_obj.get("watchlist_id"),
                        "indicator_type": trace_obj.get("indicator_type"),
                        "value": trace_obj.get("indicator_value"),
                        "reason": alert["reason"],
                    }
                )
                alerts_created += 1
        if alerts_created:
            custody(case_id, "watchlist_retroactive_scan", {"events_scanned": len(events), "alerts_created": alerts_created})
            touch_case(case_id)

    return jsonify({"case_id": case_id, "events_scanned": len(events), "alerts_created": alerts_created, "matches": matches}), 200
