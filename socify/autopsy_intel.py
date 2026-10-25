import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime

from flask import Blueprint, jsonify, request

from .autopsy_api import insert_record
from .autopsy_domain import canonical, custody, normalize_indicator, text_value
from .cases import _case_row
from .db import get_db, inserted_id, transaction
from .security import actor_id, error_response, require_permission, workspace_id
from .timeutils import iso_now, iso_timestamp, parse_timestamp, utc_now

autopsy_intel_api = Blueprint("autopsy_intel", __name__)
VERDICTS = {"unknown": 0, "benign": 1, "suspicious": 2, "malicious": 3}
SCHEMA = """
CREATE TABLE IF NOT EXISTS autopsy_intel_entries (
 id INTEGER PRIMARY KEY, bundle_id INTEGER NOT NULL REFERENCES autopsy_intel_bundles(id),
 type TEXT NOT NULL, value TEXT NOT NULL, verdict TEXT NOT NULL, confidence INTEGER NOT NULL,
 country TEXT, asn INTEGER, notes TEXT NOT NULL, valid_from TEXT, valid_until TEXT, UNIQUE(bundle_id,type,value)
);
CREATE INDEX IF NOT EXISTS idx_local_intel_lookup ON autopsy_intel_entries(type,value,bundle_id);
CREATE TABLE IF NOT EXISTS autopsy_intel_activation (
 workspace_id INTEGER NOT NULL, name TEXT NOT NULL, bundle_id INTEGER NOT NULL REFERENCES autopsy_intel_bundles(id),
 activated_by INTEGER NOT NULL, activated_at TEXT NOT NULL, PRIMARY KEY(workspace_id,name)
);
CREATE TABLE IF NOT EXISTS autopsy_observables (
 id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES incident_cases(id), type TEXT NOT NULL,
 value TEXT NOT NULL, occurrences INTEGER NOT NULL DEFAULT 0, first_event_id INTEGER NOT NULL,
 enrichment TEXT NOT NULL CHECK(json_valid(enrichment)), UNIQUE(case_id,type,value)
);
CREATE TABLE IF NOT EXISTS autopsy_observable_links (
 observable_id INTEGER NOT NULL REFERENCES autopsy_observables(id), event_id INTEGER NOT NULL REFERENCES security_events(id),
 PRIMARY KEY(observable_id,event_id)
);
"""


def migrate(connection):
    for statement in SCHEMA.split(";"):
        if statement.strip():
            connection.execute(statement)
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(autopsy_intel_entries)")}
    for column in ("valid_from", "valid_until"):
        if column not in columns:
            connection.execute(f"ALTER TABLE autopsy_intel_entries ADD COLUMN {column} TEXT")
    for table in ("autopsy_intel_bundles", "autopsy_intel_entries"):
        for action in ("UPDATE", "DELETE"):
            connection.execute(
                f"CREATE TRIGGER IF NOT EXISTS {table}_immutable_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT, 'local intelligence snapshots are immutable'); END"
            )


def normalize_entry(item):
    if not isinstance(item, dict) or set(item) - {"type", "value", "verdict", "confidence", "country", "asn", "notes", "valid_from", "valid_until"}:
        raise ValueError("حقول مؤشر الحزمة غير معروفة")
    kind = text_value(item.get("type"), 20, True)
    if kind not in {"ip", "cidr", "domain", "url", "md5", "sha1", "sha256"}:
        raise ValueError("نوع مؤشر غير مدعوم")
    raw = text_value(item.get("value"), 2048, True)
    value = str(ipaddress.ip_network(raw, strict=False)) if kind == "cidr" else normalize_indicator(kind, raw)
    verdict = text_value(item.get("verdict", "unknown"), 20, True)
    confidence = item.get("confidence", 50)
    country, asn = item.get("country"), item.get("asn")
    if verdict not in VERDICTS or type(confidence) is not int or not 0 <= confidence <= 100:
        raise ValueError("الحكم أو الثقة غير صالح")
    if country is not None and (not isinstance(country, str) or not re.fullmatch(r"[A-Z]{2}", country)):
        raise ValueError("الدولة تتطلب رمزًا من حرفين كبيرين")
    if asn is not None and (type(asn) is not int or not 1 <= asn <= 2**32 - 1):
        raise ValueError("ASN خارج النطاق")
    times = {}
    for field in ("valid_from", "valid_until"):
        value_at = item.get(field)
        if value_at is not None and (not isinstance(value_at, str) or not re.search(r"(?:Z|[+-]\d{2}:\d{2})$", value_at)):
            raise ValueError("صلاحية المؤشر تتطلب وقتًا بمنطقة زمنية صريحة")
        times[field] = iso_timestamp(value_at) if value_at is not None else None
    if times["valid_from"] and times["valid_until"] and times["valid_from"] >= times["valid_until"]:
        raise ValueError("نهاية صلاحية المؤشر تسبق بدايتها")
    return {
        "type": kind,
        "value": value,
        "verdict": verdict,
        "confidence": confidence,
        "country": country,
        "asn": asn,
        "notes": text_value(item.get("notes", ""), 1000),
        **times,
    }


def convert_intelligence(content, format_name):
    if format_name in {"flat", "geoip"}:
        entries = content
    elif format_name == "stix21":
        if not isinstance(content, dict) or content.get("type") != "bundle" or not isinstance(content.get("objects"), list) or len(content["objects"]) > 10000:
            raise ValueError("يتطلب STIX حزمة objects")
        entries = []
        mapping = {"ipv4-addr": "ip", "ipv6-addr": "ip", "domain-name": "domain", "url": "url"}
        for obj in content["objects"]:
            if not isinstance(obj, dict):
                raise ValueError("كائن STIX غير صالح")
            if obj.get("type") in {"identity", "marking-definition"}:
                continue
            if obj.get("revoked") is True:
                continue
            if obj.get("type") == "indicator":
                pattern = obj.get("pattern")
                match = re.fullmatch(r"\[(ipv4-addr|ipv6-addr|domain-name|url):value = '([^'\\]+)'\]", pattern) if isinstance(pattern, str) else None
                if obj.get("pattern_type") != "stix" or not match:
                    raise ValueError("يدعم مستورد STIX مساواة قيمة مفردة فقط؛ الشرط غير المدعوم لم يُتجاهل")
                entries.append(
                    {
                        "type": mapping[match[1]],
                        "value": match[2],
                        "verdict": "suspicious",
                        "confidence": obj.get("confidence", 50),
                        "notes": obj.get("description", ""),
                        "valid_from": obj.get("valid_from"),
                        "valid_until": obj.get("valid_until"),
                    }
                )
            elif obj.get("type") in mapping:
                entries.append(
                    {"type": mapping[obj["type"]], "value": obj.get("value"), "notes": "Imported STIX observable; not an independent malicious verdict"}
                )
            elif obj.get("type") == "file" and isinstance(obj.get("hashes"), dict):
                for name, value in obj["hashes"].items():
                    kind = {"SHA-256": "sha256", "SHA-1": "sha1", "MD5": "md5"}.get(name)
                    if not kind:
                        raise ValueError("خوارزمية STIX غير مدعومة")
                    entries.append({"type": kind, "value": value})
            else:
                raise ValueError("نوع STIX خارج نطاق المستورد المعلن")
    elif format_name == "misp":
        event = content.get("Event") if isinstance(content, dict) else None
        attributes = event.get("Attribute") if isinstance(event, dict) else None
        if not isinstance(attributes, list) or len(attributes) > 10000:
            raise ValueError("استخدم export لحدث MISP يحتوي Attribute")
        entries = []
        for item in attributes:
            if not isinstance(item, dict):
                raise ValueError("MISP attribute غير صالح")
            kind = {
                "ip-src": "ip",
                "ip-dst": "ip",
                "domain": "domain",
                "hostname": "domain",
                "url": "url",
                "md5": "md5",
                "sha1": "sha1",
                "sha256": "sha256",
            }.get(text_value(item.get("type"), 100, True))
            if not kind or type(item.get("to_ids", False)) is not bool:
                raise ValueError("نوع MISP attribute أو to_ids غير مدعوم")
            entries.append(
                {"type": kind, "value": item.get("value"), "verdict": "suspicious" if item.get("to_ids") else "unknown", "notes": item.get("comment", "")}
            )
    else:
        raise ValueError("الصيغة غير مدعومة؛ لا يوجد جلب شبكة")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 10000:
        raise ValueError("الحزمة تتطلب من 1 إلى 10,000 مؤشر")
    result = [normalize_entry(item) for item in entries]
    if len({(item["type"], item["value"]) for item in result}) != len(result):
        raise ValueError("الحزمة تحتوي مؤشرات متكررة")
    if format_name == "geoip" and any(item["type"] != "cidr" or not (item["country"] or item["asn"]) for item in result):
        raise ValueError("GeoIP المحلي يتطلب شبكات CIDR ودولة أو ASN")
    return result


@autopsy_intel_api.get("/api/autopsy/intelligence")
@require_permission("cases.read")
def list_bundles():
    rows = (
        get_db()
        .execute(
            "SELECT b.id,b.name,b.version,b.source,b.license,b.expires_at,b.sha256,b.created_at, a.bundle_id = b.id AS active, (SELECT COUNT(*) FROM autopsy_intel_entries e WHERE e.bundle_id=b.id) AS entries FROM autopsy_intel_bundles b LEFT JOIN autopsy_intel_activation a ON a.workspace_id=b.workspace_id AND a.name=b.name WHERE b.workspace_id=? ORDER BY b.id DESC LIMIT 200",
            (workspace_id(),),
        )
        .fetchall()
    )
    return jsonify(
        {
            "items": [dict(row) for row in rows],
            "formats": ["flat", "stix21", "misp", "geoip"],
            "network": "offline-only",
            "geoip_format": "licensed CIDR JSON snapshot; no database or feed bundled",
        }
    )


@autopsy_intel_api.post("/api/autopsy/intelligence")
@require_permission("intel.manage")
def import_bundle():
    data = request.get_json(silent=True)
    try:
        if not isinstance(data, dict) or set(data) != {"name", "version", "source", "license", "expires_at", "format", "content"}:
            raise ValueError("حدد الاسم والإصدار والمصدر والرخصة والصلاحية والصيغة والمحتوى المحلي")
        name, version = text_value(data["name"], 160, True), text_value(data["version"], 80, True)
        source, license_name = text_value(data["source"], 500, True), text_value(data["license"], 500, True)
        if not isinstance(data["expires_at"], str) or not re.search(r"(?:Z|[+-]\d{2}:\d{2})$", data["expires_at"]):
            raise ValueError("أدخل صلاحية بمنطقة زمنية صريحة")
        expires = iso_timestamp(data["expires_at"])
        if parse_timestamp(expires) <= datetime.now(UTC):
            raise ValueError("لا يمكن استيراد حزمة منتهية")
        payload = canonical({"format": data["format"], "content": data["content"]})
        if len(payload.encode()) > 2 * 1024 * 1024:
            raise ValueError("الحزمة تتجاوز 2 MiB")
        entries = convert_intelligence(data["content"], data["format"])
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        return error_response("INVALID_LOCAL_INTELLIGENCE", str(exc), 422)
    with transaction():
        duplicate = (
            get_db().execute("SELECT id FROM autopsy_intel_bundles WHERE workspace_id=? AND name=? AND version=?", (workspace_id(), name, version)).fetchone()
        )
        if duplicate:
            return error_response("INTELLIGENCE_VERSION_EXISTS", "الإصدار محفوظ؛ استورد إصدارًا جديدًا بدل تغييره", 409)
        digest = hashlib.sha256(payload.encode()).hexdigest()
        identifier = inserted_id(
            get_db().execute(
                "INSERT INTO autopsy_intel_bundles(workspace_id,name,version,source,license,expires_at,payload,sha256,created_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (workspace_id(), name, version, source, license_name, expires, payload, digest, actor_id(), iso_now()),
            )
        )
        get_db().executemany(
            "INSERT INTO autopsy_intel_entries(bundle_id,type,value,verdict,confidence,country,asn,notes,valid_from,valid_until) VALUES (?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    identifier,
                    item["type"],
                    item["value"],
                    item["verdict"],
                    item["confidence"],
                    item["country"],
                    item["asn"],
                    item["notes"],
                    item["valid_from"],
                    item["valid_until"],
                )
                for item in entries
            ],
        )
    return jsonify({"id": identifier, "sha256": digest, "entries": len(entries), "state": "inactive"}), 201


@autopsy_intel_api.post("/api/autopsy/intelligence/<int:bundle_id>/activate")
@require_permission("intel.manage")
def activate_bundle(bundle_id):
    from .audit import record_audit

    with transaction():
        row = get_db().execute("SELECT * FROM autopsy_intel_bundles WHERE id=? AND workspace_id=?", (bundle_id, workspace_id())).fetchone()
        if not row:
            return error_response("INTELLIGENCE_NOT_FOUND", "الحزمة غير متاحة", 404)
        if parse_timestamp(row["expires_at"]) <= utc_now() or hashlib.sha256(row["payload"].encode()).hexdigest() != row["sha256"]:
            return error_response("INTELLIGENCE_INTEGRITY_OR_EXPIRY", "الحزمة منتهية أو بصمتها غير مطابقة", 409)
        get_db().execute(
            "INSERT INTO autopsy_intel_activation(workspace_id,name,bundle_id,activated_by,activated_at) VALUES (?,?,?,?,?) ON CONFLICT(workspace_id,name) DO UPDATE SET bundle_id=excluded.bundle_id,activated_by=excluded.activated_by,activated_at=excluded.activated_at",
            (workspace_id(), row["name"], bundle_id, actor_id(), iso_now()),
        )
        record_audit(get_db(), "activate", "local_intelligence", bundle_id, details={"sha256": row["sha256"], "version": row["version"]})
    return jsonify({"id": bundle_id, "active": True})


def intelligence_configuration(workspace):
    rows = (
        get_db()
        .execute(
            "SELECT b.id,b.sha256,b.expires_at FROM autopsy_intel_activation a JOIN autopsy_intel_bundles b ON b.id=a.bundle_id WHERE a.workspace_id=? AND julianday(b.expires_at)>julianday(?) ORDER BY b.id",
            (workspace, iso_now()),
        )
        .fetchall()
    )
    return hashlib.sha256(canonical([dict(row) for row in rows]).encode()).hexdigest()


def lookup_local(workspace, kind, raw, configuration=None):
    value = normalize_indicator(kind, raw)
    candidates = [(kind, value)]
    if kind == "ip":
        address = ipaddress.ip_address(value)
        candidates.extend(("cidr", str(ipaddress.ip_network(f"{value}/{prefix}", strict=False))) for prefix in range(address.max_prefixlen, -1, -1))
    placeholders = ",".join("(?,?)" for _ in candidates)
    args = [part for candidate in candidates for part in candidate]
    rows = (
        get_db()
        .execute(
            f"SELECT e.*,b.name,b.version,b.source,b.license,b.expires_at,b.sha256 FROM autopsy_intel_entries e JOIN autopsy_intel_bundles b ON b.id=e.bundle_id JOIN autopsy_intel_activation a ON a.bundle_id=b.id WHERE b.workspace_id=? AND julianday(b.expires_at)>julianday(?) AND (e.valid_from IS NULL OR julianday(e.valid_from)<=julianday(?)) AND (e.valid_until IS NULL OR julianday(e.valid_until)>julianday(?)) AND (e.type,e.value) IN ({placeholders}) ORDER BY CASE e.verdict WHEN 'malicious' THEN 3 WHEN 'suspicious' THEN 2 WHEN 'benign' THEN 1 ELSE 0 END DESC,e.confidence DESC,e.id DESC LIMIT 101",
            (workspace, iso_now(), iso_now(), iso_now(), *args),
        )
        .fetchall()
    )
    active = (
        get_db()
        .execute(
            "SELECT COUNT(*) FROM autopsy_intel_activation a JOIN autopsy_intel_bundles b ON b.id=a.bundle_id WHERE a.workspace_id=? AND julianday(b.expires_at)>julianday(?)",
            (workspace, iso_now()),
        )
        .fetchone()[0]
    )
    now = utc_now()
    validity = get_db().execute(
        f"SELECT e.valid_from,e.valid_until,b.expires_at FROM autopsy_intel_entries e JOIN autopsy_intel_bundles b ON b.id=e.bundle_id JOIN autopsy_intel_activation a ON a.bundle_id=b.id WHERE b.workspace_id=? AND julianday(b.expires_at)>julianday(?) AND (e.type,e.value) IN ({placeholders})",
        (workspace, iso_now(), *args),
    )
    changes = [parse_timestamp(value) for row in validity for value in row if value is not None and parse_timestamp(value) > now]
    refresh = min(changes).isoformat().replace("+00:00", "Z") if changes else None
    matches = [dict(row) for row in rows[:100]]
    best = max(matches, key=lambda item: (VERDICTS[item["verdict"]], item["confidence"]), default=None)
    return {
        "type": kind,
        "value": value,
        "status": "matched" if matches else "no_match" if active else "not_configured",
        "verdict": best["verdict"] if best else "unknown",
        "confidence": best["confidence"] if best else None,
        "matches": matches,
        "matches_truncated": len(rows) > 100,
        "refresh_after": refresh,
        "checked_at": iso_now(),
        "network": "offline-only",
        "configuration_sha256": configuration or intelligence_configuration(workspace),
        "limitations": "غياب نتيجة أو انتهاء الحزمة لا يثبت سلامة المؤشر؛ الثقة والموقع من المصدر المحلي المعلن",
    }


def enrich_imported_event(job, event_id):
    row = get_db().execute("SELECT source_ip,destination_ip,hostname,file_hash FROM security_events WHERE id=?", (event_id,)).fetchone()
    if not row:
        return
    configuration = intelligence_configuration(job["workspace_id"])
    values = [("ip", row["source_ip"]), ("ip", row["destination_ip"]), ("domain", row["hostname"])]
    if row["file_hash"] and re.fullmatch(r"[0-9a-fA-F]{64}", row["file_hash"]):
        values.append(("sha256", row["file_hash"]))
    for kind, raw in values:
        if not raw:
            continue
        try:
            value = normalize_indicator(kind, raw)
        except (ValueError, UnicodeError):
            continue
        existing = (
            get_db().execute("SELECT id,enrichment FROM autopsy_observables WHERE case_id=? AND type=? AND value=?", (job["case_id"], kind, value)).fetchone()
        )
        if existing:
            identifier = existing["id"]
            cached = json.loads(existing["enrichment"])
            if cached.get("configuration_sha256") != configuration or cached.get("refresh_after") and parse_timestamp(cached["refresh_after"]) <= utc_now():
                result = lookup_local(job["workspace_id"], kind, value, configuration)
                get_db().execute("UPDATE autopsy_observables SET enrichment=? WHERE id=?", (canonical(result), identifier))
        else:
            result = lookup_local(job["workspace_id"], kind, value, configuration)
            identifier = inserted_id(
                get_db().execute(
                    "INSERT INTO autopsy_observables(case_id,type,value,first_event_id,enrichment) VALUES (?,?,?,?,?)",
                    (job["case_id"], kind, value, event_id, canonical(result)),
                )
            )
        inserted = get_db().execute("INSERT OR IGNORE INTO autopsy_observable_links(observable_id,event_id) VALUES (?,?)", (identifier, event_id))
        if inserted.rowcount:
            get_db().execute("UPDATE autopsy_observables SET occurrences=occurrences+1 WHERE id=?", (identifier,))


@autopsy_intel_api.get("/api/cases/<int:case_id>/observables")
@require_permission("cases.read")
def case_observables(case_id):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    from .autopsy_pipeline import case_full_access

    if not case_full_access(case_id):
        return error_response("FULL_CASE_ACCESS_REQUIRED", "تجميع المؤشرات يتطلب نطاق القضية الكامل", 403)
    try:
        page = int(request.args.get("page", 1))
        if not 1 <= page <= 1000000:
            raise ValueError
    except ValueError:
        return error_response("INVALID_PAGE", "الصفحة غير صالحة", 422)
    active = "EXISTS (SELECT 1 FROM autopsy_observable_links l JOIN security_events e ON e.id=l.event_id WHERE l.observable_id=o.id AND e.autopsy_active=1)"
    rows = (
        get_db()
        .execute(
            f"SELECT o.*, (SELECT COUNT(*) FROM autopsy_observable_links l JOIN security_events e ON e.id=l.event_id WHERE l.observable_id=o.id AND e.autopsy_active=1) AS active_occurrences FROM autopsy_observables o WHERE o.case_id=? AND {active} ORDER BY o.id LIMIT 100 OFFSET ?",
            (case_id, (page - 1) * 100),
        )
        .fetchall()
    )
    return jsonify(
        {
            "items": [
                {
                    **dict(row),
                    "historical_occurrences": row["occurrences"],
                    "occurrences": row["active_occurrences"],
                    "enrichment": json.loads(row["enrichment"]),
                }
                for row in rows
            ],
            "page": page,
            "limit": 100,
            "total": get_db().execute(f"SELECT COUNT(*) FROM autopsy_observables o WHERE o.case_id=? AND {active}", (case_id,)).fetchone()[0],
        }
    )


@autopsy_intel_api.post("/api/cases/<int:case_id>/observables/<int:observable_id>/enrich")
@require_permission("cases.update")
def enrich_observable(case_id, observable_id):
    case = _case_row(case_id)
    if not case:
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    if case["status"] == "closed":
        return error_response("CASE_CLOSED", "أعد فتح القضية قبل إضافة تحليل جديد", 409)
    from .autopsy_pipeline import case_full_access

    if not case_full_access(case_id):
        return error_response("FULL_CASE_ACCESS_REQUIRED", "يلزم نطاق القضية الكامل", 403)
    with transaction():
        row = get_db().execute("SELECT * FROM autopsy_observables WHERE case_id=? AND id=?", (case_id, observable_id)).fetchone()
        if not row:
            return error_response("OBSERVABLE_NOT_FOUND", "المؤشر المرصود غير متاح", 404)
        result = lookup_local(workspace_id(), row["type"], row["value"])
        get_db().execute("UPDATE autopsy_observables SET enrichment=? WHERE id=?", (canonical(result), observable_id))
        identifier = insert_record(case_id, "analysis", {"analysis_type": "local_intelligence", "observable_id": observable_id, **result})
        custody(case_id, "observable_enriched_locally", {"observable_id": observable_id, "record_id": identifier})
    return jsonify({"id": identifier, "payload": result})
