"""Alert intake: alerts from a SIEM or EDR arrive in a triage queue before they become cases.

An integration (Wazuh, Elastic, Splunk, Microsoft Sentinel or the generic schema) has its own endpoint,
POST /api/intake/<id>/alerts, authenticated by an API token with the intake:write scope or by an HMAC signature over
"<timestamp>.<body>". Each alert is normalised by its adapter, de-duplicated (the same source id, or the same content,
within SOCIFY_INTAKE_GROUP_SECONDS counts as another occurrence of one alert) and stored with its raw payload encrypted.
Analysts with intake.read see the queue; intake.triage lets them create a case from an alert (the raw alert becomes
evidence with its hash and custody entry, its entities become assets and indicators, and the case's detection time is
the alert's first-seen time), link it to an existing case, or dismiss it with a reason.
"""

import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from datetime import timedelta
from typing import Any

from flask import Blueprint, current_app, g, jsonify, request

from ..api_tokens import accepts_token
from ..audit import record_audit
from ..db import get_db, inserted_id, transaction
from ..security import current_user, decrypt_secret, encrypt_secret, error_response, has_permission, require_permission
from ..timeutils import iso_now, parse_timestamp, utc_now
from ..validation import ValidationError, public_error_message
from . import elastic, generic, sentinel, splunk, wazuh
from .common import SEVERITIES, text

intake_api = Blueprint("intake", __name__)

ADAPTERS = {"wazuh": wazuh, "elastic": elastic, "splunk": splunk, "sentinel": sentinel, "generic": generic}
STATUSES = ("new", "triaging", "linked", "dismissed")
MAX_BODY = 1024 * 1024
MAX_BATCH = 100
SIGNATURE_SKEW_SECONDS = 300
MANAGER_ROLES = {"soc_manager", "admin"}
CASE_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "low"}
HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS intake_integrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    kind TEXT NOT NULL CHECK (kind IN ('wazuh', 'elastic', 'splunk', 'sentinel', 'generic')),
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    auth_mode TEXT NOT NULL CHECK (auth_mode IN ('token', 'hmac')),
    hmac_secret_ciphertext TEXT,
    auto_case_rules TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(auto_case_rules)),
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS intake_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    integration_id INTEGER NOT NULL REFERENCES intake_integrations(id),
    external_id TEXT,
    dedup_key TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status TEXT NOT NULL CHECK (status IN ('new', 'triaging', 'linked', 'dismissed')),
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    normalized TEXT NOT NULL CHECK (json_valid(normalized)),
    raw_ciphertext TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    case_id INTEGER REFERENCES incident_cases(id),
    dismissed_reason TEXT,
    claimed_by INTEGER REFERENCES users(id),
    claimed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_intake_alerts_queue ON intake_alerts(workspace_id, status, id);
CREATE INDEX IF NOT EXISTS idx_intake_alerts_dedup ON intake_alerts(integration_id, dedup_key, last_seen);
CREATE TABLE IF NOT EXISTS intake_replay (
    integration_id INTEGER NOT NULL,
    digest TEXT NOT NULL,
    seen_at TEXT NOT NULL,
    PRIMARY KEY (integration_id, digest)
);
"""


def migrate(connection: sqlite3.Connection) -> None:
    for statement in SCHEMA.split(";"):
        if statement.strip():
            connection.execute(statement)
    # Added after the first 1.1 build: who claimed an alert for triage.
    columns = {row[1] for row in connection.execute("PRAGMA table_info(intake_alerts)")}
    for name, definition in (("claimed_by", "INTEGER REFERENCES users(id)"), ("claimed_at", "TEXT")):
        if name not in columns:
            connection.execute(f"ALTER TABLE intake_alerts ADD COLUMN {name} {definition}")


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _stamp(moment) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def _rank(severity: str) -> int:
    return len(SEVERITIES) - SEVERITIES.index(severity) if severity in SEVERITIES else 0


# Integrations -----------------------------------------------------------------------------------------------------


def _manager() -> dict[str, Any] | None:
    user = current_user()
    if user is None or user.get("role") not in MANAGER_ROLES or getattr(g, "api_token_id", None) is not None:
        return None
    return user


def _rules(value: object, workspace: int) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict) or set(value) - {"min_severity", "assignee"}:
        raise ValidationError("قواعد الإنشاء التلقائي تقبل الحد الأدنى للخطورة والمسؤول فقط")
    rules: dict[str, Any] = {}
    if value.get("min_severity") is not None:
        if value["min_severity"] not in SEVERITIES:
            raise ValidationError("درجة الخطورة غير معروفة")
        rules["min_severity"] = value["min_severity"]
    if value.get("assignee") is not None:
        member = get_db().execute("SELECT 1 FROM users WHERE id = ? AND workspace_id = ? AND is_active = 1", (value["assignee"], workspace)).fetchone()
        if type(value["assignee"]) is not int or not member:
            raise ValidationError("المسؤول ليس عضوًا نشطًا في هذا الفريق")
        rules["assignee"] = value["assignee"]
    return rules


def _integration_view(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "kind": row["kind"],
        "name": row["name"],
        "enabled": bool(row["enabled"]),
        "auth_mode": row["auth_mode"],
        "auto_case": json.loads(row["auto_case_rules"]),
        "endpoint": f"/api/intake/{row['id']}/alerts",
        "created_at": row["created_at"],
    }


@intake_api.get("/api/intake/integrations")
@require_permission("intake.read")
def list_integrations():
    user = current_user() or {}
    rows = get_db().execute("SELECT * FROM intake_integrations WHERE workspace_id = ? ORDER BY id", (int(user["workspace_id"]),)).fetchall()
    return jsonify({"items": [_integration_view(row) for row in rows], "kinds": list(ADAPTERS), "can_manage": _manager() is not None})


@intake_api.post("/api/intake/integrations")
@require_permission("intake.read")
def create_integration():
    user = _manager()
    if user is None:
        return error_response("PERMISSION_DENIED", "إدارة تكاملات الاستقبال لمدير الفريق", 403)
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) - {"kind", "name", "auth_mode", "auto_case"}:
        return error_response("INVALID_INTEGRATION", "أرسل النوع والاسم وطريقة المصادقة وقواعد الإنشاء التلقائي فقط", 422)
    name = text(data.get("name"), 120)
    if data.get("kind") not in ADAPTERS or data.get("auth_mode") not in {"token", "hmac"} or not name or len(name) < 3:
        return error_response("INVALID_INTEGRATION", "اختر نوع التكامل وطريقة المصادقة واسمًا من 3 محارف على الأقل", 422)
    try:
        rules = _rules(data.get("auto_case"), int(user["workspace_id"]))
    except ValueError as error:
        return error_response("INVALID_INTEGRATION", public_error_message(error, "قواعد الإنشاء التلقائي غير صالحة"), 422)
    secret = secrets.token_urlsafe(32) if data["auth_mode"] == "hmac" else None
    with transaction():
        integration_id = inserted_id(
            get_db().execute(
                "INSERT INTO intake_integrations (workspace_id, kind, name, auth_mode, hmac_secret_ciphertext, auto_case_rules, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    int(user["workspace_id"]),
                    data["kind"],
                    name,
                    data["auth_mode"],
                    encrypt_secret(secret) if secret else None,
                    _canonical(rules),
                    user["id"],
                    iso_now(),
                ),
            )
        )
        record_audit(get_db(), "create", "intake_integration", integration_id, details={"kind": data["kind"], "auth_mode": data["auth_mode"]})
    row = get_db().execute("SELECT * FROM intake_integrations WHERE id = ?", (integration_id,)).fetchone()
    body: dict[str, Any] = {"item": _integration_view(row)}
    if secret:
        body["hmac_secret"] = secret  # shown once
    return jsonify(body), 201


@intake_api.patch("/api/intake/integrations/<int:integration_id>")
@require_permission("intake.read")
def update_integration(integration_id: int):
    user = _manager()
    if user is None:
        return error_response("PERMISSION_DENIED", "إدارة تكاملات الاستقبال لمدير الفريق", 403)
    data = request.get_json(silent=True)
    row = get_db().execute("SELECT * FROM intake_integrations WHERE id = ? AND workspace_id = ?", (integration_id, int(user["workspace_id"]))).fetchone()
    if row is None:
        return error_response("INTEGRATION_NOT_FOUND", "التكامل غير موجود", 404)
    if not isinstance(data, dict) or not data or set(data) - {"enabled", "auto_case"} or ("enabled" in data and not isinstance(data["enabled"], bool)):
        return error_response("INVALID_INTEGRATION", "أرسل enabled أو auto_case", 422)
    try:
        rules = _rules(data["auto_case"], int(user["workspace_id"])) if "auto_case" in data else json.loads(row["auto_case_rules"])
    except ValueError as error:
        return error_response("INVALID_INTEGRATION", public_error_message(error, "قواعد الإنشاء التلقائي غير صالحة"), 422)
    enabled = data.get("enabled", bool(row["enabled"]))
    with transaction():
        get_db().execute(
            "UPDATE intake_integrations SET enabled = ?, auto_case_rules = ? WHERE id = ?", (1 if enabled else 0, _canonical(rules), integration_id)
        )
        record_audit(get_db(), "update", "intake_integration", integration_id, details={"fields": sorted(data)})
    return jsonify(_integration_view(get_db().execute("SELECT * FROM intake_integrations WHERE id = ?", (integration_id,)).fetchone()))


# Receiving alerts -------------------------------------------------------------------------------------------------


def _signature_refusal(integration: sqlite3.Row, raw: bytes):
    """Check X-SOCify-Timestamp and X-SOCify-Signature; None when valid, else the refusal."""
    supplied_time = request.headers.get("X-SOCify-Timestamp", "")
    supplied = request.headers.get("X-SOCify-Signature", "")
    if integration["auth_mode"] != "hmac" or not supplied_time.isdigit() or not supplied.startswith("sha256="):
        return error_response("INTAKE_AUTHENTICATION_FAILED", "مصادقة التكامل غير صالحة", 401)
    if abs(time.time() - int(supplied_time)) > SIGNATURE_SKEW_SECONDS:
        return error_response("INTAKE_SIGNATURE_EXPIRED", "توقيت التوقيع خارج النافذة المسموحة (5 دقائق)", 401)
    expected = hmac.new(decrypt_secret(integration["hmac_secret_ciphertext"]).encode(), supplied_time.encode() + b"." + raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied[len("sha256=") :], expected):
        return error_response("INTAKE_AUTHENTICATION_FAILED", "مصادقة التكامل غير صالحة", 401)
    digest = hashlib.sha256(supplied.encode()).hexdigest()
    cutoff = _stamp(utc_now() - timedelta(seconds=2 * SIGNATURE_SKEW_SECONDS))
    get_db().execute("DELETE FROM intake_replay WHERE seen_at < ?", (cutoff,))
    try:
        get_db().execute("INSERT INTO intake_replay (integration_id, digest, seen_at) VALUES (?, ?, ?)", (integration["id"], digest, iso_now()))
    except sqlite3.IntegrityError:
        return error_response("INTAKE_REPLAYED", "هذا الطلب الموقّع وصل من قبل", 409)
    return None


def _dedup_key(integration_id: int, normalized: dict[str, Any]) -> str:
    if normalized["external_id"]:
        basis = f"{integration_id}:id:{normalized['external_id']}"
    else:
        subset = {key: normalized[key] for key in ("title", "rule_id", "severity", "entities", "time")}
        basis = f"{integration_id}:content:{_canonical(subset)}"
    return hashlib.sha256(basis.encode()).hexdigest()


def _store(integration: sqlite3.Row, item: dict[str, Any]) -> tuple[int, str]:
    normalized = ADAPTERS[integration["kind"]].normalize(item)
    now = utc_now()
    seen = normalized["time"]
    if seen is None or parse_timestamp(seen) > now + timedelta(minutes=5):
        seen = _stamp(now)
    key = _dedup_key(integration["id"], normalized)
    window = _stamp(now - timedelta(seconds=int(current_app.config.get("INTAKE_GROUP_SECONDS", 3600))))
    existing = (
        get_db()
        # Only an alert still waiting for triage absorbs repeats; after a dismissal or a case, a repeat is a new alert to look at.
        .execute(
            "SELECT id FROM intake_alerts WHERE integration_id = ? AND dedup_key = ? AND last_seen >= ? AND status IN ('new', 'triaging') ORDER BY id DESC LIMIT 1",
            (integration["id"], key, window),
        )
        .fetchone()
    )
    if existing:
        get_db().execute(
            "UPDATE intake_alerts SET occurrence_count = occurrence_count + 1, last_seen = ?, updated_at = ? WHERE id = ?",
            (_stamp(now), _stamp(now), existing["id"]),
        )
        return int(existing["id"]), "grouped"
    raw = _canonical(item)
    alert_id = inserted_id(
        get_db().execute(
            """INSERT INTO intake_alerts (workspace_id, integration_id, external_id, dedup_key, title, severity, status, first_seen, last_seen,
            normalized, raw_ciphertext, raw_sha256, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'new', ?, ?, ?, ?, ?, ?, ?)""",
            (
                integration["workspace_id"],
                integration["id"],
                normalized["external_id"],
                key,
                normalized["title"],
                normalized["severity"],
                seen,
                _stamp(now),
                _canonical(normalized),
                encrypt_secret(raw),
                hashlib.sha256(raw.encode()).hexdigest(),
                _stamp(now),
                _stamp(now),
            ),
        )
    )
    return alert_id, "created"


@intake_api.post("/api/intake/<int:integration_id>/alerts")
@accepts_token("intake:write", session=False)
def receive_alerts(integration_id: int):
    from ..auth import attempts_exhausted, record_failed_attempt

    limiter = f"intake:{integration_id}"
    if attempts_exhausted(limiter, "RATE_LIMIT_SOURCE_KEY_ATTEMPTS"):
        return error_response("INTAKE_RATE_LIMITED", "محاولات مصادقة خاطئة كثيرة لهذا التكامل. حاول لاحقًا", 429)
    integration = get_db().execute("SELECT * FROM intake_integrations WHERE id = ? AND enabled = 1", (integration_id,)).fetchone()
    raw = request.get_data(cache=True)
    if len(raw) > MAX_BODY:
        return error_response("INTAKE_TOO_LARGE", "حجم دفعة التنبيهات يتجاوز 1 MiB", 413)
    principal = getattr(g, "current_user", None) if getattr(g, "api_token_id", None) is not None else None
    if principal is not None:
        refusal = (
            None
            if integration and integration["auth_mode"] == "token" and integration["workspace_id"] == principal["workspace_id"]
            else error_response("INTEGRATION_NOT_FOUND", "التكامل غير موجود", 404)
        )
    elif integration is None:
        refusal = error_response("INTAKE_AUTHENTICATION_FAILED", "مصادقة التكامل غير صالحة", 401)
    else:
        refusal = _signature_refusal(integration, raw)
    if refusal is not None:
        record_failed_attempt(limiter)
        return refusal
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return error_response("INVALID_INTAKE_PAYLOAD", "جسم الطلب ليس JSON صالحًا", 400)
    items = ADAPTERS[integration["kind"]].items(payload)
    if not items or len(items) > MAX_BATCH or not all(isinstance(item, dict) for item in items):
        return error_response("INVALID_INTAKE_PAYLOAD", "أرسل من 1 إلى 100 تنبيه، كل تنبيه كائن JSON", 422)
    results: list[dict[str, Any]] = []
    with transaction():
        for item in items:
            alert_id, outcome = _store(integration, item)
            results.append({"id": alert_id, "status": outcome})
        record_audit(
            get_db(),
            "ingest",
            "intake_integration",
            integration_id,
            details={"created": sum(item["status"] == "created" for item in results), "grouped": sum(item["status"] == "grouped" for item in results)},
            actor=principal["id"] if principal else None,
            workspace=int(integration["workspace_id"]),
        )
    _apply_auto_case(integration, [item["id"] for item in results if item["status"] == "created"])
    _notify_severe(integration, [item["id"] for item in results if item["status"] == "created"])
    return jsonify({"accepted": len(results), "items": results}), 202


def _notify_severe(integration: sqlite3.Row, alert_ids: list[int]) -> None:
    """New high and critical alerts still in the queue reach everyone who triages incoming alerts, once each."""
    from ..notifications import notify

    if not alert_ids:
        return
    marks = ",".join("?" for _ in alert_ids)
    severe = (
        get_db()
        .execute(f"SELECT id FROM intake_alerts WHERE id IN ({marks}) AND status = 'new' AND severity IN ('critical', 'high') ORDER BY id", alert_ids)
        .fetchall()
    )
    with transaction():
        for row in severe:
            notify(
                None,
                "intake_alert",
                workspace=int(integration["workspace_id"]),
                intake_alert_id=int(row["id"]),
                permission="intake.triage",
                dedup_key=f"intake:{row['id']}",
            )


def _apply_auto_case(integration: sqlite3.Row, alert_ids: list[int]) -> None:
    rules = json.loads(integration["auto_case_rules"])
    if not rules.get("min_severity") or not alert_ids:
        return
    actor = get_db().execute("SELECT id FROM users WHERE id = ? AND is_active = 1", (integration["created_by"],)).fetchone()
    if actor is None:
        return
    for alert_id in alert_ids:
        row = get_db().execute("SELECT * FROM intake_alerts WHERE id = ?", (alert_id,)).fetchone()
        if _rank(row["severity"]) >= _rank(rules["min_severity"]):
            # The alerts are already stored and acknowledged; a rule that cannot open a case leaves the alert in the queue.
            try:
                with acting_as(int(actor["id"])):
                    created = create_case_from_alert(row, assignee=rules.get("assignee"))
                failed = (created[1] if isinstance(created, tuple) else created.status_code) != 201
            except (ValidationError, sqlite3.Error, ValueError):
                failed = True
            if failed:
                record_audit(
                    get_db(),
                    "auto_case_failed",
                    "intake_alert",
                    alert_id,
                    "failure",
                    {"integration_id": integration["id"]},
                    workspace=int(integration["workspace_id"]),
                )


class acting_as:  # noqa: N801 - used as a context manager like a function
    """Run case creation as a given member when no one is signed in (an integration acting on its rules)."""

    def __init__(self, user_id: int):
        self.user_id = user_id

    def __enter__(self):
        self.saved = getattr(g, "current_user", None)
        row = (
            get_db()
            .execute(
                "SELECT id, email, socify_user_name(name,name_ar,name_en) AS name, name AS account_name, name_ar, name_en, role, team, workspace_id, leaderboard_opt_in, is_active FROM users WHERE id = ?",
                (self.user_id,),
            )
            .fetchone()
        )
        g.current_user = dict(row)
        return self

    def __exit__(self, *_):
        if self.saved is None:
            g.pop("current_user", None)
        else:
            g.current_user = self.saved
        return False


# Triage ------------------------------------------------------------------------------------------------------------


def _alert_view(row: sqlite3.Row, *, raw: bool = False) -> dict[str, Any]:
    view = {
        "id": row["id"],
        "integration_id": row["integration_id"],
        "integration_name": row["integration_name"],
        "integration_kind": row["integration_kind"],
        "external_id": row["external_id"],
        "title": row["title"],
        "severity": row["severity"],
        "status": row["status"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "occurrence_count": row["occurrence_count"],
        "normalized": json.loads(row["normalized"]),
        "raw_sha256": row["raw_sha256"],
        "case_id": row["case_id"],
        "dismissed_reason": row["dismissed_reason"],
        "claimed_by": row["claimed_by"],
        "claimed_by_name": row["claimed_by_name"],
        "claimed_at": row["claimed_at"],
    }
    if raw:
        view["raw"] = json.loads(decrypt_secret(row["raw_ciphertext"]))
    return view


ALERT_SELECT = """SELECT a.*, i.name AS integration_name, i.kind AS integration_kind,
    socify_user_name(u.name, u.name_ar, u.name_en) AS claimed_by_name
    FROM intake_alerts a JOIN intake_integrations i ON i.id = a.integration_id LEFT JOIN users u ON u.id = a.claimed_by"""


def _alert(alert_id: int) -> sqlite3.Row | None:
    user = current_user() or {}
    return get_db().execute(f"{ALERT_SELECT} WHERE a.id = ? AND a.workspace_id = ?", (alert_id, int(user.get("workspace_id") or 0))).fetchone()


def open_count(workspace: int) -> int:
    return int(get_db().execute("SELECT COUNT(*) FROM intake_alerts WHERE workspace_id = ? AND status IN ('new', 'triaging')", (workspace,)).fetchone()[0])


@intake_api.get("/api/intake/alerts")
@require_permission("intake.read")
def list_alerts():
    user = current_user() or {}
    clauses: list[str] = ["a.workspace_id = ?"]
    values: list[Any] = [int(user["workspace_id"])]
    status = request.args.get("status", "open")
    if status == "open":
        clauses.append("a.status IN ('new', 'triaging')")
    elif status in STATUSES:
        clauses.append("a.status = ?")
        values.append(status)
    elif status != "all":
        return error_response("INVALID_INTAKE_FILTER", "مرشح الحالة غير صالح", 422)
    severity = request.args.get("severity", "")
    if severity:
        if severity not in SEVERITIES:
            return error_response("INVALID_INTAKE_FILTER", "مرشح الخطورة غير صالح", 422)
        clauses.append("a.severity = ?")
        values.append(severity)
    integration = request.args.get("integration_id", "")
    if integration:
        if not integration.isdigit():
            return error_response("INVALID_INTAKE_FILTER", "مرشح التكامل غير صالح", 422)
        clauses.append("a.integration_id = ?")
        values.append(int(integration))
    query = (request.args.get("q") or "").strip()
    if len(query) > 200:
        return error_response("INVALID_INTAKE_FILTER", "نص البحث أطول من 200 محرف", 422)
    if query:
        # Title, rule, source id and entity values, matched as plain text (LIKE wildcards in the query are escaped).
        pattern = "%" + query.replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%"
        clauses.append("(a.title LIKE ? ESCAPE '!' OR a.external_id LIKE ? ESCAPE '!' OR a.normalized LIKE ? ESCAPE '!')")
        values.extend([pattern, pattern, pattern])
    mine = request.args.get("mine", "0")
    if mine not in {"0", "1"}:
        return error_response("INVALID_INTAKE_FILTER", "مرشح المسؤول غير صالح", 422)
    if mine == "1":
        clauses.append("a.claimed_by = ?")
        values.append(int(user["id"]))
    since = request.args.get("since", "")
    if since:
        try:
            values.append(_stamp(parse_timestamp(since)))
        except ValueError:
            return error_response("INVALID_INTAKE_FILTER", "مرشح الوقت غير صالح", 422)
        clauses.append("a.last_seen >= ?")
    page = request.args.get("page", "1")
    number = int(page) if page.isdigit() and 1 <= int(page) <= 100000 else 1
    where = " AND ".join(clauses)
    total = get_db().execute(f"SELECT COUNT(*) FROM intake_alerts a WHERE {where}", values).fetchone()[0]
    rows = (
        get_db()
        .execute(
            f"{ALERT_SELECT} WHERE {where} ORDER BY a.last_seen DESC, a.id DESC LIMIT 50 OFFSET ?",
            (*values, (number - 1) * 50),
        )
        .fetchall()
    )
    return jsonify(
        {
            "items": [_alert_view(row) for row in rows],
            "total": total,
            "page": number,
            "page_size": 50,
            "open": open_count(int(user["workspace_id"])),
            "fetched_at": iso_now(),
            "can_triage": has_permission(user, "intake.triage"),
        }
    )


@intake_api.get("/api/intake/alerts/<int:alert_id>")
@require_permission("intake.read")
def alert_detail(alert_id: int):
    row = _alert(alert_id)
    if row is None:
        return error_response("INTAKE_ALERT_NOT_FOUND", "التنبيه الوارد غير موجود", 404)
    return jsonify(_alert_view(row, raw=has_permission(current_user(), "intake.triage")))


def _attach(case_id: int, row: sqlite3.Row, *, detection: bool) -> int:
    """Attach the raw alert to a case as evidence with its hash and custody entry; optionally record the detection moment."""
    from ..autopsy_api import insert_record
    from ..autopsy_domain import custody, validate_record

    raw = decrypt_secret(row["raw_ciphertext"])
    provenance = {
        "source": "intake",
        "integration_id": row["integration_id"],
        "integration_kind": row["integration_kind"],
        "intake_alert_id": row["id"],
        "content_length": len(raw.encode()),
    }
    evidence_id = inserted_id(
        get_db().execute(
            "INSERT INTO case_evidence (case_id, evidence_type, reference_id, title, sha256, provenance, added_by, added_at) VALUES (?, 'raw_log', ?, ?, ?, ?, ?, ?)",
            (
                case_id,
                f"intake-alert:{row['id']}",
                f"{row['integration_name']}: {row['title']}"[:255],
                row["raw_sha256"],
                _canonical(provenance),
                (current_user() or {})["id"],
                iso_now(),
            ),
        )
    )
    get_db().execute("INSERT INTO case_evidence_content (evidence_id, ciphertext) VALUES (?, ?)", (evidence_id, encrypt_secret(raw)))
    custody(case_id, "intake_alert_attached", {"evidence_id": evidence_id, "intake_alert_id": row["id"], "sha256": row["raw_sha256"]})
    if detection:
        normalized = json.loads(row["normalized"])
        records: list[tuple[str, dict[str, Any]]] = [
            (
                "response",
                {
                    "title": f"رصد التنبيه في {row['integration_name']}"[:255],
                    "phase": "detection",
                    "status": "succeeded",
                    "performed_by": int((current_user() or {})["id"]),
                    "performed_at": row["first_seen"],
                    "details": (normalized.get("rule_name") or row["title"])[:4000],
                    "evidence_id": evidence_id,
                },
            )
        ]
        for host in normalized["entities"]["hosts"][:20]:
            records.append(("asset", {"name": host, "type": "unknown", "role": "affected", "evidence_id": evidence_id}))
        indicators = [("ip", value) for value in normalized["entities"]["ips"]]
        indicators += [("domain", value) for value in normalized["entities"]["domains"]]
        indicators += [("url", value) for value in normalized["entities"]["urls"]]
        indicators += [(HASH_TYPES[len(value)], value) for value in normalized["entities"]["hashes"]]
        for kind, value in indicators[:50]:
            records.append(
                (
                    "indicator",
                    {"type": kind, "value": value, "classification": "observable", "source": f"intake:{row['integration_kind']}", "evidence_id": evidence_id},
                )
            )
        skipped = 0
        for kind, payload in records:
            try:
                validated = validate_record(case_id, kind, payload)
            except ValidationError:
                if kind == "response":
                    raise
                # One entity the case model refuses (an unusual host name, say) must not cost the analyst the whole case.
                skipped += 1
                continue
            insert_record(case_id, kind, validated)
        if skipped:
            custody(case_id, "intake_entities_skipped", {"intake_alert_id": row["id"], "skipped": skipped})
    return evidence_id


def create_case_from_alert(row: sqlite3.Row, *, title: str | None = None, assignee: int | None = None):
    from ..cases import _create_case

    integration = get_db().execute("SELECT name, kind FROM intake_integrations WHERE id = ?", (row["integration_id"],)).fetchone()
    data: dict[str, Any] = {
        "title": (title or row["title"])[:255],
        "reason": "alert_review",
        "objective": f"فرز التنبيه الوارد من {integration['name']} وتحديد أثره والإجراء المناسب"[:2000],
        "severity": CASE_SEVERITY[row["severity"]],
    }
    if assignee is not None:
        data["assignee"] = assignee
    detailed = get_db().execute(f"{ALERT_SELECT} WHERE a.id = ?", (row["id"],)).fetchone()

    def link(case_id: int) -> None:
        _close_alert(row["id"], "UPDATE intake_alerts SET status = 'linked', case_id = ?, updated_at = ? WHERE id = ?", (case_id, iso_now(), row["id"]))
        _attach(case_id, detailed, detection=True)
        record_audit(get_db(), "case_from_intake", "case", case_id, details={"intake_alert_id": row["id"], "integration_id": row["integration_id"]})

    try:
        response = _create_case(data, then=link)
    except AlertClosed:
        return _closed()
    body, status = (response[0], response[1]) if isinstance(response, tuple) else (response, response.status_code)
    if status != 201:
        return response
    return jsonify({"case_id": int(body.get_json()["id"]), "alert_id": row["id"]}), 201


class AlertClosed(Exception):
    """The alert was linked or dismissed by someone else after it was read; the surrounding transaction rolls back."""


def _close_alert(alert_id: int, statement: str, values: tuple[Any, ...]) -> None:
    if get_db().execute(statement + " AND status IN ('new', 'triaging')", values).rowcount != 1:
        raise AlertClosed


def _closed():
    return error_response("INTAKE_ALERT_CLOSED", "التنبيه مربوط بقضية أو مستبعد مسبقًا", 409)


def _open(alert_id: int):
    row = _alert(alert_id)
    if row is None:
        return None, error_response("INTAKE_ALERT_NOT_FOUND", "التنبيه الوارد غير موجود", 404)
    if row["status"] in {"linked", "dismissed"}:
        return None, _closed()
    return row, None


@intake_api.post("/api/intake/alerts/<int:alert_id>/case")
@require_permission("intake.triage")
def alert_to_case(alert_id: int):
    if not has_permission(current_user(), "cases.create"):
        return error_response("PERMISSION_DENIED", "ليست لديك صلاحية إنشاء قضية", 403)
    row, refusal = _open(alert_id)
    if refusal is not None:
        return refusal
    data = request.get_json(silent=True) or {}
    if (
        not isinstance(data, dict)
        or set(data) - {"title"}
        or ("title" in data and not (isinstance(data["title"], str) and 3 <= len(data["title"].strip()) <= 255))
    ):
        return error_response("INVALID_INTAKE_ACTION", "عنوان القضية من 3 إلى 255 محرفًا", 422)
    return create_case_from_alert(row, title=data.get("title"))


@intake_api.post("/api/intake/alerts/<int:alert_id>/link")
@require_permission("intake.triage")
def alert_to_existing_case(alert_id: int):
    from ..cases import _case_row

    if not has_permission(current_user(), "evidence.add"):
        return error_response("PERMISSION_DENIED", "ليست لديك صلاحية إضافة دليل", 403)
    row, refusal = _open(alert_id)
    if refusal is not None:
        return refusal
    data = request.get_json(silent=True)
    case_id = data.get("case_id") if isinstance(data, dict) else None
    case = _case_row(case_id) if type(case_id) is int and 1 <= case_id <= 9223372036854775807 else None
    if case is None:
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    if case["status"] == "closed":
        return error_response("CASE_EVIDENCE_LOCKED", "الأدلة مقفلة بعد إغلاق القضية", 409)
    try:
        with transaction():
            _close_alert(alert_id, "UPDATE intake_alerts SET status = 'linked', case_id = ?, updated_at = ? WHERE id = ?", (case_id, iso_now(), alert_id))
            evidence_id = _attach(int(case["id"]), row, detection=False)
            record_audit(get_db(), "link_intake_alert", "case", case_id, details={"intake_alert_id": alert_id, "evidence_id": evidence_id})
    except AlertClosed:
        return _closed()
    return jsonify({"case_id": case_id, "alert_id": alert_id, "evidence_id": evidence_id})


@intake_api.post("/api/intake/alerts/<int:alert_id>/dismiss")
@require_permission("intake.triage")
def dismiss_alert(alert_id: int):
    row, refusal = _open(alert_id)
    if refusal is not None:
        return refusal
    data = request.get_json(silent=True)
    reason = text(data.get("reason"), 500) if isinstance(data, dict) else None
    if not reason or len(reason) < 5:
        return error_response("INVALID_INTAKE_ACTION", "اكتب سبب الاستبعاد (5 محارف على الأقل)", 422)
    try:
        with transaction():
            _close_alert(
                alert_id, "UPDATE intake_alerts SET status = 'dismissed', dismissed_reason = ?, updated_at = ? WHERE id = ?", (reason, iso_now(), alert_id)
            )
            record_audit(get_db(), "dismiss", "intake_alert", alert_id, details={"reason": reason})
    except AlertClosed:
        return _closed()
    return jsonify({"alert_id": alert_id, "status": "dismissed"})


@intake_api.post("/api/intake/alerts/<int:alert_id>/claim")
@require_permission("intake.triage")
def claim_alert(alert_id: int):
    """Take an open alert for triage so colleagues see who is on it; a manager may take it from someone else."""
    row, refusal = _open(alert_id)
    if refusal is not None:
        return refusal
    user = current_user() or {}
    if row["claimed_by"] not in {None, user["id"]} and user.get("role") not in MANAGER_ROLES:
        return error_response("INTAKE_ALERT_CLAIMED", "يتولى زميل فرز هذا التنبيه", 409)
    now = iso_now()
    try:
        with transaction():
            _close_alert(
                alert_id,
                "UPDATE intake_alerts SET status = 'triaging', claimed_by = ?, claimed_at = ?, updated_at = ? WHERE id = ?",
                (user["id"], now, now, alert_id),
            )
            record_audit(get_db(), "claim", "intake_alert", alert_id, details={"previous": row["claimed_by"]})
    except AlertClosed:
        return _closed()
    return jsonify(_alert_view(_alert(alert_id) or row))


@intake_api.post("/api/intake/alerts/<int:alert_id>/release")
@require_permission("intake.triage")
def release_alert(alert_id: int):
    """Hand an alert back to the queue; the member triaging it or a manager can do this."""
    row, refusal = _open(alert_id)
    if refusal is not None:
        return refusal
    user = current_user() or {}
    if row["claimed_by"] != user["id"] and user.get("role") not in MANAGER_ROLES:
        return error_response("INTAKE_ALERT_CLAIMED", "يتولى زميل فرز هذا التنبيه", 409)
    try:
        with transaction():
            _close_alert(
                alert_id, "UPDATE intake_alerts SET status = 'new', claimed_by = NULL, claimed_at = NULL, updated_at = ? WHERE id = ?", (iso_now(), alert_id)
            )
            record_audit(get_db(), "release", "intake_alert", alert_id, details={"previous": row["claimed_by"]})
    except AlertClosed:
        return _closed()
    return jsonify(_alert_view(_alert(alert_id) or row))
