import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import urllib.error
import urllib.request
from typing import Any

from flask import Blueprint, current_app, jsonify, request

from .audit import record_audit
from .db import get_db, inserted_id, transaction
from .events import ingest_event
from .ingestion import _attach_import_result, parse_records
from .schema import public_id
from .security import (
    actor_id,
    decrypt_secret,
    encrypt_secret,
    error_response,
    require_permission,
    safe_external_endpoint,
    workspace_id,
)
from .timeutils import iso_now

sources_api = Blueprint("sources", __name__)

SOURCE_TYPES = {"training", "file", "syslog", "http", "windows", "linux", "web", "cef"}
MAX_REMOTE_PULL_BYTES = 5 * 1024 * 1024
MAX_INGEST_BATCH_RECORDS = 5000


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise urllib.error.HTTPError(req.full_url, code, "Redirects are disabled for SIEM pull connectors", headers, fp)


def _fetch_remote_events_bytes(url: str, headers: dict[str, str]) -> tuple[bytes, str]:
    opener = urllib.request.build_opener(_NoRedirectHandler)
    req = urllib.request.Request(url, headers={"Accept": "application/json, text/plain", **headers}, method="GET")  # noqa: S310
    with opener.open(req, timeout=5) as resp:  # nosec B310
        body = resp.read(MAX_REMOTE_PULL_BYTES + 1)
        if len(body) > MAX_REMOTE_PULL_BYTES:
            raise ValueError("Remote SIEM response exceeds 5 MiB limit")
        content_type = str(resp.headers.get("Content-Type", "application/octet-stream"))
        return body, content_type


def _source_view(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        raise RuntimeError("source disappeared during request")
    data = dict(row)
    data.pop("api_key", None)
    data.pop("credential_ciphertext", None)
    token_hash = data.pop("ingest_token_hash", None)
    data["credentials_stored"] = bool(data.pop("credential_configured", 0))
    data["ingest_key_configured"] = bool(token_hash)
    return data


def _extract_source_token() -> str | None:
    direct = request.headers.get("X-SOCify-Source-Key", "").strip()
    if direct:
        return direct
    auth = request.headers.get("Authorization", "").strip()
    for prefix in ("Bearer ", "Splunk "):
        if auth.startswith(prefix) and len(auth) > len(prefix):
            return auth[len(prefix) :].strip()
    return None


def _parse_stream_payload(raw_bytes: bytes, content_type: str, source_name: str) -> tuple[str, list[dict[str, Any]]]:
    if not raw_bytes or not raw_bytes.strip():
        raise ValueError("empty SIEM ingest payload")
    if len(raw_bytes) > int(current_app.config["MAX_CONTENT_LENGTH"]):
        raise ValueError("payload exceeds configured upload limit")
    ct_lower = content_type.lower()
    if "ndjson" in ct_lower or "jsonl" in ct_lower:
        fmt, iterator = parse_records("stream.jsonl", raw_bytes, "jsonl", source_name)
        return fmt, list(iterator)
    if "json" in ct_lower or raw_bytes.lstrip().startswith((b"{", b"[")):
        try:
            decoded = json.loads(raw_bytes.decode("utf-8-sig"))
            if isinstance(decoded, dict) and isinstance(decoded.get("events"), list):
                serialized = json.dumps(decoded["events"], ensure_ascii=False).encode("utf-8")
                fmt, iterator = parse_records("stream.json", serialized, "json", source_name)
                return fmt, list(iterator)
            if isinstance(decoded, dict) and isinstance(decoded.get("event"), dict):
                serialized = json.dumps([decoded["event"]], ensure_ascii=False).encode("utf-8")
                fmt, iterator = parse_records("stream.json", serialized, "json", source_name)
                return fmt, list(iterator)
        except json.JSONDecodeError:
            if raw_bytes.lstrip().startswith(b"{"):
                fmt, iterator = parse_records("stream.jsonl", raw_bytes, "jsonl", source_name)
                return fmt, list(iterator)
    fmt, iterator = parse_records("stream.log", raw_bytes, "auto", source_name)
    return fmt, list(iterator)


def _ingest_records_for_source(
    source_row: sqlite3.Row,
    raw_bytes: bytes,
    content_type: str,
    target_case_id: int | None,
    actor: int | None,
) -> dict[str, Any]:
    ws_id = int(source_row["workspace_id"])
    source_id = int(source_row["id"])
    source_name = str(source_row["name"])
    fmt, records = _parse_stream_payload(raw_bytes, content_type, source_name)
    if len(records) > MAX_INGEST_BATCH_RECORDS:
        raise ValueError(f"SIEM batch exceeds {MAX_INGEST_BATCH_RECORDS} records")

    effective_actor = actor
    if effective_actor is None:
        owner_row = (
            get_db()
            .execute(
                "SELECT COALESCE(assignee, creator) FROM incident_cases WHERE id = ? AND workspace_id = ?",
                (target_case_id, ws_id),
            )
            .fetchone()
            if target_case_id
            else None
        )
        if owner_row and owner_row[0]:
            effective_actor = int(owner_row[0])
        else:
            fallback_user = get_db().execute("SELECT id FROM users WHERE workspace_id = ? AND is_active = 1 ORDER BY id LIMIT 1", (ws_id,)).fetchone()
            effective_actor = int(fallback_user[0]) if fallback_user else None

    content_hash = hashlib.sha256(raw_bytes).hexdigest()
    now = iso_now()
    accepted = 0
    rejected = 0
    skipped = 0
    alert_ids: list[int] = []

    with transaction():
        job_db_id: int | None = None
        if target_case_id is not None:
            case_check = (
                get_db()
                .execute(
                    "SELECT id, status, archived_at FROM incident_cases WHERE id = ? AND workspace_id = ?",
                    (target_case_id, ws_id),
                )
                .fetchone()
            )
            if not case_check or case_check["archived_at"] is not None or case_check["status"] == "closed":
                raise ValueError("linked target case is closed or unavailable")
            retained = (
                get_db()
                .execute(
                    """SELECT id, total FROM ingestion_jobs WHERE workspace_id = ? AND source_id = ? AND case_id = ?
                   AND content_hash = ? AND status = 'completed' AND active_version = 1 AND accepted > 0 AND rejected = 0
                   ORDER BY id LIMIT 1""",
                    (ws_id, source_id, target_case_id, content_hash),
                )
                .fetchone()
            )
            if retained:
                get_db().execute(
                    "UPDATE event_sources SET error_rate = 0, last_sync = ?, status = 'connected', updated_at = ? WHERE id = ?",
                    (now, now, source_id),
                )
                record_audit(
                    get_db(),
                    "ingest_retry",
                    "source",
                    source_id,
                    details={"accepted": 0, "skipped": retained["total"], "case_id": target_case_id, "retained_job_id": retained["id"]},
                    actor=effective_actor,
                    workspace=ws_id,
                )
                return {
                    "source_id": source_id,
                    "case_id": target_case_id,
                    "format": fmt,
                    "accepted": 0,
                    "rejected": 0,
                    "skipped": retained["total"],
                    "alerts_triggered": 0,
                    "alert_ids": [],
                }
            ciphertext = encrypt_secret(base64.b64encode(raw_bytes).decode())
            cursor = get_db().execute(
                """INSERT INTO ingestion_jobs
                   (job_id, workspace_id, source_id, training_run_id, case_id, filename, original_filename, format,
                    content_hash, evidence_ciphertext, raw_size, estimated_total, source_name, status,
                    parser_version, active_version, autopsy_options, created_by, executor_id, created_at, updated_at, available_at, completed_at, progress)
                   VALUES (?, ?, ?, NULL, ?, 'siem-stream.log', 'siem-stream.log', ?, ?, ?, ?, ?, ?, 'completed', 'socify-siem', 1, '{}', ?, ?, ?, ?, ?, ?, 1)""",
                (
                    public_id("IMP"),
                    ws_id,
                    source_id,
                    target_case_id,
                    fmt,
                    content_hash,
                    ciphertext,
                    len(raw_bytes),
                    len(records),
                    source_name,
                    effective_actor,
                    effective_actor,
                    now,
                    now,
                    now,
                    now,
                ),
            )
            job_db_id = inserted_id(cursor)
            get_db().execute(
                "INSERT INTO autopsy_case_imports(case_id, job_id, attached_by, attached_at) VALUES (?, ?, ?, ?)",
                (target_case_id, job_db_id, effective_actor, now),
            )
            get_db().execute(
                "INSERT INTO case_evidence(case_id, evidence_type, reference_id, title, sha256, provenance, added_by, added_at) VALUES (?, 'import', ?, ?, ?, ?, ?, ?)",
                (
                    target_case_id,
                    str(job_db_id),
                    f"SIEM Stream ({source_name})",
                    content_hash,
                    json.dumps({"source_id": source_id, "source": source_name, "format": fmt}),
                    effective_actor,
                    now,
                ),
            )

        job_row = get_db().execute("SELECT * FROM ingestion_jobs WHERE id = ?", (job_db_id,)).fetchone() if job_db_id else None
        for idx, record in enumerate(records, 1):
            if record.get("__parse_error"):
                rejected += 1
                continue
            record = dict(record)
            record["source"] = source_name
            if record.get("source_type") in (None, "import", "training"):
                record["source_type"] = "http" if source_row["type"] == "http" else str(source_row["type"])
            raw_payload = record.get("raw_payload")
            if not isinstance(raw_payload, dict):
                raw_payload = {}
            explicit_ext_id = raw_payload.get("external_id") or raw_payload.get("id")
            record["idempotency_key"] = f"siem:{source_id}:{explicit_ext_id}" if explicit_ext_id else f"siem:{source_id}:{content_hash}:{idx}"
            try:
                ev_id, triggered, duplicate = ingest_event(
                    get_db(),
                    record,
                    effective_actor,
                    ws_id,
                    None,
                    target_case_id,
                    job_db_id,
                    True,
                )
                if duplicate:
                    skipped += 1
                else:
                    accepted += 1
                    alert_ids.extend(triggered)
                    if target_case_id is not None and job_row is not None:
                        _attach_import_result(job_row, ev_id, triggered)
            except (ValueError, OverflowError, sqlite3.Error):
                rejected += 1

        if job_db_id is not None and target_case_id is not None:
            from .autopsy_domain import custody, touch_case

            get_db().execute(
                "UPDATE ingestion_jobs SET accepted = ?, rejected = ?, skipped = ?, total = ?, checkpoint = ? WHERE id = ?",
                (accepted, rejected, skipped, len(records), len(records), job_db_id),
            )
            custody(
                target_case_id,
                "siem_stream_ingested",
                {"source_id": source_id, "job_id": job_db_id, "accepted": accepted, "alerts": len(alert_ids), "sha256": content_hash},
                actor=effective_actor,
            )
            touch_case(target_case_id)

        total_attempt = accepted + rejected + skipped
        err_rate = (rejected / total_attempt) if total_attempt else 0.0
        get_db().execute(
            "UPDATE event_sources SET rows_ingested = rows_ingested + ?, error_rate = ?, last_sync = ?, status = ?, updated_at = ? WHERE id = ?",
            (accepted, err_rate, now, "connected" if accepted or not rejected else "failed", now, source_id),
        )
        record_audit(
            get_db(),
            "ingest",
            "source",
            source_id,
            details={"accepted": accepted, "rejected": rejected, "alerts_triggered": len(alert_ids), "case_id": target_case_id},
            actor=effective_actor,
            workspace=ws_id,
        )

    return {
        "source_id": source_id,
        "case_id": target_case_id,
        "format": fmt,
        "accepted": accepted,
        "rejected": rejected,
        "skipped": skipped,
        "alerts_triggered": len(alert_ids),
        "alert_ids": alert_ids,
    }


@sources_api.get("/api/sources")
@require_permission("sources.read")
def list_sources():
    rows = get_db().execute("SELECT * FROM event_sources WHERE workspace_id = ? ORDER BY name", (workspace_id(),)).fetchall()
    return jsonify([_source_view(row) for row in rows])


def _source_payload(require_all: bool = True) -> tuple[dict[str, Any] | None, object | None]:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, error_response("INVALID_JSON", "يلزم إرسال كائن JSON صالح", 400)
    result: dict[str, Any] = {}
    if require_all or "name" in data:
        name = data.get("name")
        if not isinstance(name, str) or not 2 <= len(name.strip()) <= 100:
            return None, error_response("INVALID_SOURCE_NAME", "اسم المصدر مطلوب وبحد أقصى 100 محرف", 422)
        result["name"] = name.strip()
    if require_all or "type" in data:
        source_type = data.get("type")
        if source_type not in SOURCE_TYPES:
            return None, error_response("INVALID_SOURCE_TYPE", "نوع المصدر غير مدعوم", 422)
        result["type"] = source_type
    if "endpoint" in data or require_all:
        endpoint = data.get("endpoint")
        if endpoint is not None and (not isinstance(endpoint, str) or len(endpoint) > 500):
            return None, error_response("INVALID_SOURCE_ENDPOINT", "عنوان المصدر غير صالح", 422)
        result["endpoint"] = endpoint.strip() if isinstance(endpoint, str) else None
    if "credential" in data or "api_key" in data:
        credential = data.get("credential", data.get("api_key"))
        if credential is not None and (not isinstance(credential, str) or not 1 <= len(credential) <= 4096):
            return None, error_response("INVALID_SOURCE_CREDENTIAL", "بيانات الاعتماد غير صالحة", 422)
        result["credential"] = credential
    if "is_active" in data:
        if not isinstance(data["is_active"], bool):
            return None, error_response("INVALID_SOURCE_STATE", "is_active يجب أن تكون قيمة منطقية", 422)
        result["is_active"] = data["is_active"]
    if "default_case_id" in data:
        cid = data["default_case_id"]
        if cid is not None and (type(cid) is not int or cid < 1):
            return None, error_response("INVALID_SOURCE_CASE", "معرف القضية المرتبطة غير صالح", 422)
        result["default_case_id"] = cid
    if "generate_ingest_key" in data:
        if not isinstance(data["generate_ingest_key"], bool):
            return None, error_response("INVALID_SOURCE_STATE", "generate_ingest_key يجب أن تكون قيمة منطقية", 422)
        result["generate_ingest_key"] = data["generate_ingest_key"]
    return result, None


@sources_api.post("/api/sources")
@require_permission("sources.manage")
def create_source():
    data, failure = _source_payload()
    if failure:
        return failure
    if data is None:
        raise RuntimeError("source payload validation did not return data")
    default_case_id = data.pop("default_case_id", None)
    if default_case_id is not None:
        from .cases import _case_row

        if not _case_row(default_case_id):
            return error_response("CASE_NOT_FOUND", "القضية المرتبطة غير متاحة", 404)
    generate_key = bool(data.pop("generate_ingest_key", False))
    raw_ingest_key = secrets.token_urlsafe(32) if generate_key else None
    token_hash = hashlib.sha256(raw_ingest_key.encode()).hexdigest() if raw_ingest_key else None
    credential = data.pop("credential", None)
    ciphertext = encrypt_secret(credential) if isinstance(credential, str) and credential else None
    now = iso_now()
    with transaction():
        cursor = get_db().execute(
            """INSERT INTO event_sources
            (workspace_id, name, type, endpoint, api_key, credential_ciphertext, credential_configured, status,
            is_active, rows_ingested, error_rate, default_case_id, ingest_token_hash, created_at, updated_at)
            VALUES (?, ?, ?, ?, NULL, ?, ?, 'not_tested', ?, 0, 0, ?, ?, ?, ?)""",
            (
                workspace_id(),
                data["name"],
                data["type"],
                data.get("endpoint"),
                ciphertext,
                1 if ciphertext else 0,
                1 if data.get("is_active", True) else 0,
                default_case_id,
                token_hash,
                now,
                now,
            ),
        )
        source_id = inserted_id(cursor)
        record_audit(get_db(), "create", "source", source_id, details={"type": data["type"], "credential_configured": bool(ciphertext)})
    row = get_db().execute("SELECT * FROM event_sources WHERE id = ?", (source_id,)).fetchone()
    payload = _source_view(row)
    if raw_ingest_key:
        payload["ingest_key"] = raw_ingest_key
    return jsonify(payload), 201, {"Location": f"/api/sources/{source_id}"}


@sources_api.put("/api/sources/<int:source_id>")
@sources_api.patch("/api/sources/<int:source_id>")
@require_permission("sources.manage")
def update_source(source_id: int):
    row = get_db().execute("SELECT * FROM event_sources WHERE id = ? AND workspace_id = ?", (source_id, workspace_id())).fetchone()
    if not row:
        return error_response("SOURCE_NOT_FOUND", "المصدر غير موجود", 404)
    data, failure = _source_payload(False)
    if failure:
        return failure
    if data is None:
        raise RuntimeError("source payload validation did not return data")
    updates: dict[str, Any] = {key: value for key, value in data.items() if key in {"name", "type", "endpoint"}}
    if "default_case_id" in data:
        if data["default_case_id"] is not None:
            from .cases import _case_row

            if not _case_row(data["default_case_id"]):
                return error_response("CASE_NOT_FOUND", "القضية المرتبطة غير متاحة", 404)
        updates["default_case_id"] = data["default_case_id"]
    if "is_active" in data:
        updates["is_active"] = 1 if data["is_active"] else 0
        if not data["is_active"]:
            updates["status"] = "disabled"
        elif not row["is_active"]:
            updates["status"] = "not_tested"
    if "credential" in data:
        credential = data["credential"]
        updates["credential_ciphertext"] = encrypt_secret(credential) if isinstance(credential, str) and credential else None
        updates["credential_configured"] = 1 if updates["credential_ciphertext"] else 0
        updates["api_key"] = None
    if not updates:
        return error_response("NO_CHANGES", "لم تُرسل حقول قابلة للتعديل", 422)
    updates["updated_at"] = iso_now()
    assignments = ", ".join(f"{key} = ?" for key in updates)
    with transaction():
        get_db().execute(f"UPDATE event_sources SET {assignments} WHERE id = ?", (*updates.values(), source_id))
        record_audit(get_db(), "update", "source", source_id, details={"fields": list(updates)})
    return jsonify(_source_view(get_db().execute("SELECT * FROM event_sources WHERE id = ?", (source_id,)).fetchone()))


@sources_api.post("/api/sources/<int:source_id>/rotate-key")
@require_permission("sources.manage")
def rotate_source_key(source_id: int):
    row = get_db().execute("SELECT * FROM event_sources WHERE id = ? AND workspace_id = ?", (source_id, workspace_id())).fetchone()
    if not row:
        return error_response("SOURCE_NOT_FOUND", "المصدر غير موجود", 404)
    raw_key = secrets.token_urlsafe(32)
    digest = hashlib.sha256(raw_key.encode()).hexdigest()
    now = iso_now()
    with transaction():
        get_db().execute("UPDATE event_sources SET ingest_token_hash = ?, updated_at = ? WHERE id = ?", (digest, now, source_id))
        record_audit(get_db(), "rotate_key", "source", source_id)
    updated = get_db().execute("SELECT * FROM event_sources WHERE id = ?", (source_id,)).fetchone()
    return jsonify({**_source_view(updated), "ingest_key": raw_key})


@sources_api.delete("/api/sources/<int:source_id>")
@require_permission("sources.manage")
def disable_source(source_id: int):
    row = get_db().execute("SELECT id FROM event_sources WHERE id = ? AND workspace_id = ?", (source_id, workspace_id())).fetchone()
    if not row:
        return error_response("SOURCE_NOT_FOUND", "المصدر غير موجود", 404)
    get_db().execute("UPDATE event_sources SET is_active = 0, status = 'disabled', updated_at = ? WHERE id = ?", (iso_now(), source_id))
    record_audit(get_db(), "disable", "source", source_id)
    return "", 204


@sources_api.post("/api/sources/<int:source_id>/test")
@require_permission("sources.manage")
def test_source(source_id: int):
    row = get_db().execute("SELECT * FROM event_sources WHERE id = ? AND workspace_id = ?", (source_id, workspace_id())).fetchone()
    if not row:
        return error_response("SOURCE_NOT_FOUND", "المصدر غير موجود", 404)
    source_type = row["type"]
    status = "unsupported"
    message = "التحقق الشبكي غير مفعّل لهذا النوع"
    if source_type in {"training", "file"}:
        status = "connected"
        message = "المصدر المحلي جاهز للاستيراد"
    elif source_type == "http" and row["endpoint"]:
        allowlist = {item.strip().lower() for item in os.environ.get("SOCIFY_SOURCE_ALLOWLIST", "").split(",") if item.strip()}
        safe, reason = safe_external_endpoint(row["endpoint"], allowlist)
        status = "not_configured" if not allowlist else ("connected" if safe else "failed")
        if not allowlist:
            status = "not_configured"
        elif not safe:
            status = "failed"
        else:
            status = "not_configured"
        message = "يتطلب موصل HTTP عاملًا معزولًا ومصرحًا" if safe else reason
    now = iso_now()
    get_db().execute("UPDATE event_sources SET status = ?, last_validation = ?, updated_at = ? WHERE id = ?", (status, now, now, source_id))
    record_audit(get_db(), "test", "source", source_id, result="success" if status == "connected" else "unsupported", details={"status": status})
    response_status = 200 if status in {"connected", "unsupported", "not_configured"} else 422
    return jsonify({"id": source_id, "status": status, "message": message, "checked_at": now}), response_status


@sources_api.post("/api/sources/<int:source_id>/ingest")
def source_webhook_ingest(source_id: int):
    token = _extract_source_token()
    if not token:
        return error_response("INVALID_SOURCE_KEY", "مفتاح إرسال المصدر مفقود أو غير صالح", 401)
    row = get_db().execute("SELECT * FROM event_sources WHERE id = ? AND is_active = 1", (source_id,)).fetchone()
    expected_hash = str(row["ingest_token_hash"]) if row and row["ingest_token_hash"] else ""
    provided_hash = hashlib.sha256(token.encode()).hexdigest()
    if not row or not expected_hash or not hmac.compare_digest(provided_hash, expected_hash):
        return error_response("INVALID_SOURCE_KEY", "مفتاح إرسال المصدر مفقود أو غير صالح", 401)
    raw_bytes = request.get_data(cache=False)
    target_case = row["default_case_id"]
    query_case = request.args.get("case_id")
    if query_case:
        if len(query_case) > 19 or not query_case.isdecimal():
            return error_response("INVALID_CASE", "معرف القضية غير صالح", 422)
        if target_case is None or int(query_case) != target_case:
            return error_response("SOURCE_CASE_MISMATCH", "مفتاح المصدر لا يخول الإرسال إلى هذه القضية", 403)
    try:
        result = _ingest_records_for_source(row, raw_bytes, request.content_type or "", target_case, None)
    except ValueError as exc:
        return error_response("SIEM_INGEST_FAILED", str(exc), 422)
    return jsonify(result), 201


def _execute_source_pull(row: sqlite3.Row, target_case_id: int | None) -> tuple[Any, int]:
    if not row["is_active"]:
        return error_response("SOURCE_DISABLED", "المصدر معطل حاليًا", 409)
    if row["type"] != "http" or not row["endpoint"]:
        return error_response("SOURCE_PULL_UNSUPPORTED", "السحب المباشر متاح لمصادر HTTP المزودة بعنوان صالح", 422)
    allowlist = {item.strip().lower() for item in os.environ.get("SOCIFY_SOURCE_ALLOWLIST", "").split(",") if item.strip()}
    if not allowlist:
        return error_response("SOURCE_ALLOWLIST_REQUIRED", "حدد SOCIFY_SOURCE_ALLOWLIST للسماح بالسحب المباشر من خادم SIEM", 422)
    safe, reason = safe_external_endpoint(row["endpoint"], allowlist)
    if not safe:
        return error_response("UNSAFE_SOURCE_ENDPOINT", reason, 422)
    headers: dict[str, str] = {}
    if row["credential_ciphertext"]:
        secret = decrypt_secret(row["credential_ciphertext"])
        if secret:
            headers["Authorization"] = secret if " " in secret else f"Bearer {secret}"
    try:
        body, content_type = _fetch_remote_events_bytes(str(row["endpoint"]), headers)
        result = _ingest_records_for_source(row, body, content_type, target_case_id, actor_id())
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return error_response("SIEM_PULL_FAILED", f"تعذر سحب السجلات من المصدر: {exc}", 422)
    return jsonify(result), 200


@sources_api.post("/api/sources/<int:source_id>/pull")
@require_permission("sources.manage")
def pull_source(source_id: int):
    row = get_db().execute("SELECT * FROM event_sources WHERE id = ? AND workspace_id = ?", (source_id, workspace_id())).fetchone()
    if not row:
        return error_response("SOURCE_NOT_FOUND", "المصدر غير موجود", 404)
    body = request.get_json(silent=True) or {}
    target_case = body.get("case_id", row["default_case_id"]) if isinstance(body, dict) else row["default_case_id"]
    if target_case is not None:
        from .cases import _case_row

        if type(target_case) is not int or not _case_row(target_case):
            return error_response("CASE_NOT_FOUND", "القضية المرتبطة غير متاحة", 404)
    return _execute_source_pull(row, target_case)


@sources_api.get("/api/cases/<int:case_id>/siem-connectors")
@require_permission("cases.read")
def list_case_siem_connectors(case_id: int):
    from .cases import _case_row

    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    rows = (
        get_db()
        .execute(
            "SELECT * FROM event_sources WHERE workspace_id = ? AND default_case_id = ? ORDER BY id DESC",
            (workspace_id(), case_id),
        )
        .fetchall()
    )
    return jsonify({"items": [_source_view(row) for row in rows], "total": len(rows)})


@sources_api.post("/api/cases/<int:case_id>/siem-connectors")
@require_permission("evidence.add")
def create_case_siem_connector(case_id: int):
    from .cases import _case_row

    case = _case_row(case_id)
    if not case:
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    if case["status"] == "closed":
        return error_response("CASE_CLOSED", "القضية مغلقة", 409)
    data, failure = _source_payload()
    if failure:
        return failure
    if data is None:
        raise RuntimeError("connector payload validation did not return data")
    credential = data.pop("credential", None)
    ciphertext = encrypt_secret(credential) if isinstance(credential, str) and credential else None
    raw_ingest_key = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_ingest_key.encode()).hexdigest()
    now = iso_now()
    with transaction():
        cursor = get_db().execute(
            """INSERT INTO event_sources
            (workspace_id, name, type, endpoint, api_key, credential_ciphertext, credential_configured, status,
            is_active, rows_ingested, error_rate, default_case_id, ingest_token_hash, created_at, updated_at)
            VALUES (?, ?, ?, ?, NULL, ?, ?, 'not_tested', 1, 0, 0, ?, ?, ?, ?)""",
            (
                workspace_id(),
                data["name"],
                data["type"],
                data.get("endpoint"),
                ciphertext,
                1 if ciphertext else 0,
                case_id,
                token_hash,
                now,
                now,
            ),
        )
        source_id = inserted_id(cursor)
        record_audit(get_db(), "create_case_connector", "source", source_id, details={"case_id": case_id, "type": data["type"]})
    row = get_db().execute("SELECT * FROM event_sources WHERE id = ?", (source_id,)).fetchone()
    return jsonify({**_source_view(row), "ingest_key": raw_ingest_key, "ingest_url": f"/api/sources/{source_id}/ingest"}), 201


@sources_api.post("/api/cases/<int:case_id>/siem-connectors/<int:source_id>/pull")
@require_permission("evidence.add")
def pull_case_siem_connector(case_id: int, source_id: int):
    from .cases import _case_row

    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    row = (
        get_db()
        .execute(
            "SELECT * FROM event_sources WHERE id = ? AND workspace_id = ? AND default_case_id = ?",
            (source_id, workspace_id(), case_id),
        )
        .fetchone()
    )
    if not row:
        return error_response("SOURCE_NOT_FOUND", "موصل SIEM غير مرتبط بهذه القضية", 404)
    return _execute_source_pull(row, case_id)
