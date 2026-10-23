import os
import sqlite3
from typing import Any

from flask import Blueprint, jsonify, request

from .audit import record_audit
from .db import get_db, inserted_id, transaction
from .security import encrypt_secret, error_response, require_permission, safe_external_endpoint, workspace_id
from .timeutils import iso_now

sources_api = Blueprint("sources", __name__)

SOURCE_TYPES = {"training", "file", "syslog", "http", "windows", "linux", "web"}


def _source_view(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        raise RuntimeError("source disappeared during request")
    data = dict(row)
    data.pop("api_key", None)
    data.pop("credential_ciphertext", None)
    data["credentials_stored"] = bool(data.pop("credential_configured", 0))
    return data


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
    return result, None


@sources_api.post("/api/sources")
@require_permission("sources.manage")
def create_source():
    data, failure = _source_payload()
    if failure:
        return failure
    if data is None:
        raise RuntimeError("source payload validation did not return data")
    credential = data.pop("credential", None)
    ciphertext = encrypt_secret(credential) if isinstance(credential, str) and credential else None
    now = iso_now()
    with transaction():
        cursor = get_db().execute(
            """INSERT INTO event_sources
            (workspace_id, name, type, endpoint, api_key, credential_ciphertext, credential_configured, status,
            is_active, rows_ingested, error_rate, created_at, updated_at)
            VALUES (?, ?, ?, ?, NULL, ?, ?, 'not_tested', ?, 0, 0, ?, ?)""",
            (
                workspace_id(),
                data["name"],
                data["type"],
                data.get("endpoint"),
                ciphertext,
                1 if ciphertext else 0,
                1 if data.get("is_active", True) else 0,
                now,
                now,
            ),
        )
        source_id = inserted_id(cursor)
        record_audit(get_db(), "create", "source", source_id, details={"type": data["type"], "credential_configured": bool(ciphertext)})
    row = get_db().execute("SELECT * FROM event_sources WHERE id = ?", (source_id,)).fetchone()
    return jsonify(_source_view(row)), 201, {"Location": f"/api/sources/{source_id}"}


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
    if "is_active" in data:
        updates["is_active"] = 1 if data["is_active"] else 0
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
        status = "not_configured" if not allowlist else "failed"
        message = "يتطلب موصل HTTP عاملًا معزولًا ومصرحًا" if safe else reason
    now = iso_now()
    get_db().execute("UPDATE event_sources SET status = ?, last_validation = ?, updated_at = ? WHERE id = ?", (status, now, now, source_id))
    record_audit(get_db(), "test", "source", source_id, result="success" if status == "connected" else "unsupported", details={"status": status})
    response_status = 200 if status in {"connected", "unsupported", "not_configured"} else 422
    return jsonify({"id": source_id, "status": status, "message": message, "checked_at": now}), response_status
