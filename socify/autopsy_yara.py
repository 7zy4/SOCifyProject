import base64
import hashlib
import json
import sqlite3

from flask import Blueprint, jsonify, request

from .audit import record_audit
from .autopsy_domain import canonical, text_value
from .autopsy_worker import compute_artifacts
from .db import get_db, inserted_id, transaction
from .security import actor_id, error_response, require_permission, workspace_id
from .timeutils import iso_now

autopsy_yara_api = Blueprint("autopsy_yara", __name__)


def migrate(connection):
    connection.execute(
        "CREATE TABLE IF NOT EXISTS autopsy_yara_packs (id INTEGER PRIMARY KEY,workspace_id INTEGER NOT NULL REFERENCES training_workspaces(id),name TEXT NOT NULL,version INTEGER NOT NULL,source TEXT NOT NULL,license TEXT NOT NULL,origin TEXT NOT NULL,sha256 TEXT NOT NULL,validation TEXT NOT NULL CHECK(json_valid(validation)),created_by INTEGER NOT NULL REFERENCES users(id),created_at TEXT NOT NULL,UNIQUE(workspace_id,name,version))"
    )
    for action in ("UPDATE", "DELETE"):
        connection.execute(
            f"CREATE TRIGGER IF NOT EXISTS autopsy_yara_immutable_{action.lower()} BEFORE {action} ON autopsy_yara_packs BEGIN SELECT RAISE(ABORT,'YARA snapshots are immutable'); END"
        )


def validate_input(data):
    if not isinstance(data, dict) or set(data) != {"name", "version", "source", "license", "origin", "fixtures"}:
        raise ValueError("حدد اسم الحزمة وإصدارها ومصدرها ورخصتها وfixtures")
    if type(data["version"]) is not int or not 1 <= data["version"] <= 1000000:
        raise ValueError("الإصدار عدد صحيح موجب")
    fields = {key: text_value(data[key], maximum, True) for key, maximum in (("name", 120), ("source", 65536), ("license", 500), ("origin", 1000))}
    if len(fields["source"].encode()) > 65536:
        raise ValueError("قواعد YARA تتجاوز 64 KiB")
    fixtures = data["fixtures"]
    if not isinstance(fixtures, dict) or set(fixtures) != {"positive", "negative"}:
        raise ValueError("fixtures تتطلب positive وnegative بترميز base64")
    total = 0
    for items in fixtures.values():
        if not isinstance(items, list) or not 1 <= len(items) <= 10:
            raise ValueError("كل مجموعة fixtures تتطلب 1–10 عينات اصطناعية")
        for item in items:
            if not isinstance(item, str) or len(item) > 87384:
                raise ValueError("fixture يتجاوز 64 KiB")
            try:
                content = base64.b64decode(item, validate=True)
            except ValueError as exc:
                raise ValueError("ترميز fixture غير صالح") from exc
            if not content or len(content) > 65536:
                raise ValueError("fixture فارغ أو كبير")
            total += len(content)
    if total > 512 * 1024:
        raise ValueError("مجموع fixtures يتجاوز 512 KiB")
    return {**fields, "version": data["version"], "fixtures": fixtures}


@autopsy_yara_api.get("/api/autopsy/yara")
@require_permission("cases.read")
def list_packs():
    rows = (
        get_db()
        .execute(
            "SELECT id,name,version,license,origin,sha256,validation,created_by,created_at FROM autopsy_yara_packs WHERE workspace_id=? ORDER BY id DESC LIMIT 1000",
            (workspace_id(),),
        )
        .fetchall()
    )
    return jsonify({"items": [{**dict(row), "validation": json.loads(row["validation"])} for row in rows], "default": "EICAR test marker only", "limit": 1000})


@autopsy_yara_api.post("/api/autopsy/yara")
@require_permission("rules.manage")
def publish_pack():
    try:
        data = validate_input(request.get_json(silent=True))
    except (ValueError, UnicodeError) as exc:
        return error_response("INVALID_YARA_PACK", str(exc), 422)
    if get_db().execute("SELECT COUNT(*) FROM autopsy_yara_packs WHERE workspace_id=?", (workspace_id(),)).fetchone()[0] >= 1000:
        return error_response("YARA_LIBRARY_FULL", "وصلت المكتبة إلى حد الإصدارات المحلي", 409)
    try:
        validation = json.loads(compute_artifacts({"rules": data["source"], "fixtures": data["fixtures"]}, "yara_validation", ["validation"], 30)["validation"])
    except (ValueError, OSError, TimeoutError):
        return error_response("YARA_VALIDATION_UNAVAILABLE", "تعذر التحقق المعزول؛ لم تنشر الحزمة", 503)
    if not validation.get("valid"):
        return error_response("YARA_FIXTURES_FAILED", "فشل تجميع YARA أو أمثلتها الإيجابية والسلبية؛ راجع الملف محليًا", 422)
    digest = hashlib.sha256(data["source"].encode()).hexdigest()
    if validation.get("sha256") != digest:
        return error_response("YARA_INTEGRITY_FAILED", "بصمة التحقق لا تطابق الحزمة", 503)
    try:
        with transaction():
            identifier = inserted_id(
                get_db().execute(
                    "INSERT INTO autopsy_yara_packs(workspace_id,name,version,source,license,origin,sha256,validation,created_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        workspace_id(),
                        data["name"],
                        data["version"],
                        data["source"],
                        data["license"],
                        data["origin"],
                        digest,
                        canonical(validation),
                        actor_id(),
                        iso_now(),
                    ),
                )
            )
            record_audit(get_db(), "publish", "yara_pack", identifier, details={"sha256": digest, "name": data["name"], "version": data["version"]})
    except sqlite3.IntegrityError:
        return error_response("YARA_VERSION_EXISTS", "هذا الإصدار محفوظ؛ أنشئ رقم إصدار جديدًا", 409)
    return jsonify({"id": identifier, "sha256": digest, "validation": validation}), 201
