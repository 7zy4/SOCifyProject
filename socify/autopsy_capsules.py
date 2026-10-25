import base64
import hashlib
import io
import json
import re
import sqlite3
import stat
import struct
import uuid
import zipfile
from typing import Any

from cryptography.fernet import InvalidToken
from flask import Blueprint, Response, jsonify, request

from .autopsy_api import manager
from .autopsy_domain import canonical, custody, text_value
from .cases import _case_row, _reference
from .db import get_db, inserted_id, transaction
from .ingestion import _job_content
from .request_limits import StructureLimitError, validate_json_structure
from .security import actor_id, cipher, current_user, decrypt_secret, encrypt_secret, error_response, has_permission, require_permission, workspace_id
from .timeutils import iso_now

autopsy_capsules_api = Blueprint("autopsy_capsules", __name__)
MAX_EXPANDED = 64 * 1024 * 1024
MAX_ARCHIVE = MAX_EXPANDED + 512 * 1024
MAX_MEMBER = 32 * 1024 * 1024
MAX_FILES = 4096
MAX_ROWS = 50000
PATH = re.compile(
    r"(?:data\.json|originals/[1-9][0-9]*\.bin|evidence/[1-9][0-9]*\.txt|samples/[1-9][0-9]*\.bin|reports/[1-9][0-9]*/(?:json|html|pdf|md|docx)|legacy_reports/[1-9][0-9]*\.txt)"
)
CASE_TABLES = (
    "case_notes",
    "case_tasks",
    "case_history",
    "case_evidence",
    "case_technique_annotations",
    "autopsy_case_members",
    "autopsy_case_imports",
    "autopsy_records",
    "autopsy_custody",
    "autopsy_reports",
    "case_reports",
)
SCHEMA = """
CREATE TABLE IF NOT EXISTS autopsy_capsule_archives (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES incident_cases(id),
    profile TEXT NOT NULL,
    source_reference TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    ciphertext BLOB NOT NULL,
    id_map TEXT NOT NULL CHECK(json_valid(id_map)),
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_autopsy_capsule_case ON autopsy_capsule_archives(case_id, id);
CREATE TRIGGER IF NOT EXISTS autopsy_capsule_immutable_update BEFORE UPDATE ON autopsy_capsule_archives
BEGIN SELECT RAISE(ABORT, 'imported capsule archives are immutable'); END;
CREATE TRIGGER IF NOT EXISTS autopsy_capsule_immutable_delete BEFORE DELETE ON autopsy_capsule_archives
BEGIN SELECT RAISE(ABORT, 'imported capsule archives are immutable'); END;
"""


def migrate(connection):
    statement = ""
    for line in SCHEMA.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            connection.execute(statement)
            statement = ""


def digest(content):
    return hashlib.sha256(content).hexdigest()


def rows(query, values=()):
    found = get_db().execute(query + " LIMIT ?", (*values, MAX_ROWS + 1)).fetchall()
    if len(found) > MAX_ROWS:
        raise ValueError("تتجاوز الحزمة حد الصفوف؛ استخدم تصدير السجلات المقسم والأرشيف المعتمد لدى الشركة")
    return [dict(row) for row in found]


def full_case_access(case_id):
    from .autopsy_pipeline import case_full_access

    return case_full_access(case_id)


def add_file(files, path, content):
    if len(content) > MAX_MEMBER or len(files) >= MAX_FILES - 1 or sum(map(len, files.values())) + len(content) > MAX_EXPANDED:
        raise ValueError("تتجاوز الحزمة حدود الحجم أو عدد الملفات المسموح")
    files[path] = content


def export_snapshot(case_id, profile):
    case = _case_row(case_id)
    if case is None:
        raise ValueError("القضية غير متاحة")
    snapshot: dict[str, Any] = {
        "case": dict(case),
        "context": dict(get_db().execute("SELECT * FROM autopsy_case_context WHERE case_id = ?", (case_id,)).fetchone() or {}),
        "tables": {},
    }
    snapshot["case"].pop("workspace_id", None)
    files: dict[str, bytes] = {}
    for table in CASE_TABLES:
        snapshot["tables"][table] = rows(f"SELECT * FROM {table} WHERE case_id = ? ORDER BY rowid", (case_id,))
    if profile == "team":
        snapshot["tables"]["case_notes"] = [row for row in snapshot["tables"]["case_notes"] if row["visibility"] != "private"]
        snapshot["tables"]["autopsy_records"] = [
            row for row in snapshot["tables"]["autopsy_records"] if json.loads(row["payload"]).get("visibility") != "private"
        ]
    records = {row["id"] for row in snapshot["tables"]["autopsy_records"]}
    snapshot["revisions"] = rows(
        "SELECT r.* FROM autopsy_record_revisions r JOIN autopsy_records a ON a.id = r.record_id WHERE a.case_id = ? ORDER BY r.record_id, r.version",
        (case_id,),
    )
    snapshot["revisions"] = [
        row
        for row in snapshot["revisions"]
        if row["record_id"] in records and (profile == "backup" or json.loads(row["payload"]).get("visibility") != "private")
    ]
    snapshot["events"] = rows("SELECT e.* FROM security_events e JOIN case_events ce ON ce.event_id = e.id WHERE ce.case_id = ? ORDER BY e.id", (case_id,))
    snapshot["event_links"] = rows("SELECT * FROM case_events WHERE case_id = ? ORDER BY event_id", (case_id,))
    snapshot["alerts"] = rows("SELECT a.* FROM alerts a JOIN case_alerts ca ON ca.alert_id = a.id WHERE ca.case_id = ? ORDER BY a.id", (case_id,))
    snapshot["alert_links"] = rows("SELECT * FROM case_alerts WHERE case_id = ? ORDER BY alert_id", (case_id,))
    snapshot["alert_events"] = rows(
        "SELECT ae.* FROM alert_events ae JOIN case_alerts ca ON ca.alert_id = ae.alert_id WHERE ca.case_id = ? ORDER BY ae.alert_id, ae.event_id", (case_id,)
    )
    snapshot["actors"] = rows("SELECT DISTINCT u.id, u.name, u.role FROM users u WHERE u.workspace_id = ? ORDER BY u.id", (workspace_id(),))
    snapshot["imports"] = rows("SELECT * FROM ingestion_jobs WHERE case_id = ? ORDER BY id", (case_id,))
    for job in snapshot["imports"]:
        if job.get("evidence_ciphertext"):
            add_file(files, f"originals/{job['id']}.bin", _job_content(job))
        job.pop("evidence_ciphertext", None)
    snapshot["import_errors"] = rows(
        "SELECT e.* FROM ingestion_errors e JOIN ingestion_jobs j ON j.id = e.job_id WHERE j.case_id = ? ORDER BY e.id", (case_id,)
    )
    for entry in rows(
        "SELECT c.evidence_id, c.ciphertext FROM case_evidence_content c JOIN case_evidence e ON e.id = c.evidence_id WHERE e.case_id = ? ORDER BY e.id",
        (case_id,),
    ):
        add_file(files, f"evidence/{entry['evidence_id']}.txt", decrypt_secret(entry["ciphertext"]).encode())
    snapshot["samples"] = rows(
        "SELECT id, case_id, evidence_id, filename, sha256, size, created_by, created_at FROM autopsy_samples WHERE case_id = ? ORDER BY id", (case_id,)
    )
    if profile == "backup":
        for sample in snapshot["samples"]:
            encrypted = get_db().execute("SELECT ciphertext FROM autopsy_samples WHERE id = ?", (sample["id"],)).fetchone()[0]
            content = cipher().decrypt(encrypted)
            if digest(content) != sample["sha256"]:
                raise ValueError("بصمة العينة غير مطابقة")
            add_file(files, f"samples/{sample['id']}.bin", content)
    for report in snapshot["tables"]["autopsy_reports"]:
        if profile == "team":
            report.pop("payload", None)
            continue
        for item in rows("SELECT * FROM autopsy_report_files WHERE report_id = ? ORDER BY format", (report["id"],)):
            content = cipher().decrypt(item["content"])
            if digest(content) != item["sha256"]:
                raise ValueError("بصمة ملف التقرير غير مطابقة")
            add_file(files, f"reports/{report['id']}/{item['format']}", content)
    for report in snapshot["tables"]["case_reports"]:
        content = report.pop("content").encode()
        if digest(content) != report["sha256"]:
            raise ValueError("بصمة التقرير المؤرشف غير مطابقة")
        if profile == "backup":
            add_file(files, f"legacy_reports/{report['id']}.txt", content)
    snapshot["policy"] = {
        "private_notes": "included" if profile == "backup" else "excluded",
        "sample_binaries": profile == "backup",
        "authentication": "SHA-256 validates integrity, not the external author's identity",
        "foreign_workflow": "Foreign approvals, actor identities and action outcomes are archived and require independent local review",
        "reports": "complete originals" if profile == "backup" else "metadata only; use authorized complete backup for original report contents",
    }
    add_file(files, "data.json", canonical(snapshot).encode())
    manifest = {
        "format": "socify-case-capsule",
        "version": 1,
        "profile": profile,
        "source_reference": case["reference"],
        "created_at": iso_now(),
        "members": [{"path": path, "size": len(content), "sha256": digest(content)} for path, content in sorted(files.items())],
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        archive.writestr("manifest.json", canonical(manifest).encode())
        for path, content in files.items():
            archive.writestr(path, content)
    if output.tell() > MAX_ARCHIVE:
        raise ValueError("تتجاوز الحزمة الحد المسموح")
    return output.getvalue()


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("مفتاح JSON مكرر")
        result[key] = value
    return result


def decode_json(content):
    if not isinstance(content, (str, bytes)):
        raise ValueError("JSON الحزمة يتطلب نصًا")
    try:
        value = json.loads(
            content, object_pairs_hook=object_pairs, parse_constant=lambda value: (_ for _ in ()).throw(ValueError("JSON numeric constant is invalid"))
        )
        validate_json_structure(value, max_nodes=MAX_ROWS * 100)
        canonical(value).encode()
        return value
    except (UnicodeError, RecursionError, json.JSONDecodeError, StructureLimitError) as exc:
        raise ValueError("JSON الحزمة غير صالح") from exc


def inspect_capsule(content):
    if not content or len(content) > MAX_ARCHIVE:
        raise ValueError("حجم الحزمة خارج النطاق")
    preflight_directory(content)
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            if not 2 <= len(entries) <= MAX_FILES or len(set(names)) != len(names) or "manifest.json" not in names:
                raise ValueError("فهرس الحزمة ناقص أو مكرر")
            if sum(entry.file_size for entry in entries) > MAX_EXPANDED:
                raise ValueError("حجم الحزمة بعد التوسيع يتجاوز الحد")
            for entry in entries:
                mode = entry.external_attr >> 16
                if entry.filename != "manifest.json" and not PATH.fullmatch(entry.filename):
                    raise ValueError("مسار ملف غير مسموح")
                if (
                    entry.is_dir()
                    or stat.S_ISLNK(mode)
                    or stat.S_IFMT(mode) not in {0, stat.S_IFREG}
                    or entry.flag_bits & 1
                    or entry.file_size > MAX_MEMBER
                    or entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    or entry.file_size > max(entry.compress_size, 1) * 1000
                ):
                    raise ValueError("خصائص ملف الحزمة غير مسموحة")
            manifest = decode_json(archive.read("manifest.json"))
            if (
                not isinstance(manifest, dict)
                or set(manifest) != {"format", "version", "profile", "source_reference", "created_at", "members"}
                or manifest["format"] != "socify-case-capsule"
                or type(manifest["version"]) is not int
                or manifest["version"] != 1
                or manifest["profile"] not in {"team", "backup"}
            ):
                raise ValueError("صيغة manifest غير مدعومة")
            if not isinstance(manifest["members"], list) or len(manifest["members"]) != len(entries) - 1:
                raise ValueError("فهرس manifest لا يطابق الملفات")
            files = {}
            for item in manifest["members"]:
                if (
                    not isinstance(item, dict)
                    or set(item) != {"path", "size", "sha256"}
                    or not isinstance(item["path"], str)
                    or not PATH.fullmatch(item["path"])
                    or item["path"] in files
                    or type(item["size"]) is not int
                    or not isinstance(item["sha256"], str)
                ):
                    raise ValueError("سجل manifest غير صالح")
                payload = archive.read(item["path"])
                if len(payload) != item["size"] or digest(payload) != item["sha256"]:
                    raise ValueError("بصمة ملف الحزمة أو حجمه غير مطابق")
                files[item["path"]] = payload
            if set(files) != set(names) - {"manifest.json"} or "data.json" not in files:
                raise ValueError("ملفات غير مفهرسة أو بيانات القضية مفقودة")
    except (zipfile.BadZipFile, zipfile.LargeZipFile, KeyError, TypeError, NotImplementedError, RuntimeError, OSError) as exc:
        raise ValueError("حزمة ZIP غير صالحة أو تالفة") from exc
    data = decode_json(files["data.json"])
    if (
        not isinstance(data, dict)
        or set(data)
        != {
            "case",
            "context",
            "tables",
            "revisions",
            "events",
            "event_links",
            "alerts",
            "alert_links",
            "alert_events",
            "actors",
            "imports",
            "import_errors",
            "samples",
            "policy",
        }
        or not isinstance(data["case"], dict)
        or not isinstance(data["context"], dict)
        or not isinstance(data["tables"], dict)
        or set(data["tables"]) != set(CASE_TABLES)
    ):
        raise ValueError("مخطط بيانات القضية غير مدعوم")
    for key in ("revisions", "events", "event_links", "alerts", "alert_links", "alert_events", "actors", "imports", "import_errors", "samples"):
        if not isinstance(data[key], list) or len(data[key]) > MAX_ROWS or any(not isinstance(row, dict) for row in data[key]):
            raise ValueError("قائمة بيانات القضية غير صالحة")
    for value in data["tables"].values():
        if not isinstance(value, list) or len(value) > MAX_ROWS or any(not isinstance(row, dict) for row in value):
            raise ValueError("جدول بيانات القضية غير صالح")
    for values in [data["events"], data["imports"], data["samples"], *data["tables"].values()]:
        identifiers = []
        for row in values:
            if "id" in row:
                identifier = row["id"]
                if type(identifier) is not int or not 1 <= identifier <= 2**63 - 1:
                    raise ValueError("معرف سجل الحزمة غير صالح")
                identifiers.append(identifier)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("معرف سجل الحزمة مكرر")
    for row in data["tables"]["autopsy_records"]:
        if not isinstance(row.get("kind"), str) or not isinstance(decode_json(row.get("payload")), dict):
            raise ValueError("مخطط إفادة الحزمة غير صالح")
    for row in data["revisions"]:
        if not isinstance(decode_json(row.get("payload")), dict):
            raise ValueError("مخطط إصدار الإفادة غير صالح")
    for row in data["tables"]["case_evidence"]:
        if not isinstance(row.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
            raise ValueError("بصمة الدليل غير صالحة")
    for row in data["events"]:
        for key, expected in (("normalized_fields", dict), ("tags", list), ("mitre_ids", list)):
            if not isinstance(decode_json(row.get(key, "{}" if expected is dict else "[]")), expected):
                raise ValueError("حقول السجل المطبع غير صالحة")
    text_value(manifest["source_reference"], 160, True)
    text_value(data["case"].get("title"), 255, True)
    for key in ("severity", "priority", "description"):
        if key in data["case"] and not isinstance(data["case"][key], str):
            raise ValueError("بيانات القضية غير صالحة")
    if manifest["profile"] == "team" and (
        any(row.get("visibility") == "private" for row in data["tables"]["case_notes"])
        or any(decode_json(row["payload"]).get("visibility") == "private" for row in data["tables"]["autopsy_records"])
        or any(decode_json(row.get("payload")).get("visibility") == "private" for row in data["revisions"])
        or any("payload" in row for row in data["tables"]["autopsy_reports"])
        or any(path.startswith(("samples/", "reports/", "legacy_reports/")) for path in files)
    ):
        raise ValueError("سياسة مشاركة الحزمة لا تطابق محتواها")
    event_ids = {row["id"] for row in data["events"]}
    if any(row.get("event_id") not in event_ids for row in data["event_links"]):
        raise ValueError("علاقة سجل الحزمة غير صالحة")
    for row in data["imports"]:
        if f"originals/{row['id']}.bin" not in files and row.get("raw_size", 0):
            raise ValueError("أصل استيراد مفقود")
    return manifest, data, files


def preflight_directory(content):
    if len(content) < 22:
        raise ValueError("فهرس ZIP مفقود")
    signature, disk, directory_disk, disk_count, total, size, offset, comment = struct.unpack_from("<4s4H2IH", content, len(content) - 22)
    if (
        signature != b"PK\x05\x06"
        or disk
        or directory_disk
        or disk_count != total
        or not 2 <= total <= MAX_FILES
        or comment
        or offset + size != len(content) - 22
    ):
        raise ValueError("تتطلب الحزمة فهرس ZIP32 واحدًا محدودًا بلا تعليق ختامي")
    cursor, count = offset, 0
    while cursor < offset + size:
        count += 1
        if count > MAX_FILES or cursor + 46 > offset + size or content[cursor : cursor + 4] != b"PK\x01\x02":
            raise ValueError("فهرس ZIP يتجاوز حدود الملفات أو يحتوي بيانات تالفة")
        name_size, extra_size, comment_size = struct.unpack_from("<3H", content, cursor + 28)
        cursor += 46 + name_size + extra_size + comment_size
        if not 1 <= name_size <= 200 or cursor > offset + size:
            raise ValueError("سجل فهرس ZIP خارج الحدود")
    if cursor != offset + size or count != total:
        raise ValueError("عدد ملفات فهرس ZIP غير متطابق")


def insert_values(table, values):
    columns = {row["name"] for row in get_db().execute(f"PRAGMA table_info({table})")}
    selected = {key: value for key, value in values.items() if key in columns}
    if any(not isinstance(value, (str, int, float, bytes, type(None))) for value in selected.values()):
        raise ValueError("قيمة جدول غير صالحة")
    return inserted_id(get_db().execute(f"INSERT INTO {table} ({','.join(selected)}) VALUES ({','.join('?' for _ in selected)})", tuple(selected.values())))


def restore_capsule(content, manifest, data, files):
    now, principal = iso_now(), actor_id()
    case = data["case"]
    case_id = insert_values(
        "incident_cases",
        {
            "reference": _reference(get_db()),
            "workspace_id": workspace_id(),
            "title": text_value(case["title"], 255, True),
            "description": text_value(case.get("description", ""), 10000),
            "case_type": "investigation",
            "severity": case.get("severity") if case.get("severity") in {"critical", "high", "medium", "low"} else "medium",
            "priority": case.get("priority") if case.get("priority") in {"urgent", "high", "medium", "low"} else "medium",
            "status": "open",
            "assignee": principal,
            "creator": principal,
            "created_at": now,
            "updated_at": now,
        },
    )
    source_context = data["context"]
    insert_values(
        "autopsy_case_context",
        {
            "case_id": case_id,
            "reason": "forensic_review",
            "objective": "مراجعة أدلة قضية مستوردة والتحقق من استنتاجاتها قبل اعتمادها محليًا",
            "classification": source_context.get("classification")
            if source_context.get("classification") in {"internal", "confidential", "restricted"}
            else "confidential",
            "created_at": now,
        },
    )
    insert_values("autopsy_case_members", {"case_id": case_id, "user_id": principal, "responsibility": "owner", "assigned_by": principal, "assigned_at": now})
    maps: dict[str, dict[str, int]] = {"events": {}, "imports": {}, "evidence": {}, "samples": {}}
    for source in data["imports"]:
        identifier = int(source["id"])
        path = f"originals/{identifier}.bin"
        if path not in files:
            continue
        payload = files[path]
        if digest(payload) != source.get("content_hash"):
            raise ValueError("بصمة أصل الاستيراد غير مطابقة")
        values = {
            key: value for key, value in source.items() if key not in {"id", "source_id", "training_run_id", "worker_id", "lease_expires_at", "available_at"}
        }
        values.update(
            case_id=case_id,
            workspace_id=workspace_id(),
            job_id="CAP-" + uuid.uuid4().hex,
            created_by=principal,
            executor_id=principal,
            evidence_ciphertext=encrypt_secret(base64.b64encode(payload).decode()),
            status="completed" if source.get("status") in {"completed", "completed_with_errors"} else "cancelled",
            autopsy_options=canonical({"capsule_source_job": identifier, "source_sha256": digest(content)}),
        )
        new_id = insert_values("ingestion_jobs", values)
        maps["imports"][str(identifier)] = new_id
        insert_values("autopsy_case_imports", {"case_id": case_id, "job_id": new_id, "attached_by": principal, "attached_at": now})
    for source in data["events"]:
        identifier = int(source["id"])
        values = {key: value for key, value in source.items() if key not in {"id", "training_run_id", "assigned_to"}}
        values.update(
            event_id="CAP-EVT-" + uuid.uuid4().hex,
            external_id=str(source.get("event_id", identifier)),
            idempotency_key=f"capsule:{case_id}:{identifier}",
            workspace_id=workspace_id(),
            owner_case_id=case_id,
            created_by=principal,
            provenance=canonical({"capsule_sha256": digest(content), "source_event_id": identifier, "source_provenance": source.get("provenance")}),
        )
        if source.get("import_job_id") is not None:
            mapped = maps["imports"].get(str(source["import_job_id"]))
            if mapped is None:
                raise ValueError("مرجع مصدر السجل غير موجود")
            values["import_job_id"] = mapped
        new_id = insert_values("security_events", values)
        maps["events"][str(identifier)] = new_id
        insert_values("case_events", {"case_id": case_id, "event_id": new_id, "attached_by": principal, "attached_at": now})
    for source in data["tables"]["case_evidence"]:
        identifier = int(source["id"])
        reference = str(source["reference_id"])
        if source["evidence_type"] == "event":
            if reference not in maps["events"]:
                raise ValueError("مرجع سجل الدليل مفقود")
            reference = str(maps["events"][reference])
        elif source["evidence_type"] == "import":
            if reference not in maps["imports"]:
                raise ValueError("مرجع أصل الدليل مفقود")
            reference = str(maps["imports"][reference])
        values = {
            "case_id": case_id,
            "evidence_type": text_value(source["evidence_type"], 100, True),
            "reference_id": reference,
            "title": text_value(source["title"], 255, True),
            "sha256": text_value(source["sha256"], 64, True),
            "provenance": canonical({"capsule_sha256": digest(content), "source_evidence_id": identifier, "source_provenance": source.get("provenance")}),
            "added_by": principal,
            "added_at": now,
        }
        new_id = insert_values("case_evidence", values)
        maps["evidence"][str(identifier)] = new_id
        path = f"evidence/{identifier}.txt"
        if path in files:
            if digest(files[path]) != source["sha256"]:
                raise ValueError("بصمة محتوى الدليل غير مطابقة")
            get_db().execute("INSERT INTO case_evidence_content(evidence_id, ciphertext) VALUES (?, ?)", (new_id, encrypt_secret(files[path].decode())))
    for source in data["samples"]:
        identifier = int(source["id"])
        path = f"samples/{identifier}.bin"
        if path not in files:
            continue
        evidence_id = maps["evidence"].get(str(source["evidence_id"]))
        if not evidence_id or digest(files[path]) != source["sha256"]:
            raise ValueError("دليل العينة أو بصمتها غير مطابق")
        new_id = insert_values(
            "autopsy_samples",
            {
                "case_id": case_id,
                "evidence_id": evidence_id,
                "filename": text_value(source["filename"], 255, True),
                "sha256": source["sha256"],
                "size": len(files[path]),
                "ciphertext": cipher().encrypt(files[path]),
                "created_by": principal,
                "created_at": now,
            },
        )
        maps["samples"][str(identifier)] = new_id
    identifier = inserted_id(
        get_db().execute(
            "INSERT INTO autopsy_capsule_archives(case_id, profile, source_reference, sha256, ciphertext, id_map, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (case_id, manifest["profile"], manifest["source_reference"], digest(content), cipher().encrypt(content), canonical(maps), principal, now),
        )
    )
    custody(
        case_id,
        "capsule_imported",
        {
            "capsule_id": identifier,
            "sha256": digest(content),
            "source_reference": manifest["source_reference"],
            "profile": manifest["profile"],
            "foreign_workflow": "immutable unverified archive; not approved or executed",
        },
    )
    return {"case_id": case_id, "capsule_id": identifier, "sha256": digest(content), "id_map": maps, "state": "open", "foreign_approvals_trusted": False}


@autopsy_capsules_api.get("/api/cases/<int:case_id>/capsule")
@require_permission("cases.export")
@require_permission("evidence.download")
def export_case_capsule(case_id: int):
    profile = request.args.get("profile", "team")
    if set(request.args) - {"profile"} or profile not in {"team", "backup"}:
        return error_response("INVALID_CAPSULE_PROFILE", "حدد مشاركة الفريق أو النسخ الاحتياطي الكامل", 422)
    if profile == "backup" and (not manager() or not has_permission(current_user(), "samples.download")):
        return error_response("PERMISSION_DENIED", "النسخة الكاملة تتطلب المدير وصلاحية تنزيل العينات", 403)
    with transaction():
        if not _case_row(case_id) or not full_case_access(case_id):
            return error_response("CASE_NOT_FOUND", "القضية أو بعض دفعاتها غير متاحة", 404)
        try:
            content = export_snapshot(case_id, profile)
        except (ValueError, InvalidToken) as exc:
            return error_response("CAPSULE_EXPORT_FAILED", str(exc), 422)
        custody(case_id, "capsule_exported", {"profile": profile, "sha256": digest(content), "bytes": len(content)})
    return Response(
        content,
        mimetype="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="SOCify-case-{case_id}-{profile}.zip"',
            "Cache-Control": "no-store",
            "X-Content-SHA256": digest(content),
            "Content-Security-Policy": "default-src 'none'; sandbox",
        },
    )


@autopsy_capsules_api.post("/api/cases/import-capsule")
@require_permission("cases.create")
@require_permission("evidence.add")
def import_case_capsule():
    request.max_content_length = MAX_ARCHIVE + 65536
    upload = request.files.get("file")
    if not upload or set(request.files) != {"file"} or request.form:
        return error_response("INVALID_CAPSULE", "أرفق ملف ZIP واحدًا في حقل file", 422)
    content = upload.stream.read(MAX_ARCHIVE + 1)
    try:
        manifest, data, files = inspect_capsule(content)
        if manifest["profile"] == "backup" and (not manager() or not has_permission(current_user(), "samples.download")):
            return error_response("PERMISSION_DENIED", "استيراد نسخة كاملة يتطلب المدير وصلاحية العينات", 403)
        with transaction():
            result = restore_capsule(content, manifest, data, files)
    except (ValueError, InvalidToken, sqlite3.IntegrityError, OverflowError, UnicodeError, KeyError, TypeError) as exc:
        return error_response("INVALID_CAPSULE", str(exc), 422)
    return jsonify(result), 201


def archive_access(case_id, archive_id):
    if not _case_row(case_id) or not full_case_access(case_id):
        return None
    row = get_db().execute("SELECT * FROM autopsy_capsule_archives WHERE id = ? AND case_id = ?", (archive_id, case_id)).fetchone()
    if row and row["profile"] == "backup" and (not manager() or not has_permission(current_user(), "samples.download")):
        return None
    return row


@autopsy_capsules_api.get("/api/cases/<int:case_id>/capsules")
@require_permission("cases.read")
def list_case_capsules(case_id: int):
    if not _case_row(case_id) or not full_case_access(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    scope = "" if manager() and has_permission(current_user(), "samples.download") else " AND profile = 'team'"
    found = (
        get_db()
        .execute(
            f"SELECT id, profile, source_reference, sha256, created_by, created_at FROM autopsy_capsule_archives WHERE case_id = ?{scope} ORDER BY id DESC LIMIT 100",
            (case_id,),
        )
        .fetchall()
    )
    return jsonify({"items": [dict(row) for row in found], "policy": "foreign historical archive; external actors and approvals are never local authority"})


@autopsy_capsules_api.get("/api/cases/<int:case_id>/capsules/<int:archive_id>/snapshot")
@require_permission("cases.read")
def capsule_snapshot(case_id: int, archive_id: int):
    row = archive_access(case_id, archive_id)
    if not row:
        return error_response("CAPSULE_NOT_FOUND", "الأرشيف غير متاح", 404)
    section = request.args.get("section", "case")
    try:
        page, limit = int(request.args.get("page", 1)), int(request.args.get("limit", 50))
        if not 1 <= page <= 1000000 or not 1 <= limit <= 100 or set(request.args) - {"section", "page", "limit"}:
            raise ValueError("الترقيم أو المرشح غير صالح")
        manifest, snapshot, _ = inspect_capsule(cipher().decrypt(row["ciphertext"]))
        if section == "manifest":
            value = manifest["members"]
        elif section in snapshot and section != "tables":
            value = snapshot[section]
        elif section in snapshot["tables"]:
            value = snapshot["tables"][section]
        else:
            raise ValueError("قسم الأرشيف غير معروف")
        items = value if isinstance(value, list) else [value]
        return jsonify(
            {
                "section": section,
                "items": items[(page - 1) * limit : page * limit],
                "total": len(items),
                "page": page,
                "limit": limit,
                "id_map": json.loads(row["id_map"]),
                "foreign_archive": True,
            }
        )
    except (ValueError, InvalidToken) as exc:
        return error_response("INVALID_CAPSULE_VIEW", str(exc), 422)


@autopsy_capsules_api.get("/api/cases/<int:case_id>/capsules/<int:archive_id>/file/<path:member>")
@require_permission("cases.read")
@require_permission("evidence.download")
def capsule_file(case_id: int, archive_id: int, member: str):
    row = archive_access(case_id, archive_id)
    if not row or not PATH.fullmatch(member):
        return error_response("CAPSULE_FILE_NOT_FOUND", "الملف غير متاح", 404)
    try:
        _, _, files = inspect_capsule(cipher().decrypt(row["ciphertext"]))
    except (ValueError, InvalidToken):
        return error_response("CAPSULE_INTEGRITY_FAILED", "الأرشيف غير سليم", 409)
    if member not in files:
        return error_response("CAPSULE_FILE_NOT_FOUND", "الملف غير متاح", 404)
    with transaction():
        custody(case_id, "capsule_member_downloaded", {"archive_id": archive_id, "member": member, "sha256": digest(files[member])})
    return Response(
        files[member],
        mimetype="application/octet-stream",
        headers={
            "Content-Disposition": 'attachment; filename="imported-capsule-evidence.bin"',
            "X-Content-SHA256": digest(files[member]),
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; sandbox",
        },
    )
