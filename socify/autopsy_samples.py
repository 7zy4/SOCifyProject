import hashlib
import json
from datetime import UTC, datetime

from cryptography.fernet import InvalidToken
from flask import Blueprint, Response, current_app, jsonify, request

from .autopsy_api import insert_record
from .autopsy_domain import canonical, custody, text_value
from .cases import _case_row
from .db import get_db, inserted_id, transaction
from .security import actor_id, cipher, encrypt_secret, error_response, require_permission
from .timeutils import iso_now

autopsy_samples_api = Blueprint("autopsy_samples", __name__)


@autopsy_samples_api.get("/api/cases/<int:case_id>/samples")
@require_permission("cases.read")
def list_samples(case_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    rows = (
        get_db()
        .execute(
            "SELECT id, evidence_id, filename, sha256, size, created_by, created_at FROM autopsy_samples WHERE case_id = ? ORDER BY id DESC LIMIT 200",
            (case_id,),
        )
        .fetchall()
    )
    return jsonify({"items": [dict(row) for row in rows], "policy": "quarantined; never executed"})


@autopsy_samples_api.post("/api/cases/<int:case_id>/samples")
@require_permission("evidence.add")
def upload_sample(case_id: int):
    upload = request.files.get("file")
    try:
        if not upload or set(request.files) != {"file"} or request.form:
            raise ValueError("أرفق العينة فقط في حقل file")
        name = text_value(upload.filename, 255, True)
        if any(char in name for char in ("/", "\\")):
            raise ValueError("أرسل اسم ملف دون مسار")
        maximum = min(int(current_app.config["MAX_CONTENT_LENGTH"]), 10 * 1024 * 1024)
        content = upload.stream.read(maximum + 1)
        if not content or len(content) > maximum:
            raise ValueError("العينة فارغة أو تتجاوز الحد المسموح")
    except ValueError as exc:
        return error_response("INVALID_SAMPLE", str(exc), 422)
    digest = hashlib.sha256(content).hexdigest()
    with transaction():
        case = _case_row(case_id)
        if not case:
            return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
        if case["status"] == "closed":
            return error_response("CASE_CLOSED", "أعد فتح القضية قبل إضافة عينة", 409)
        duplicate = get_db().execute("SELECT id FROM autopsy_samples WHERE case_id = ? AND sha256 = ?", (case_id, digest)).fetchone()
        if duplicate:
            return jsonify({"id": duplicate["id"], "duplicate": True, "sha256": digest})
        evidence = inserted_id(
            get_db().execute(
                "INSERT INTO case_evidence(case_id, evidence_type, reference_id, title, sha256, provenance, added_by, added_at) VALUES (?, 'quarantined_sample', ?, ?, ?, ?, ?, ?)",
                (
                    case_id,
                    digest,
                    name,
                    digest,
                    canonical({"source": "manual_sample_upload", "bytes": len(content), "download_route": "samples"}),
                    actor_id(),
                    iso_now(),
                ),
            )
        )
        identifier = inserted_id(
            get_db().execute(
                "INSERT INTO autopsy_samples(case_id, evidence_id, filename, sha256, size, ciphertext, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (case_id, evidence, name, digest, len(content), cipher().encrypt(content), actor_id(), iso_now()),
            )
        )
        custody(case_id, "sample_quarantined", {"sample_id": identifier, "evidence_id": evidence, "sha256": digest, "bytes": len(content)})
    return jsonify({"id": identifier, "evidence_id": evidence, "sha256": digest, "size": len(content), "quarantined": True}), 201


@autopsy_samples_api.get("/api/cases/<int:case_id>/samples/<int:sample_id>/download")
@require_permission("samples.download")
def download_sample(case_id: int, sample_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    row = get_db().execute("SELECT * FROM autopsy_samples WHERE case_id = ? AND id = ?", (case_id, sample_id)).fetchone()
    if not row:
        return error_response("SAMPLE_NOT_FOUND", "العينة غير متاحة", 404)
    try:
        content = cipher().decrypt(row["ciphertext"])
        if hashlib.sha256(content).hexdigest() != row["sha256"]:
            raise ValueError("Sample digest mismatch")
    except (InvalidToken, ValueError):
        return error_response("SAMPLE_INTEGRITY_FAILED", "تعذر التحقق من سلامة العينة", 409)
    with transaction():
        custody(case_id, "sample_downloaded", {"sample_id": sample_id, "sha256": row["sha256"]})
    return Response(
        content,
        mimetype="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="quarantined-{sample_id}.bin"',
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "X-Content-SHA256": row["sha256"],
            "Cache-Control": "no-store",
            "X-SOCify-Quarantined": "true",
        },
    )


@autopsy_samples_api.post("/api/cases/<int:case_id>/samples/<int:sample_id>/analyze")
@require_permission("cases.update")
def queue_analysis(case_id: int, sample_id: int):
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or data:
        return error_response("INVALID_ANALYSIS", "التحليل يستخدم سياسة وقواعد محلية ثابتة؛ أرسل كائنًا فارغًا", 422)
    with transaction():
        case = _case_row(case_id)
        if not case:
            return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
        if case["status"] == "closed":
            return error_response("CASE_CLOSED", "القضية مغلقة", 409)
        sample = get_db().execute("SELECT id FROM autopsy_samples WHERE case_id = ? AND id = ?", (case_id, sample_id)).fetchone()
        if not sample:
            return error_response("SAMPLE_NOT_FOUND", "العينة غير متاحة", 404)
        prior = (
            get_db()
            .execute(
                "SELECT id FROM autopsy_jobs WHERE case_id = ? AND kind = 'sample' AND json_extract(parameters, '$.sample_id') = ? AND state IN ('queued', 'processing')",
                (case_id, sample_id),
            )
            .fetchone()
        )
        if prior:
            return jsonify({"id": prior["id"], "duplicate": True})
        active = (
            get_db()
            .execute(
                "SELECT COUNT(*) FROM autopsy_jobs j JOIN incident_cases c ON c.id = j.case_id WHERE c.workspace_id = ? AND j.state IN ('queued', 'processing')",
                (case["workspace_id"],),
            )
            .fetchone()[0]
        )
        if active >= 20:
            return error_response("JOB_QUEUE_FULL", "طابور التحليل ممتلئ", 429)
        identifier = inserted_id(
            get_db().execute(
                "INSERT INTO autopsy_jobs(case_id, kind, parameters, created_by, created_at) VALUES (?, 'sample', ?, ?, ?)",
                (case_id, canonical({"sample_id": sample_id}), actor_id(), iso_now()),
            )
        )
        custody(case_id, "sample_analysis_queued", {"job_id": identifier, "sample_id": sample_id})
    return jsonify({"id": identifier, "state": "queued"}), 202


def parse_vt_report(content, expected_hash):
    if not content or len(content) > 1024 * 1024:
        raise ValueError("تقرير VirusTotal فارغ أو يتجاوز 1 MiB")
    try:
        document = json.loads(content)
        data = document["data"]
        attributes = data["attributes"]
        if not isinstance(data, dict) or data.get("type") != "file" or not isinstance(attributes, dict):
            raise ValueError("استخدم JSON لنتيجة ملف VirusTotal v3")
        actual = attributes.get("sha256")
        if not isinstance(actual, str) or actual.lower() != expected_hash or data.get("id", actual).lower() != expected_hash:
            raise ValueError("بصمة التقرير لا تطابق العينة أو المؤشر المحدد")
        stats = attributes["last_analysis_stats"]
        keys = {"harmless", "type-unsupported", "suspicious", "confirmed-timeout", "timeout", "failure", "malicious", "undetected"}
        if not isinstance(stats, dict) or not stats or set(stats) - keys or any(type(value) is not int or not 0 <= value <= 10000 for value in stats.values()):
            raise ValueError("إحصاءات الفحص غير صالحة")
        stamp = attributes["last_analysis_date"]
        if type(stamp) is not int or stamp < 0:
            raise ValueError("توقيت الفحص غير صالح")
        examined = datetime.fromtimestamp(stamp, UTC).isoformat().replace("+00:00", "Z")
        engines = attributes.get("last_analysis_results", {})
        if not isinstance(engines, dict) or len(engines) > 300:
            raise ValueError("عدد محركات الفحص غير صالح")
        results = []
        for name, item in engines.items():
            if not isinstance(item, dict) or item.get("category") not in keys:
                raise ValueError("نتيجة محرك الفحص غير صالحة")
            results.append({"engine": text_value(name, 160, True), "category": item["category"], "result": text_value(item.get("result") or "", 1000)})
    except (KeyError, TypeError, AttributeError, OverflowError, OSError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("مخطط تقرير VirusTotal غير صالح") from exc
    return {
        "source": "VirusTotal v3 manual import",
        "sha256": expected_hash,
        "examined_at": examined,
        "stats": stats,
        "engines": results,
        "authenticity": "unverified external report; manually supplied",
        "network": "No data, hash, file or request sent to VirusTotal",
        "limitations": "تقرير مستورد غير متحقق التوقيع، يعكس وقت الفحص المذكور ولا يثبت سلامة الملف أو صحة جميع النتائج",
    }


@autopsy_samples_api.post("/api/cases/<int:case_id>/reputation/virustotal")
@require_permission("cases.update")
def import_virustotal(case_id: int):
    upload = request.files.get("file")
    try:
        if not upload or set(request.files) != {"file"} or set(request.form) not in ({"sample_id"}, {"indicator_id"}):
            raise ValueError("حدد عينة أو مؤشر SHA-256 وأرفق تقرير JSON فقط")
        field = next(iter(request.form))
        raw_id = request.form[field]
        if not raw_id.isascii() or not raw_id.isdigit() or not 1 <= int(raw_id) <= 2**63 - 1:
            raise ValueError("معرف العينة أو المؤشر غير صالح")
        content = upload.stream.read(1024 * 1024 + 1)
        with transaction():
            case = _case_row(case_id)
            if not case:
                return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
            if case["status"] == "closed":
                return error_response("CASE_CLOSED", "القضية مغلقة", 409)
            if field == "sample_id":
                row = get_db().execute("SELECT sha256, evidence_id FROM autopsy_samples WHERE case_id = ? AND id = ?", (case_id, int(raw_id))).fetchone()
            else:
                row = (
                    get_db()
                    .execute(
                        "SELECT json_extract(payload, '$.value') AS sha256, json_extract(payload, '$.evidence_id') AS evidence_id FROM autopsy_records WHERE case_id = ? AND id = ? AND kind = 'indicator' AND json_extract(payload, '$.type') = 'sha256'",
                        (case_id, int(raw_id)),
                    )
                    .fetchone()
                )
            if not row:
                raise ValueError("العينة أو مؤشر SHA-256 غير متاح في القضية")
            payload = parse_vt_report(content, row["sha256"])
            source_sha = hashlib.sha256(content).hexdigest()
            prior = (
                get_db()
                .execute(
                    "SELECT id FROM autopsy_records WHERE case_id = ? AND kind = 'reputation' AND json_extract(payload, '$.source_sha256') = ?",
                    (case_id, source_sha),
                )
                .fetchone()
            )
            if prior:
                return jsonify({"id": prior["id"], "duplicate": True})
            evidence_id = inserted_id(
                get_db().execute(
                    "INSERT INTO case_evidence(case_id, evidence_type, reference_id, title, sha256, provenance, added_by, added_at) VALUES (?, 'reputation_report', ?, ?, ?, ?, ?, ?)",
                    (
                        case_id,
                        f"vt:{source_sha}",
                        "Manually imported VirusTotal file report",
                        source_sha,
                        canonical({"source": "manual VirusTotal JSON", "subject_sha256": row["sha256"]}),
                        actor_id(),
                        iso_now(),
                    ),
                )
            )
            get_db().execute("INSERT INTO case_evidence_content(evidence_id, ciphertext) VALUES (?, ?)", (evidence_id, encrypt_secret(content.decode("utf-8"))))
            payload.update({field: int(raw_id), "evidence_id": evidence_id, "source_sha256": source_sha, "imported_at": iso_now(), "imported_by": actor_id()})
            record = insert_record(case_id, "reputation", payload)
    except (ValueError, UnicodeError) as exc:
        return error_response("INVALID_REPUTATION_REPORT", str(exc), 422)
    return jsonify({"id": record, "payload": payload}), 201
