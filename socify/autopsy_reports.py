import hashlib
import json
from datetime import datetime
from typing import Any

from cryptography.fernet import InvalidToken
from flask import Blueprint, Response, jsonify, request

from .autopsy_api import case_summary, manager, record_view
from .autopsy_domain import canonical, custody, text_value
from .autopsy_report_render import FORMATS
from .cases import _case_row, _history
from .db import get_db, inserted_id, transaction
from .security import actor_id, cipher, current_user, error_response, has_permission, require_permission
from .timeutils import iso_now

autopsy_reports_api = Blueprint("autopsy_reports", __name__)
STATES = {
    "new": {"open", "triaged", "investigating", "cancelled"},
    "open": {"triaged", "investigating", "escalated", "cancelled"},
    "triaged": {"investigating", "escalated", "awaiting_review"},
    "investigating": {"contained", "escalated", "awaiting_review"},
    "escalated": {"investigating", "awaiting_review"},
    "contained": {"remediated", "recovered", "awaiting_review"},
    "remediated": {"recovered", "awaiting_review"},
    "recovered": {"awaiting_review"},
    "false_positive": {"awaiting_review", "reopened"},
    "awaiting_review": {"investigating", "closed"},
    "closed": {"reopened"},
    "reopened": {"investigating", "contained", "awaiting_review"},
    "cancelled": {"reopened"},
}


def bounded_rows(sql, args, maximum):
    rows = get_db().execute(sql + " LIMIT ?", (*args, maximum + 1)).fetchall()
    if len(rows) > maximum:
        raise ValueError("حجم التقرير تجاوز الحد؛ قلل العناصر المكررة أو استخدم تصدير السجلات المنفصل")
    return [dict(row) for row in rows]


def duration(start, end):
    try:
        seconds = (datetime.fromisoformat(end.replace("Z", "+00:00")) - datetime.fromisoformat(start.replace("Z", "+00:00"))).total_seconds()
        return seconds if seconds >= 0 else None
    except (TypeError, ValueError, AttributeError):
        return None


def case_metrics(records):
    responses = records.get("response", [])
    times = {}
    for phase in ("detection", "acknowledgement", "containment", "recovery"):
        candidates = [
            row["payload"].get("performed_at")
            for row in responses
            if row["payload"].get("phase") == phase and row["payload"].get("status") == "succeeded" and row["payload"].get("evidence_id")
        ]
        times[phase] = min((value for value in candidates if value), default=None)
    footholds = [row["payload"].get("first_observed_at") for row in records.get("foothold", []) if row["payload"].get("evidence_id")]
    first = min((value for value in footholds if value), default=None)
    return {
        "basis": "أوقات موثقة بدليل؛ أقدم نشاط مثبت لا يثبت بداية الهجوم الفعلية. ليست متوسطات MTTD/MTTR عبر قضايا متعددة.",
        "first_evidenced_activity": first,
        **times,
        "detection_delay_seconds": duration(first, times["detection"]),
        "acknowledgement_delay_seconds": duration(times["detection"], times["acknowledgement"]),
        "containment_delay_seconds": duration(times["detection"], times["containment"]),
        "recovery_delay_seconds": duration(times["detection"], times["recovery"]),
        "missing_or_inconsistent_times": "القيمة غير المسجلة تعني عدم إمكان الحساب، ولا تعني صفرًا",
    }


def build_snapshot(case, revision: int, profile: str):
    case_id = case["id"]
    case_fields = ("reference", "title", "status", "severity", "priority", "created_at", "closed_at", "version")
    payload = {
        "schema": "socify-report/1",
        "revision": revision,
        "source_version": case["version"],
        "generated_at": iso_now(),
        "profile": profile,
        "case": {key: case[key] for key in case_fields},
        "summary": {},
        "records": {},
    }
    context = (
        get_db()
        .execute(
            "SELECT reason, objective, classification, attack_outcome, alert_verdict, legal_hold, retention_until FROM autopsy_case_context WHERE case_id = ?",
            (case_id,),
        )
        .fetchone()
    )
    payload["context"] = dict(context) if context else {"reason": "قضية موروثة؛ راجع الهدف والنطاق قبل الاعتماد"}
    if profile == "full":
        payload["legacy_closure"] = {
            key: case[key]
            for key in ("disposition", "root_cause", "impact", "response_summary", "evidence_summary", "lessons_learned", "validation")
            if case[key]
        }
    counts = {
        name: get_db().execute(f"SELECT COUNT(*) FROM {table} WHERE case_id = ?", (case_id,)).fetchone()[0]
        for name, table in (("normalized_logs", "case_events"), ("evidence", "case_evidence"), ("alerts", "case_alerts"))
    }
    counts["historical_normalized_logs"] = counts["normalized_logs"]
    counts["normalized_logs"] = get_db().execute("SELECT COUNT(*) FROM case_events WHERE case_id=? AND active_event=1", (case_id,)).fetchone()[0]
    payload["summary"] = {
        "counts": counts,
        "classification": payload["context"].get("classification"),
        "attack_outcome": payload["context"].get("attack_outcome", "unknown"),
        "alert_verdict": payload["context"].get("alert_verdict", "undetermined"),
        "status_at_preparation": case["status"],
    }
    payload["limitations"] = [
        "المعالجة محلية دون إثراء شبكي. نتائج سمعة خارجية مستوردة لا تثبت إرسال المنصة أي بيانات.",
        "يعكس التقرير الأدلة المحفوظة ونطاق الفحص؛ غياب سجل أو تنبيه ليس دليلًا على غياب الاختراق.",
        "لا تُدرج الملاحظات الخاصة في التقرير. ملف السجلات الكامل منفصل عن فهرس الأدلة المهمّة.",
        "بصمات وسلسلة حيازة داخل قاعدة البيانات تكشف التعديل العرضي ولا تمنع مسؤول قاعدة بيانات مميزًا من العبث أو إعادة بناء السلسلة.",
    ]
    if profile == "metadata_only_v1":
        payload["case"]["title"] = "قضية منقحة للعرض الإحصائي"
        payload["context"] = {key: value for key, value in payload["context"].items() if key in {"classification", "attack_outcome", "alert_verdict"}}
        payload["limitations"].append("نسخة منقحة تقتصر على البيانات الإحصائية والحالة؛ لا تصلح وحدها لاعتماد إغلاق القضية.")
        return payload
    records = bounded_rows(
        "SELECT * FROM autopsy_records WHERE case_id = ? AND COALESCE(json_extract(payload, '$.visibility'), 'team') != 'private' ORDER BY id",
        (case_id,),
        2000,
    )
    for row in records:
        payload["records"].setdefault(row["kind"], []).append({key: value for key, value in record_view(row).items() if key != "case_id"})
    from .autopsy_workflow import factual_metrics, sla_status

    payload["metrics"] = factual_metrics(case, {kind: [row["payload"] for row in records] for kind, records in payload["records"].items()})
    payload["workflow"] = {
        "sla": sla_status(case),
        "collections": payload["records"].get("collection_request", []),
        "postmortems": payload["records"].get("postmortem", []),
    }
    payload["members"] = bounded_rows(
        "SELECT m.user_id, u.name, u.role, m.responsibility FROM autopsy_case_members m JOIN users u ON u.id = m.user_id WHERE m.case_id = ? ORDER BY m.user_id",
        (case_id,),
        200,
    )
    payload["evidence"] = bounded_rows(
        "SELECT id, evidence_type, title, sha256, added_by, added_at FROM case_evidence WHERE case_id = ? ORDER BY id", (case_id,), 2000
    )
    payload["imports"] = bounded_rows(
        "SELECT j.id, j.original_filename, j.filename, j.content_hash AS sha256, j.format, j.parser_version, j.status, j.accepted, j.rejected, j.autopsy_options, j.active_version, j.created_at FROM ingestion_jobs j JOIN autopsy_case_imports a ON a.job_id = j.id WHERE a.case_id = ? ORDER BY j.id",
        (case_id,),
        1000,
    )
    payload["alerts"] = bounded_rows(
        "SELECT a.id, r.name AS title, a.severity, a.status, a.reason, a.evidence, a.detected_at, review.payload AS review FROM alerts a JOIN rules r ON r.id = a.rule_id JOIN case_alerts c ON c.alert_id = a.id LEFT JOIN autopsy_alert_reviews review ON review.alert_id=a.id WHERE c.case_id = ? ORDER BY a.id",
        (case_id,),
        2000,
    )
    payload["observables"] = bounded_rows(
        "SELECT o.type,o.value,o.enrichment,(SELECT COUNT(*) FROM autopsy_observable_links l JOIN security_events e ON e.id=l.event_id WHERE l.observable_id=o.id AND e.autopsy_active=1) AS active_occurrences FROM autopsy_observables o WHERE o.case_id=? ORDER BY o.id",
        (case_id,),
        2000,
    )
    for observable in payload["observables"]:
        observable["enrichment"] = json.loads(observable["enrichment"])
    payload["tasks"] = bounded_rows(
        "SELECT id, title, assignee, status, required, completed_at FROM case_tasks WHERE case_id = ? ORDER BY id", (case_id,), 1000
    )
    payload["techniques"] = bounded_rows(
        "SELECT technique_id, attack_version, event_id, assessment, reason, created_by, created_at FROM case_technique_annotations WHERE case_id = ? ORDER BY id",
        (case_id,),
        1000,
    )
    payload["evidenced_timeline"] = bounded_rows(
        "SELECT e.id, e.title, e.event_time, e.source, e.event_type, e.severity, e.raw_hash, e.provenance, e.normalized_fields FROM security_events e JOIN case_evidence ce ON ce.case_id = ? AND ce.evidence_type = 'event' AND ce.reference_id = CAST(e.id AS TEXT) ORDER BY e.event_time, e.id",
        (case_id,),
        2000,
    )
    payload["shared_notes"] = bounded_rows(
        "SELECT author_id, body, created_at FROM case_notes WHERE case_id = ? AND visibility = 'team' ORDER BY id", (case_id,), 1000
    )
    payload["history"] = bounded_rows(
        "SELECT action, previous_value, new_value, reason, actor_id, created_at FROM case_history WHERE case_id = ? ORDER BY id", (case_id,), 3000
    )
    previous, valid, count = "0" * 64, True, 0
    for entry in get_db().execute("SELECT * FROM autopsy_custody WHERE case_id = ? ORDER BY id", (case_id,)):
        material = [case_id, entry["actor_id"], entry["action"], entry["details"], entry["previous_hash"], entry["created_at"]]
        valid = valid and entry["previous_hash"] == previous and hashlib.sha256(canonical(material).encode()).hexdigest() == entry["entry_hash"]
        previous, count = entry["entry_hash"], count + 1
    payload["custody"] = {"entries": count, "head_sha256": previous, "integrity_valid": valid}
    if len(canonical(payload).encode()) > 4 * 1024 * 1024:
        raise ValueError("حجم التقرير يتجاوز 4 MiB؛ استخدم حزمة القضية للأرشيف الكامل")
    return payload


@autopsy_reports_api.post("/api/cases/<int:case_id>/reports")
@require_permission("cases.read")
def create_report(case_id: int):
    data = request.get_json(silent=True)
    if (
        not isinstance(data, dict)
        or set(data) - {"version", "profile"}
        or type(data.get("version")) is not int
        or not isinstance(data.get("profile", "full"), str)
        or data.get("profile", "full") not in {"full", "metadata_only_v1"}
    ):
        return error_response("INVALID_REPORT", "حدد إصدار القضية وسياسة المشاركة", 422)
    profile = data.get("profile", "full")
    if profile == "full" and not has_permission(current_user(), "evidence.download"):
        return error_response("PERMISSION_DENIED", "التقرير الكامل يتطلب صلاحية تنزيل الأدلة", 403)
    with transaction():
        case = _case_row(case_id)
        if not case:
            return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
        if case["version"] != data["version"]:
            return error_response("CASE_VERSION_CONFLICT", "تغيرت القضية؛ حدّث قبل إعداد التقرير", 409)
        active = (
            get_db()
            .execute(
                "SELECT COUNT(*) FROM autopsy_jobs j JOIN incident_cases c ON c.id = j.case_id WHERE c.workspace_id = ? AND j.state IN ('queued', 'processing')",
                (case["workspace_id"],),
            )
            .fetchone()[0]
        )
        if active >= 20:
            return error_response("JOB_QUEUE_FULL", "طابور المعالجة ممتلئ؛ أعد المحاولة بعد انتهاء الأعمال الحالية", 429)
        revision = get_db().execute("SELECT COALESCE(MAX(revision), 0) + 1 FROM autopsy_reports WHERE case_id = ?", (case_id,)).fetchone()[0]
        try:
            payload = build_snapshot(case, revision, profile)
        except ValueError as exc:
            return error_response("REPORT_TOO_LARGE", str(exc), 422)
        serialized = canonical(payload)
        digest = hashlib.sha256(serialized.encode()).hexdigest()
        report_id = inserted_id(
            get_db().execute(
                "INSERT INTO autopsy_reports(case_id, revision, payload, sha256, source_version, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (case_id, revision, serialized, digest, case["version"], actor_id(), iso_now()),
            )
        )
        job_id = inserted_id(
            get_db().execute(
                "INSERT INTO autopsy_jobs(case_id, kind, parameters, created_by, created_at) VALUES (?, 'report', ?, ?, ?)",
                (case_id, canonical({"report_id": report_id}), actor_id(), iso_now()),
            )
        )
        custody(
            case_id,
            "report_snapshot_created",
            {"report_id": report_id, "revision": revision, "source_version": case["version"], "sha256": digest, "profile": profile},
        )
    return jsonify({"id": report_id, "job_id": job_id, "revision": revision, "sha256": digest, "state": "queued"}), 202


@autopsy_reports_api.get("/api/cases/<int:case_id>/reports/<int:report_id>")
@require_permission("cases.read")
def get_report(case_id: int, report_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    row = get_db().execute("SELECT * FROM autopsy_reports WHERE id = ? AND case_id = ?", (report_id, case_id)).fetchone()
    if not row:
        return error_response("REPORT_NOT_FOUND", "التقرير غير متاح", 404)
    result = {key: value for key, value in dict(row).items() if key != "payload"}
    result["formats"] = [item[0] for item in get_db().execute("SELECT format FROM autopsy_report_files WHERE report_id = ? ORDER BY format", (report_id,))]
    result["job"] = dict(
        get_db()
        .execute(
            "SELECT id, state, error_code, attempts FROM autopsy_jobs WHERE case_id = ? AND kind = 'report' AND json_extract(parameters, '$.report_id') = ? ORDER BY id DESC LIMIT 1",
            (case_id, report_id),
        )
        .fetchone()
        or {}
    )
    if has_permission(current_user(), "evidence.download") or has_permission(current_user(), "reports.approve"):
        result["payload"] = json.loads(row["payload"])
    return jsonify(result)


@autopsy_reports_api.get("/api/cases/<int:case_id>/reports/<int:report_id>/files/<report_format>")
@require_permission("cases.read")
def download_report(case_id: int, report_id: int, report_format: str):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    row = (
        get_db()
        .execute(
            "SELECT r.payload, f.* FROM autopsy_report_files f JOIN autopsy_reports r ON r.id = f.report_id WHERE r.id = ? AND r.case_id = ? AND f.format = ?",
            (report_id, case_id, report_format),
        )
        .fetchone()
    )
    if not row or report_format not in FORMATS:
        return error_response("REPORT_FILE_NOT_FOUND", "الملف غير متاح أو لم يجهز بعد", 404)
    if json.loads(row["payload"])["profile"] == "full" and not has_permission(current_user(), "evidence.download"):
        return error_response("PERMISSION_DENIED", "الملف الكامل يتطلب صلاحية تنزيل الأدلة", 403)
    try:
        content = cipher().decrypt(row["content"])
    except InvalidToken:
        return error_response("REPORT_INTEGRITY_FAILED", "تعذر فك الملف؛ تحقق من المفتاح وسلامة التخزين", 409)
    if hashlib.sha256(content).hexdigest() != row["sha256"]:
        return error_response("REPORT_INTEGRITY_FAILED", "بصمة الملف غير مطابقة؛ لا تستخدم النسخة", 409)
    with transaction():
        custody(case_id, "report_downloaded", {"report_id": report_id, "format": report_format, "sha256": row["sha256"]})
    response = Response(content, mimetype=FORMATS[report_format])
    response.headers["Content-Disposition"] = f'attachment; filename="SOCify-case-{case_id}-report-{report_id}.{report_format}"'
    response.headers["X-Content-SHA256"] = row["sha256"]
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; font-src data:; sandbox"
    return response


@autopsy_reports_api.post("/api/cases/<int:case_id>/reports/<int:report_id>/approve")
@require_permission("reports.approve")
def approve_report(case_id: int, report_id: int):
    data = request.get_json(silent=True)
    try:
        if not isinstance(data, dict) or set(data) - {"version", "override_reason"} or type(data.get("version")) is not int:
            raise ValueError("حدد إصدار القضية وسبب الاستثناء إن لزم")
        override = text_value(data.get("override_reason", ""), 1000)
    except ValueError as exc:
        return error_response("INVALID_REPORT_APPROVAL", str(exc), 422)
    with transaction():
        case = _case_row(case_id)
        if not case:
            return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
        row = get_db().execute("SELECT * FROM autopsy_reports WHERE id = ? AND case_id = ?", (report_id, case_id)).fetchone()
        if not row:
            return error_response("REPORT_NOT_FOUND", "التقرير غير متاح", 404)
        if case["version"] != data["version"] or row["source_version"] != case["version"] or row["state"] != "draft":
            return error_response("STALE_REPORT", "اعتمد مسودة جديدة تطابق إصدار القضية الحالي", 409)
        if json.loads(row["payload"])["profile"] != "full" or get_db().execute(
            "SELECT COUNT(*) FROM autopsy_report_files WHERE report_id = ?", (report_id,)
        ).fetchone()[0] != len(FORMATS):
            return error_response("REPORT_NOT_READY", "الاعتماد يتطلب تقريرًا كاملًا بجميع ملفاته", 409)
        if row["created_by"] == actor_id() and not (manager() and len(override) >= 10):
            return error_response("INDEPENDENT_REVIEW_REQUIRED", "يلزم مراجع آخر أو استثناء مدير مسبب لا يقل عن 10 أحرف", 403)
        get_db().execute("UPDATE autopsy_reports SET state = 'approved', approved_by = ?, approved_at = ? WHERE id = ?", (actor_id(), iso_now(), report_id))
        custody(
            case_id, "report_approved", {"report_id": report_id, "sha256": row["sha256"], "source_version": row["source_version"], "override_reason": override}
        )
    return jsonify({"id": report_id, "state": "approved", "sha256": row["sha256"]})


def closure_gaps(case_id: int, version: int):
    rows = get_db().execute("SELECT kind, payload FROM autopsy_records WHERE case_id = ?", (case_id,)).fetchall()
    records: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        records.setdefault(row["kind"], []).append(json.loads(row["payload"]))
    gaps = []
    if not get_db().execute("SELECT 1 FROM case_evidence WHERE case_id = ? LIMIT 1", (case_id,)).fetchone():
        gaps.append("أدلة محفوظة")
    if not records.get("root_cause"):
        gaps.append("تحليل سبب جذري أو توثيق عدم إمكان تحديده")
    if any(item.get("status") in {"raised", "acknowledged"} for item in records.get("escalation", [])):
        gaps.append("تصعيد لم تتم الاستجابة له")
    responses = records.get("response", [])
    if not any(item.get("phase") == "validation" and item.get("status") in {"succeeded", "not_applicable"} for item in responses):
        gaps.append("نتيجة التحقق من الاستجابة أو سبب عدم انطباقها")
    if any(step["required"] and step["status"] not in {"completed", "not_applicable"} for record in records.get("playbook", []) for step in record["steps"]):
        gaps.append("خطوات كتيب استجابة إلزامية")
    if (
        get_db()
        .execute("SELECT 1 FROM case_tasks WHERE case_id = ? AND required = 1 AND status NOT IN ('completed', 'reviewed') LIMIT 1", (case_id,))
        .fetchone()
    ):
        gaps.append("مهام إلزامية")
    if (
        get_db().execute("SELECT 1 FROM autopsy_jobs WHERE case_id = ? AND state IN ('queued', 'processing') LIMIT 1", (case_id,)).fetchone()
        or get_db()
        .execute("SELECT 1 FROM ingestion_jobs WHERE case_id = ? AND status IN ('queued', 'processing', 'interrupted') LIMIT 1", (case_id,))
        .fetchone()
    ):
        gaps.append("أعمال معالجة لم تنته")
    if (
        not get_db()
        .execute("SELECT 1 FROM autopsy_reports WHERE case_id = ? AND source_version = ? AND state = 'approved' LIMIT 1", (case_id, version))
        .fetchone()
    ):
        gaps.append("تقرير كامل معتمد مطابق لإصدار القضية الحالي")
    return gaps


def transition_operational(case_id, row, target, reason, data):
    if not isinstance(data, dict) or set(data) - {"status", "reason", "version"} or type(data.get("version")) is not int:
        return error_response("INVALID_TRANSITION", "حدد الحالة والسبب وإصدار القضية فقط", 422)
    try:
        reason = text_value(reason, 2000, True)
    except ValueError as exc:
        return error_response("INVALID_TRANSITION", str(exc), 422)
    if target not in STATES.get(row["status"], set()):
        return error_response("ILLEGAL_CASE_TRANSITION", "الانتقال غير متاح من الحالة الحالية", 409)
    if target == "closed" and not has_permission(current_user(), "cases.close"):
        return error_response("PERMISSION_DENIED", "إغلاق القضية يتطلب المدير", 403)
    with transaction():
        fresh = _case_row(case_id)
        if not fresh or fresh["version"] != data["version"] or row["version"] != data["version"]:
            return error_response("CASE_VERSION_CONFLICT", "تغيرت القضية؛ حدّث قبل الانتقال", 409)
        if target == "closed":
            gaps = closure_gaps(case_id, fresh["version"])
            if gaps:
                return error_response("CASE_CLOSURE_INCOMPLETE", "أكمل متطلبات الإغلاق", 409, {"missing": gaps})
        now = iso_now()
        get_db().execute(
            "UPDATE incident_cases SET status = ?, closed_at = ?, updated_at = ?, version = version + 1 WHERE id = ?",
            (target, now if target == "closed" else None, now, case_id),
        )
        _history(get_db(), case_id, "status_changed", fresh["status"], target, reason)
        custody(case_id, "case_transition", {"from": fresh["status"], "to": target, "reason": reason, "source_version": fresh["version"]})
    return case_summary(case_id)


@autopsy_reports_api.post("/api/cases/<int:case_id>/transitions")
@require_permission("cases.update")
def transition_case(case_id: int):
    case = _case_row(case_id)
    if not case:
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("status"), str):
        return error_response("INVALID_TRANSITION", "حدد الحالة والسبب والإصدار", 422)
    return transition_operational(case_id, case, data["status"], data.get("reason"), data)


@autopsy_reports_api.get("/api/cases/<int:case_id>/jobs/<int:job_id>")
@require_permission("cases.read")
def get_job(case_id: int, job_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    row = (
        get_db()
        .execute(
            "SELECT id, kind, state, error_code, attempts, created_by, created_at, started_at, completed_at FROM autopsy_jobs WHERE id = ? AND case_id = ?",
            (job_id, case_id),
        )
        .fetchone()
    )
    if not row:
        return error_response("JOB_NOT_FOUND", "العمل غير متاح", 404)
    return jsonify(dict(row))


@autopsy_reports_api.post("/api/cases/<int:case_id>/jobs/<int:job_id>/<action>")
@require_permission("cases.read")
def job_action(case_id: int, job_id: int, action: str):
    if action not in {"cancel", "retry"}:
        return error_response("JOB_ACTION_NOT_FOUND", "الإجراء غير متاح", 404)
    with transaction():
        if not _case_row(case_id):
            return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
        job = get_db().execute("SELECT * FROM autopsy_jobs WHERE id = ? AND case_id = ?", (job_id, case_id)).fetchone()
        if not job:
            return error_response("JOB_NOT_FOUND", "العمل غير متاح", 404)
        if job["created_by"] != actor_id() and not manager():
            return error_response("PERMISSION_DENIED", "التحكم بالعمل لمؤلفه أو المدير", 403)
        if action == "cancel":
            if job["state"] not in {"queued", "processing"}:
                return error_response("JOB_STATE_CONFLICT", "العمل ليس قيد التنفيذ", 409)
            get_db().execute(
                "UPDATE autopsy_jobs SET state = 'cancelled', completed_at = ?, worker_id = NULL, lease_expires_at = NULL WHERE id = ?", (iso_now(), job_id)
            )
        else:
            if job["state"] not in {"failed", "cancelled"} or job["attempts"] >= 3:
                return error_response("JOB_STATE_CONFLICT", "أعد إعداد تقرير جديد بعد مراجعة سبب الفشل", 409)
            get_db().execute("UPDATE autopsy_jobs SET state = 'queued', error_code = NULL, completed_at = NULL WHERE id = ?", (job_id,))
        custody(case_id, "job_" + action, {"job_id": job_id, "kind": job["kind"]})
    return jsonify({"id": job_id, "state": "cancelled" if action == "cancel" else "queued"})
