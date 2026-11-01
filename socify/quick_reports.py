import html
import json
import sqlite3
from typing import Any

from flask import Blueprint, Response, jsonify, request

from .audit import record_audit
from .autopsy_domain import custody, touch_case
from .cases import _case_row
from .db import get_db, transaction
from .security import actor_id, current_user, error_response, has_permission, require_permission, workspace_id
from .timeutils import iso_now

quick_reports_api = Blueprint("quick_reports", __name__)

QUICK_REPORT_QUESTIONS: list[dict[str, Any]] = [
    {
        "id": "incident_classification",
        "label": "1. تصنيف الحادثة (Incident Classification)",
        "default": "phishing_bec",
        "options": [
            {"value": "phishing_bec", "label": "تصيد احتيالي / انتحال بريد (Phishing / BEC)"},
            {"value": "malware_execution", "label": "برمجية خبيثة / ملف مشبوه (Malware / Suspicious File)"},
            {"value": "unauthorized_access", "label": "وصول غير مصرح / تخمين كلمات مرور (Unauthorized Access / Brute Force)"},
            {"value": "web_application_attack", "label": "هجوم على تطبيق ويب / استغلال ثغرة (Web Attack / Exploitation)"},
            {"value": "ransomware_sabotage", "label": "فدية / تخريب أو مسح سجلات (Ransomware / Log Tampering)"},
            {"value": "data_exfiltration", "label": "تسريب بيانات أو اتصال C2 مشبوه (Data Exfiltration / C2)"},
            {"value": "policy_violation_recon", "label": "استطلاع شبكي / مخالفة سياسة أمنية (Reconnaissance / Policy Violation)"},
            {"value": "benign_activity", "label": "نشاط تشغيلي سليم / فحص مصرح (Authorized / Benign Activity)"},
        ],
    },
    {
        "id": "initial_vector",
        "label": "2. مدخل الهجوم أو مصدر التنبيه (Initial Vector & Source)",
        "default": "siem_builtin_rule",
        "options": [
            {"value": "email_attachment_or_link", "label": "مرفق أو رابط في بريد إلكتروني (Email Attachment / Link)"},
            {"value": "siem_builtin_rule", "label": "تنبيه قواعد SIEM المدمجة (Built-in SIEM Detection Rule)"},
            {"value": "watchlist_ioc_match", "label": "تطابق مع قائمة مراقبة IPs/الإيميلات المشبوهة (Watchlist IOC Match)"},
            {"value": "external_web_endpoint", "label": "واجهة ويب أو خدمة مواجهة للإنترنت (Public Web / API Endpoint)"},
            {"value": "endpoint_process_activity", "label": "نشاط مشبوه على جهاز طرفي أو خادم (Endpoint / Server Process)"},
            {"value": "identity_vpn_login", "label": "تسجيل دخول هوية أو VPN (Identity / VPN Authentication)"},
            {"value": "ctf_or_offline_log_pack", "label": "حزمة سجلات خارجية / فرز سريع خارج الدوام (Offline Log Pack / Rapid Triage)"},
        ],
    },
    {
        "id": "triage_verdict",
        "label": "3. حكم الفرز والتحقيق الأولي (Triage Determination)",
        "default": "suspicious_needs_deep_forensics",
        "options": [
            {"value": "confirmed_true_positive", "label": "حادثة أمنية مؤكدة (Confirmed True Positive)"},
            {"value": "suspicious_needs_deep_forensics", "label": "اشتباه مرتفع يتطلب أدوات جنائية ثقيلة (Suspicious — Needs Deep Forensics)"},
            {"value": "benign_true_positive", "label": "تنبيه صحيح لنشاط مصرح به (Benign True Positive / Authorized)"},
            {"value": "false_positive", "label": "إنذار كاذب / ضجيج قاعدة (False Positive)"},
        ],
    },
    {
        "id": "impact_scope",
        "label": "4. نطاق التأثير المرصود (Observed Impact Scope)",
        "default": "single_user_or_host",
        "options": [
            {"value": "no_compromise_blocked", "label": "لم يحدث اختراق — تم الرصد أو الإحباط مبكرًا (Blocked / No Compromise)"},
            {"value": "single_user_or_host", "label": "محصور في مستخدم واحد أو جهاز واحد (Single User / Host)"},
            {"value": "multiple_hosts_or_accounts", "label": "ممتد لعدة أجهزة أو حسابات داخلية (Multiple Hosts / Accounts)"},
            {"value": "critical_server_or_domain", "label": "يمس خادمًا حساسًا أو البنية التحتية للهوية (Critical Server / Identity Infra)"},
            {"value": "scope_under_assessment", "label": "قيد الحصر الميداني الأولي (Scope Under Assessment)"},
        ],
    },
    {
        "id": "data_exposure",
        "label": "5. تأثر البيانات الحساسة (Sensitive Data Exposure)",
        "default": "none_observed",
        "options": [
            {"value": "none_observed", "label": "لا توجد مؤشرات تسريب بيانات (No Exposure Observed)"},
            {"value": "credentials_at_risk", "label": "احتمالية انكشاف بيانات اعتماد تتطلب التدوير (Credentials at Risk)"},
            {"value": "internal_business_data", "label": "وصول محتمل لبيانات عمل داخلية (Internal Data Accessed)"},
            {"value": "confirmed_exfiltration", "label": "مؤشرات تسريب بيانات خارج الشبكة (Confirmed Exfiltration Indicators)"},
            {"value": "not_applicable", "label": "غير منطبق على طبيعة التنبيه (Not Applicable)"},
        ],
    },
    {
        "id": "file_and_email_assessment",
        "label": "6. نتيجة الفحص الساكن للملفات والبريد (File & Email Static Assessment)",
        "default": "no_files_involved",
        "options": [
            {"value": "malicious_artifact_identified", "label": "رُصد ملف/مرفق خبيث أو متنكر بالفحص الساكن (Malicious / Disguised Artifact)"},
            {"value": "suspicious_headers_or_links", "label": "انتحال مرسل أو روابط تصيد مشبوهة في البريد (Spoofed Headers / Phishing URLs)"},
            {"value": "static_clean_needs_sandbox", "label": "الفحص الساكن منخفض الإشارة ويتطلب Sandbox معزول (Needs Dynamic Sandbox)"},
            {"value": "no_files_involved", "label": "لا يتضمن التحقيق ملفات أو رسائل بريد (No Files / Emails Involved)"},
        ],
    },
    {
        "id": "containment_status",
        "label": "7. إجراء الاحتواء المنفذ (Containment Action Taken)",
        "default": "indicators_added_to_watchlist_and_block",
        "options": [
            {"value": "indicators_added_to_watchlist_and_block", "label": "أُضيفت المؤشرات لقائمة المراقبة وأوصي بالحظر الفوري (Watchlisted & Block Requested)"},
            {"value": "host_isolated_or_account_disabled", "label": "تم عزل الجهاز أو تجميد الحساب المتأثر (Host Isolated / Account Disabled)"},
            {"value": "monitoring_enhanced", "label": "تعزيز المراقبة دون حاجة لعزل فوري (Enhanced Monitoring)"},
            {"value": "pending_manager_authorization", "label": "بانتظار توجيه واعتماد مدير مركز العمليات (Pending SOC Manager Approval)"},
            {"value": "no_action_needed", "label": "لا يلزم إجراء احتواء (No Containment Needed)"},
        ],
    },
    {
        "id": "recommended_next_step",
        "label": "8. التوصية والخطوة التالية (Recommended Next Step)",
        "default": "block_iocs_and_reset_credentials",
        "options": [
            {"value": "escalate_ir_deep_dive", "label": "تصعيد لفريق الاستجابة للحوادث للتحليل الجنائي العميق (Escalate to Deep DFIR)"},
            {"value": "block_iocs_and_reset_credentials", "label": "حظر المؤشرات المشبوهة وإعادة تعيين كلمات المرور (Block IOCs & Reset Credentials)"},
            {"value": "tune_detection_rule", "label": "ضبط قاعدة الكشف لتقليل الضجيج (Tune Detection Rule)"},
            {"value": "close_after_manager_review", "label": "إغلاق القضية بعد مراجعة واعتماد المدير (Close After Manager Review)"},
        ],
    },
    {
        "id": "urgency_level",
        "label": "9. مستوى الاستعجال للتصعيد الإداري (Manager Escalation Urgency)",
        "default": "high_p2",
        "options": [
            {"value": "immediate_p1", "label": "فوري وحرج (P1 — Immediate Executive Action)"},
            {"value": "high_p2", "label": "عالٍ خلال المناوبة الحالية (P2 — High Shift Priority)"},
            {"value": "routine_p3", "label": "اعتيادي للمراجعة والتوثيق (P3 — Routine Manager Review)"},
            {"value": "informational_p4", "label": "إحاطة علم وإغلاق (P4 — Informational)"},
        ],
    },
]

QUESTION_OPTION_MAP: dict[str, dict[str, str]] = {q["id"]: {opt["value"]: opt["label"] for opt in q["options"]} for q in QUICK_REPORT_QUESTIONS}
DEFAULT_ANSWERS: dict[str, str] = {q["id"]: q["default"] for q in QUICK_REPORT_QUESTIONS}
MANAGER_DECISIONS = {"approved", "needs_followup", "closed"}


def migrate(connection: sqlite3.Connection) -> None:
    connection.execute(
        """CREATE TABLE IF NOT EXISTS case_quick_reports (
            case_id INTEGER PRIMARY KEY REFERENCES incident_cases(id),
            workspace_id INTEGER NOT NULL REFERENCES training_workspaces(id),
            answers_json TEXT NOT NULL CHECK(json_valid(answers_json)),
            executive_note TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft', 'escalated', 'acknowledged')),
            prepared_by INTEGER NOT NULL REFERENCES users(id),
            escalated_by INTEGER REFERENCES users(id),
            escalated_at TEXT,
            acknowledged_by INTEGER REFERENCES users(id),
            acknowledged_at TEXT,
            manager_decision TEXT,
            manager_comment TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )"""
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_quick_reports_ws_status ON case_quick_reports(workspace_id, status, escalated_at DESC)")


def _validate_answers(raw_answers: object) -> dict[str, str]:
    if not isinstance(raw_answers, dict) or not raw_answers:
        raise ValueError("اختر الإجابات من القوائم المنسدلة المعتمدة")
    unknown_keys = set(raw_answers) - set(QUESTION_OPTION_MAP)
    if unknown_keys:
        raise ValueError(f"أسئلة غير معروفة في التقرير: {', '.join(sorted(unknown_keys))}")
    validated: dict[str, str] = {}
    for q in QUICK_REPORT_QUESTIONS:
        qid = q["id"]
        val = raw_answers.get(qid)
        if not isinstance(val, str) or val not in QUESTION_OPTION_MAP[qid]:
            raise ValueError(f"قيمة غير معتمدة للسؤال {qid}؛ يجب الاختيار من القائمة المنسدلة فقط")
        validated[qid] = val
    return validated


def _is_manager_user() -> bool:
    user = current_user()
    if not user:
        return False
    return has_permission(user, "team.manage") or str(user.get("role") or "") in {"admin", "soc_manager", "team_admin"}


def _report_view(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    answers = json.loads(row["answers_json"])
    resolved_qa = [
        {
            "id": q["id"],
            "question": q["label"],
            "answer_value": answers.get(q["id"], q["default"]),
            "answer_label": QUESTION_OPTION_MAP[q["id"]].get(answers.get(q["id"], ""), "—"),
        }
        for q in QUICK_REPORT_QUESTIONS
    ]
    return {
        "case_id": row["case_id"],
        "status": row["status"],
        "answers": answers,
        "resolved_questions": resolved_qa,
        "executive_note": row["executive_note"],
        "prepared_by": row["prepared_by"],
        "escalated_by": row["escalated_by"],
        "escalated_at": row["escalated_at"],
        "acknowledged_by": row["acknowledged_by"],
        "acknowledged_at": row["acknowledged_at"],
        "manager_decision": row["manager_decision"],
        "manager_comment": row["manager_comment"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "print_url": f"/cases/{row['case_id']}/quick-report/print",
    }


def _collect_case_auto_summary(case_row: sqlite3.Row) -> dict[str, Any]:
    case_id = int(case_row["id"])
    db = get_db()
    owner_row = db.execute("SELECT COALESCE(name, email) AS name, role FROM users WHERE id = ?", (case_row["assignee"] or case_row["creator"],)).fetchone()
    logs_count = int(db.execute("SELECT COUNT(*) FROM case_events WHERE case_id = ? AND active_event = 1", (case_id,)).fetchone()[0])
    alerts_rows = db.execute(
        """SELECT a.id, a.alert_id, a.severity, a.reason, a.status, a.detected_at
           FROM case_alerts ca
           JOIN alerts a ON a.id = ca.alert_id
           WHERE ca.case_id = ?
           ORDER BY a.id DESC LIMIT 20""",
        (case_id,),
    ).fetchall()
    alerts_total = int(db.execute("SELECT COUNT(*) FROM case_alerts WHERE case_id = ?", (case_id,)).fetchone()[0])

    analysis_rows = db.execute(
        "SELECT id, payload, created_at FROM autopsy_records WHERE case_id = ? AND kind = 'analysis' ORDER BY id DESC LIMIT 20",
        (case_id,),
    ).fetchall()
    static_items: list[dict[str, Any]] = []
    for a_row in analysis_rows:
        p = json.loads(a_row["payload"])
        method = p.get("method") or p.get("engine") or "static_analysis"
        if method == "v6_email_static_triage":
            static_items.append(
                {
                    "id": a_row["id"],
                    "kind": "email",
                    "name": p.get("title") or "Email (.eml)",
                    "sha256": p.get("sha256") or "",
                    "verdict": p.get("email_verdict") or "reviewed",
                    "risk_score": p.get("email_risk_score", 0),
                    "detail": f"From: {p.get('sender_email') or '—'} | Attachments: {len(p.get('attachments') or [])}",
                }
            )
        else:
            static_items.append(
                {
                    "id": a_row["id"],
                    "kind": "file",
                    "name": p.get("filename") or p.get("title") or f"Sample #{p.get('sample_id', '')}",
                    "sha256": p.get("sha256") or "",
                    "verdict": p.get("verdict") or "static_only",
                    "risk_score": p.get("risk_score", 0),
                    "detail": f"{p.get('file_type_observation') or ''} {'[EXTENSION MISMATCH]' if p.get('extension_mismatch') else ''}".strip(),
                }
            )

    watchlist_alerts = [dict(r) for r in alerts_rows if str(r["reason"]).startswith("[Watchlist Match]")]
    return {
        "case": {
            "id": case_id,
            "reference": case_row["reference"],
            "title": case_row["title"],
            "severity": case_row["severity"],
            "priority": case_row["priority"],
            "status": case_row["status"],
            "owner_name": owner_row["name"] if owner_row else "Unassigned",
            "owner_role": owner_row["role"] if owner_row else "",
            "created_at": case_row["created_at"],
            "updated_at": case_row["updated_at"],
        },
        "logs_count": logs_count,
        "alerts_count": alerts_total,
        "alerts": [dict(r) for r in alerts_rows],
        "watchlist_hits_count": len(watchlist_alerts),
        "watchlist_hits": watchlist_alerts,
        "static_triage_items": static_items,
    }


@quick_reports_api.get("/api/cases/<int:case_id>/quick-report")
@require_permission("cases.read")
def get_quick_report(case_id: int):
    case = _case_row(case_id)
    if not case:
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    row = get_db().execute("SELECT * FROM case_quick_reports WHERE case_id = ?", (case_id,)).fetchone()
    return jsonify(
        {
            "case_id": case_id,
            "questions": QUICK_REPORT_QUESTIONS,
            "default_answers": DEFAULT_ANSWERS,
            "report": _report_view(row),
            "auto_summary": _collect_case_auto_summary(case),
            "can_acknowledge_as_manager": _is_manager_user(),
            "print_url": f"/cases/{case_id}/quick-report/print",
        }
    )


@quick_reports_api.put("/api/cases/<int:case_id>/quick-report")
@require_permission("cases.update")
def save_quick_report(case_id: int):
    case = _case_row(case_id)
    if not case:
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    if case["status"] == "closed":
        return error_response("CASE_CLOSED", "القضية مغلقة", 409)
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return error_response("INVALID_JSON", "يلزم إرسال كائن JSON صالح", 400)
    try:
        answers = _validate_answers(body.get("answers"))
        note = str(body.get("executive_note") or "").strip()
        if len(note) > 280:
            raise ValueError("الملاحظة المختصرة يجب ألا تتجاوز 280 محرفًا")
    except ValueError as exc:
        return error_response("INVALID_QUICK_REPORT", str(exc), 422)

    now = iso_now()
    user_id = actor_id()
    with transaction():
        prior = get_db().execute("SELECT status FROM case_quick_reports WHERE case_id = ?", (case_id,)).fetchone()
        if prior:
            next_status = prior["status"] if prior["status"] == "escalated" else "draft"
            get_db().execute(
                "UPDATE case_quick_reports SET answers_json = ?, executive_note = ?, status = ?, prepared_by = ?, updated_at = ? WHERE case_id = ?",
                (json.dumps(answers, ensure_ascii=False), note, next_status, user_id, now, case_id),
            )
        else:
            get_db().execute(
                """INSERT INTO case_quick_reports
                   (case_id, workspace_id, answers_json, executive_note, status, prepared_by, created_at, updated_at)
                   VALUES (?, ?, ?, ?, 'draft', ?, ?, ?)""",
                (case_id, case["workspace_id"], json.dumps(answers, ensure_ascii=False), note, user_id, now, now),
            )
        custody(case_id, "quick_dropdown_report_saved", {"verdict": answers["triage_verdict"], "urgency": answers["urgency_level"]})
        touch_case(case_id)
    saved = get_db().execute("SELECT * FROM case_quick_reports WHERE case_id = ?", (case_id,)).fetchone()
    return jsonify({"report": _report_view(saved), "auto_summary": _collect_case_auto_summary(case)}), 200


@quick_reports_api.post("/api/cases/<int:case_id>/quick-report/escalate")
@require_permission("cases.update")
def escalate_quick_report(case_id: int):
    case = _case_row(case_id)
    if not case:
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    if case["status"] == "closed":
        return error_response("CASE_CLOSED", "القضية مغلقة", 409)

    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return error_response("INVALID_JSON", "يلزم إرسال كائن JSON صالح", 400)

    now = iso_now()
    user_id = actor_id()
    with transaction():
        existing = get_db().execute("SELECT * FROM case_quick_reports WHERE case_id = ?", (case_id,)).fetchone()
        if "answers" in body:
            try:
                answers = _validate_answers(body.get("answers"))
                note = str(body.get("executive_note") or (existing["executive_note"] if existing else "")).strip()
                if len(note) > 280:
                    raise ValueError("الملاحظة المختصرة يجب ألا تتجاوز 280 محرفًا")
            except ValueError as exc:
                return error_response("INVALID_QUICK_REPORT", str(exc), 422)
            if existing:
                get_db().execute(
                    """UPDATE case_quick_reports
                       SET answers_json = ?, executive_note = ?, status = 'escalated', prepared_by = ?, escalated_by = ?, escalated_at = ?, updated_at = ?
                       WHERE case_id = ?""",
                    (json.dumps(answers, ensure_ascii=False), note, user_id, user_id, now, now, case_id),
                )
            else:
                get_db().execute(
                    """INSERT INTO case_quick_reports
                       (case_id, workspace_id, answers_json, executive_note, status, prepared_by, escalated_by, escalated_at, created_at, updated_at)
                       VALUES (?, ?, ?, ?, 'escalated', ?, ?, ?, ?, ?)""",
                    (case_id, case["workspace_id"], json.dumps(answers, ensure_ascii=False), note, user_id, user_id, now, now, now),
                )
        else:
            if not existing:
                return error_response("QUICK_REPORT_MISSING", "احفظ إجابات التقرير المنسدلة أولًا قبل التصعيد للمدير", 422)
            get_db().execute(
                "UPDATE case_quick_reports SET status = 'escalated', escalated_by = ?, escalated_at = ?, updated_at = ? WHERE case_id = ?",
                (user_id, now, now, case_id),
            )

        if case["status"] not in {"closed", "resolved", "escalated"}:
            get_db().execute("UPDATE incident_cases SET status = 'escalated', updated_at = ?, version = version + 1 WHERE id = ?", (now, case_id))
        custody(case_id, "quick_report_escalated_to_manager", {"escalated_by": user_id, "escalated_at": now})
        record_audit(get_db(), "escalate_quick_report", "case", case_id, details={"escalated_by": user_id})

    updated_row = get_db().execute("SELECT * FROM case_quick_reports WHERE case_id = ?", (case_id,)).fetchone()
    return jsonify({"report": _report_view(updated_row)}), 200


@quick_reports_api.get("/api/reports/escalated")
@require_permission("cases.read")
def list_escalated_reports():
    rows = (
        get_db()
        .execute(
            """SELECT qr.*, c.reference AS case_reference, c.title AS case_title, c.severity AS case_severity, c.status AS case_status,
                      COALESCE(u.name, u.email) AS investigator_name
               FROM case_quick_reports qr
               JOIN incident_cases c ON c.id = qr.case_id
               LEFT JOIN users u ON u.id = COALESCE(qr.escalated_by, qr.prepared_by)
               WHERE qr.workspace_id = ? AND qr.status IN ('escalated', 'acknowledged') AND c.archived_at IS NULL
               ORDER BY CASE WHEN qr.status = 'escalated' THEN 0 ELSE 1 END, qr.escalated_at DESC, qr.updated_at DESC
               LIMIT 100""",
            (workspace_id(),),
        )
        .fetchall()
    )
    items: list[dict[str, Any]] = []
    for row in rows:
        answers = json.loads(row["answers_json"])
        items.append(
            {
                "case_id": row["case_id"],
                "case_reference": row["case_reference"],
                "case_title": row["case_title"],
                "case_severity": row["case_severity"],
                "case_status": row["case_status"],
                "status": row["status"],
                "investigator_name": row["investigator_name"] or "—",
                "incident_classification": answers.get("incident_classification"),
                "incident_classification_label": QUESTION_OPTION_MAP["incident_classification"].get(answers.get("incident_classification", ""), "—"),
                "triage_verdict": answers.get("triage_verdict"),
                "triage_verdict_label": QUESTION_OPTION_MAP["triage_verdict"].get(answers.get("triage_verdict", ""), "—"),
                "urgency_level": answers.get("urgency_level"),
                "urgency_level_label": QUESTION_OPTION_MAP["urgency_level"].get(answers.get("urgency_level", ""), "—"),
                "escalated_at": row["escalated_at"],
                "acknowledged_at": row["acknowledged_at"],
                "manager_decision": row["manager_decision"],
                "manager_comment": row["manager_comment"],
                "print_url": f"/cases/{row['case_id']}/quick-report/print",
            }
        )
    return jsonify({"items": items, "total": len(items), "can_acknowledge": _is_manager_user()})


@quick_reports_api.post("/api/cases/<int:case_id>/quick-report/acknowledge")
@require_permission("cases.read")
def acknowledge_escalated_report(case_id: int):
    if not _is_manager_user():
        return error_response("FORBIDDEN", "اعتماد التقارير المصعدة مخصص لمدير مركز العمليات (SOC Manager)", 403)
    case = _case_row(case_id)
    if not case:
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return error_response("INVALID_JSON", "يلزم إرسال كائن JSON صالح", 400)
    decision = str(body.get("decision") or "").strip().lower()
    if decision not in MANAGER_DECISIONS:
        return error_response("INVALID_DECISION", "القرار يجب أن يكون approved أو needs_followup أو closed", 422)
    comment = str(body.get("comment") or "").strip()
    if len(comment) > 500:
        return error_response("INVALID_COMMENT", "تعليق المدير يجب ألا يتجاوز 500 محرف", 422)

    now = iso_now()
    user_id = actor_id()
    with transaction():
        existing = get_db().execute("SELECT * FROM case_quick_reports WHERE case_id = ?", (case_id,)).fetchone()
        if not existing:
            return error_response("QUICK_REPORT_MISSING", "لا يوجد تقرير سريع محفوظ لهذه القضية", 404)
        get_db().execute(
            """UPDATE case_quick_reports
               SET status = 'acknowledged', acknowledged_by = ?, acknowledged_at = ?, manager_decision = ?, manager_comment = ?, updated_at = ?
               WHERE case_id = ?""",
            (user_id, now, decision, comment, now, case_id),
        )
        if decision == "closed" and case["status"] != "closed":
            get_db().execute(
                "UPDATE incident_cases SET status = 'resolved', resolved_at = COALESCE(resolved_at, ?), updated_at = ?, version = version + 1 WHERE id = ?",
                (now, now, case_id),
            )
        custody(case_id, "quick_report_manager_acknowledged", {"decision": decision, "manager_id": user_id})
        record_audit(get_db(), "acknowledge_quick_report", "case", case_id, details={"decision": decision})

    updated = get_db().execute("SELECT * FROM case_quick_reports WHERE case_id = ?", (case_id,)).fetchone()
    return jsonify({"report": _report_view(updated)}), 200


def _esc(value: object) -> str:
    return html.escape(str(value if value is not None else "—"), quote=True)


def _fmt_bilingual(value: object) -> str:
    raw = str(value if value is not None else "—")
    if raw.endswith(")") and " (" in raw:
        ar_part, en_inner = raw.rsplit(" (", 1)
        en_part = "(" + en_inner
        if all(ch.isascii() and (ch.isalnum() or ch in " ()&/,._:-+") for ch in en_part):
            return f'{_esc(ar_part)} <span class="en-sub" dir="ltr">{_esc(en_part)}</span>'
    return _esc(raw)


def _badge_tone(raw: object) -> str:
    token = str(raw or "").strip().lower()
    if token in {"critical", "malicious", "immediate_p1"}:
        return "critical"
    if token in {"high", "high_risk", "suspicious", "escalated"}:
        return "high"
    if token in {"medium", "draft", "unsaved preview"}:
        return "medium"
    if token in {"clean", "approved", "acknowledged", "resolved"}:
        return "ok"
    return "low"


@quick_reports_api.get("/cases/<int:case_id>/quick-report/print")
@require_permission("cases.read")
def print_quick_report(case_id: int):
    case = _case_row(case_id)
    if not case:
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    row = get_db().execute("SELECT * FROM case_quick_reports WHERE case_id = ?", (case_id,)).fetchone()
    report = _report_view(row)
    summary = _collect_case_auto_summary(case)
    cmeta = summary["case"]

    if report:
        qa_rows_html = "".join(
            f"<tr><th>{_fmt_bilingual(item['question'])}</th><td><strong>{_fmt_bilingual(item['answer_label'])}</strong></td></tr>"
            for item in report["resolved_questions"]
        )
        status_label = report["status"].upper()
        status_tone = _badge_tone(report["status"])
        note_html = f'<div class="note-box"><strong>ملاحظة المحقق المختصرة:</strong> {_esc(report["executive_note"])}</div>' if report["executive_note"] else ""
        manager_html = (
            f'<div class="note-box manager-box"><strong>قرار واعتماد المدير (<span class="mono" dir="ltr">{_esc(report["manager_decision"])}</span>):</strong> {_esc(report["manager_comment"] or "تم الاعتماد")} · <span class="mono" dir="ltr">{_esc(report["acknowledged_at"])}</span></div>'
            if report["manager_decision"]
            else ""
        )
    else:
        qa_rows_html = "".join(
            f"<tr><th>{_fmt_bilingual(q['label'])}</th><td>{_fmt_bilingual(QUESTION_OPTION_MAP[q['id']][q['default']])} <em>(قيمة افتراضية — لم يُعتمد بعد)</em></td></tr>"
            for q in QUICK_REPORT_QUESTIONS
        )
        status_label = "UNSAVED PREVIEW"
        status_tone = "medium"
        note_html = ""
        manager_html = ""

    if summary["alerts"]:
        alerts_rows_html = "".join(
            f'<tr><td><code dir="ltr">{_esc(a["alert_id"])}</code></td><td><span class="badge {_badge_tone(a["severity"])}" dir="ltr">{_esc(a["severity"])}</span></td><td>{_esc(a["reason"])}</td><td><span class="mono" dir="ltr">{_esc(a["detected_at"])}</span></td></tr>'
            for a in summary["alerts"]
        )
    else:
        alerts_rows_html = '<tr><td colspan="4">لا توجد تنبيهات مسجلة في القضية حتى لحظة التقرير.</td></tr>'

    if summary["static_triage_items"]:
        triage_rows_html = "".join(
            f'<tr><td><span class="mono" dir="ltr">{_esc(t["name"])}</span></td><td><span class="badge {_badge_tone(t["verdict"])}" dir="ltr">{_esc(t["verdict"])} ({_esc(t["risk_score"])}/100)</span></td><td><code dir="ltr">{_esc(t["sha256"][:24])}...</code></td><td>{_esc(t["detail"])}</td></tr>'
            for t in summary["static_triage_items"]
        )
    else:
        triage_rows_html = '<tr><td colspan="4">لم تُفحص ملفات أو رسائل بريد ساكنة في هذه القضية.</td></tr>'

    document = f"""<!doctype html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" type="image/svg+xml" href="/static/brand-mark.svg">
  <title>تقرير فرز وتحقيق فوري · {_esc(cmeta["reference"])}</title>
  <link rel="stylesheet" href="/static/fonts.css">
  <link rel="stylesheet" href="/static/tokens.css">
  <link rel="stylesheet" href="/static/quick-report-print.css">
  <script src="/static/quick-report-print.js" defer></script>
</head>
<body>
  <div class="print-toolbar">
    <div class="toolbar-brand">
      <img src="/static/brand-mark.svg" width="22" height="22" alt="">
      <span><strong dir="ltr">SOCify · SOC / V6</strong> — تقرير فرز وتحقيق جاهز للطباعة والتصعيد</span>
    </div>
    <div class="toolbar-actions">
      <button type="button" id="trigger-print-btn">طباعة التقرير / حفظ PDF</button>
      <a class="secondary" href="/cases/{case_id}?tab=reports">العودة للقضية</a>
    </div>
  </div>
  <main class="report-sheet">
    <header class="report-header">
      <div class="header-main">
        <div class="brand-kicker"><img src="/static/brand-mark.svg" width="20" height="20" alt=""><span dir="ltr">SOCify Tactical Workbench · SOC / V6 · Instant Triage Report</span></div>
        <h1 class="report-title"><span class="mono" dir="ltr">{_esc(cmeta["reference"])}</span> — {_esc(cmeta["title"])}</h1>
      </div>
      <div><span class="badge {status_tone}" dir="ltr">{_esc(status_label)}</span></div>
    </header>

    <section class="meta-grid" aria-label="بيانات القضية الأساسية">
      <div class="meta-item"><strong>مرجع القضية</strong><span class="mono" dir="ltr">{_esc(cmeta["reference"])}</span></div>
      <div class="meta-item"><strong>المسؤول عن التحقيق</strong>{_esc(cmeta["owner_name"])}</div>
      <div class="meta-item"><strong>الخطورة والحالة</strong><span class="mono" dir="ltr">{_esc(cmeta["severity"]).upper()} · {_esc(cmeta["status"])}</span></div>
      <div class="meta-item"><strong>إجمالي السجلات المفحوصة</strong>{_esc(summary["logs_count"])} سجل</div>
      <div class="meta-item"><strong>التنبيهات وتطابقات المراقبة</strong>{_esc(summary["alerts_count"])} تنبيه (<span class="mono" dir="ltr">{_esc(summary["watchlist_hits_count"])} Watchlist</span>)</div>
      <div class="meta-item"><strong>وقت التوليد (UTC)</strong><span class="mono" dir="ltr">{_esc(iso_now())}</span></div>
    </section>

    {note_html}
    {manager_html}

    <h2 class="section-title">أولًا: خلاصة التحقيق الموجهة <span class="en-sub" dir="ltr">(Guided Triage Assessment)</span></h2>
    <table class="qa-table">
      <thead><tr><th class="qa-col-topic">محور التقييم</th><th>النتيجة المعتمدة</th></tr></thead>
      <tbody>{qa_rows_html}</tbody>
    </table>

    <h2 class="section-title">ثانيًا: تنبيهات القواعد المدمجة وقائمة المراقبة <span class="en-sub" dir="ltr">(Triggered Alerts &amp; Watchlist Hits)</span></h2>
    <table class="evidence-table">
      <thead><tr><th>المعرف</th><th>الخطورة</th><th>القاعدة / سبب التنبيه</th><th>وقت الرصد</th></tr></thead>
      <tbody>{alerts_rows_html}</tbody>
    </table>

    <h2 class="section-title">ثالثًا: نتائج الفحص الساكن الآمن للملفات والبريد <span class="en-sub" dir="ltr">(Static File &amp; Email Triage — Never Executed)</span></h2>
    <table class="evidence-table">
      <thead><tr><th>الملف / الرسالة</th><th>الحكم الأولي</th><th>SHA-256</th><th>الملاحظات الفنية</th></tr></thead>
      <tbody>{triage_rows_html}</tbody>
    </table>

    <footer class="report-footer">
      <span dir="ltr">SOCify Tactical Workbench (SOC / V6) — Structured analyst selections &amp; verified case evidence</span>
      <span class="mono" dir="ltr">Case #{case_id} · {_esc(cmeta["reference"])}</span>
    </footer>
  </main>
</body>
</html>"""
    return Response(document, status=200, mimetype="text/html; charset=utf-8")
