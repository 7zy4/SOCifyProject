import base64
import hashlib
import html
import io
import re
from pathlib import Path

from .autopsy_domain import canonical
from .report_brand import design_tokens, report_fonts, report_style
from .report_docx import add_report_run, configure_style, embed_report_fonts, set_direction
from .task_titles import TITLES, task_title

FORMATS = {
    "json": "application/json",
    "html": "text/html",
    "md": "text/markdown",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "pdf": "application/pdf",
}
LABELS = {
    "payload": "تفاصيل التحقيق",
    "notes": "ملاحظات التحقيق",
    "body": "الملاحظة أو القرار",
    "five_whys": "أسئلة السبب الجذري",
    "prepared_by": "أعدّه العضو",
    "manager_decision": "قرار المدير",
    "manager_comment": "تعليق المدير",
    "acknowledged_by": "اعتمده العضو",
    "acknowledged_at": "وقت الاعتماد",
    "logon_events": "تسجيل الدخول",
    "outcome": "النتيجة",
    "windows_event_id": "معرف حدث Windows",
    "account_domain": "نطاق الحساب",
    "logon_type": "نوع الدخول",
    "logon_type_code": "رمز نوع الدخول",
    "authentication_package": "آلية المصادقة",
    "logon_id": "معرف جلسة الدخول",
    "source_workstation": "جهاز المصدر",
    "logon_status": "رمز الحالة",
    "logon_substatus": "رمز الحالة الفرعي",
    "network_alerts": "تنبيهات الشبكة",
    "ids_rule": "معرف قاعدة الرصد",
    "ids_priority": "أولوية الرصد",
    "ids_classification": "تصنيف التنبيه",
    "ids_signature": "وصف التنبيه",
    "packet_number": "رقم الحزمة",
    "source_timestamp": "توقيت المصدر",
    "source_type": "نوع المصدر",
    "source_port": "منفذ المصدر",
    "source_ip": "عنوان المصدر",
    "destination_ip": "عنوان الوجهة",
    "source_ports": "منافذ المصدر",
    "event_ids": "معرفات السجلات المرتبطة",
    "hostname": "الجهاز",
    "username": "الحساب",
    "content_inspection": "فحص المحتوى والترميزات",
    "network_analysis": "تحليل الشبكة",
    "endpoint_results": "نتائج الأجهزة",
    "runtime_events": "أمن الأنظمة والحاويات",
    "runtime_rule": "قاعدة الرصد",
    "runtime_priority": "أولوية الرصد",
    "runtime_source": "مصدر الحدث",
    "sensor_hostname": "حساس الجمع",
    "container_id": "معرف الحاوية",
    "container_name": "الحاوية",
    "container_image": "صورة الحاوية",
    "container_image_tag": "وسم الصورة",
    "kubernetes_namespace": "نطاق الحاويات",
    "kubernetes_pod": "مجموعة الحاويات",
    "kubernetes_node": "عقدة التشغيل",
    "process_name": "العملية",
    "parent_process": "العملية الأم",
    "process_id": "معرف العملية",
    "parent_process_id": "معرف العملية الأم",
    "process_path": "مسار العملية",
    "command_line": "سطر الأوامر",
    "file_path": "مسار الملف",
    "connection_count": "عدد الاتصالات",
    "periodic_count": "الاتصالات الدورية",
    "pair_count": "أزواج الاتصال",
    "median_interval_seconds": "وسيط الفاصل بالثواني",
    "interval_mad_seconds": "الانحراف المطلق الوسيط بالثواني",
    "regularity_percent": "انتظام الفواصل %",
    "periodic": "اتصال دوري",
    "bytes_sent": "البايتات المرسلة",
    "bytes_received": "البايتات المستقبلة",
    "timed_connections": "الاتصالات ذات الوقت المعروف",
    "items": "النتائج",
    "event_count": "عدد السجلات",
    "destination_port": "منفذ الوجهة",
    "protocol": "البروتوكول",
    "first_seen": "أول اتصال",
    "last_seen": "آخر اتصال",
    "events_truncated": "روابط الأدلة مقتصرة على أول ٥٠ سجلًا",
    "names": "النطاقات",
    "byte_measurements": "الاتصالات ذات قياس حجم",
    "longest_connection_seconds": "أطول اتصال بالثواني",
    "action": "الإجراء",
    "query": "الاستعلام",
    "columns": "الحقول",
    "event_id": "معرف السجل",
    "raw_hash": "بصمة السجل",
    "engine": "محرك الفحص",
    "findings": "النتائج",
    "decoded": "النصوص المفكوكة",
    "kind": "النوع",
    "field": "الحقل",
    "offset": "إزاحة الأحرف",
    "length": "عدد الأحرف",
    "layer": "الطبقة",
    "layers": "الطبقات",
    "depth": "رقم الطبقة",
    "encoding": "الترميز",
    "text": "النص",
    "value": "القيمة",
    "truncated": "تجاوز حد الفحص",
    "depth_limit_reached": "بلوغ حد الطبقات",
    "decoded_threat_count": "مطابقات أنماط التهديد بعد فك الترميز",
    "entry_type": "نوع عنصر الخط الزمني",
    "time_basis": "أساس التوقيت",
    "actor_id": "معرف المسجل",
    "key": "مرجع العنصر",
    "decision": "القرار الموثق",
    "task_id": "المهمة المرتبطة",
    "scope": "نطاق الفحص وحدود الاستنتاج",
    "counts_by_assessment": "تقييم أصول النطاق",
    "earliest_retained_observation": "أقدم ملاحظة محفوظة مدعومة بدليل",
    "counts": "موجز الأدلة المتاحة",
    "normalized_logs": "السجلات المطبعّة",
    "status_at_preparation": "حالة القضية عند إعداد النسخة",
    "created_at": "وقت الإنشاء",
    "closed_at": "وقت الإغلاق",
    "updated_at": "آخر تعديل",
    "priority": "الأولوية",
    "severity": "درجة الخطورة",
    "version": "الإصدار",
    "name": "الاسم",
    "role": "الدور",
    "responsibility": "المسؤولية",
    "user_id": "معرف العضو",
    "created_by": "معرف المؤلف",
    "updated_by": "معرف آخر محرر",
    "created_by_name": "المؤلف",
    "updated_by_name": "آخر محرر",
    "first_response_delay_seconds": "المدة حتى أول استجابة بالثواني",
    "closure_delay_seconds": "المدة من الرصد حتى الإغلاق بالثواني",
    "first_response": "وقت أول استجابة مثبتة",
    "milestones": "مراحل الاستجابة",
    "added_by": "أضافه العضو",
    "added_at": "وقت حفظ الدليل",
    "id": "المعرف",
    "basis": "أساس حساب القياسات وحدودها",
    "first_evidenced_activity": "أقدم نشاط مثبت بالدليل",
    "detection": "وقت الرصد المثبت",
    "acknowledgement": "وقت إقرار الاستلام",
    "containment": "وقت الاحتواء المثبت",
    "recovery": "وقت التعافي المثبت",
    "detection_delay_seconds": "المدة حتى الرصد بالثواني",
    "acknowledgement_delay_seconds": "المدة حتى الإقرار بالثواني",
    "containment_delay_seconds": "المدة حتى الاحتواء بالثواني",
    "recovery_delay_seconds": "المدة حتى التعافي بالثواني",
    "missing_or_inconsistent_times": "الأوقات الناقصة أو غير المتسقة",
    "evidence_type": "نوع الدليل",
    "source": "المصدر",
    "confidence": "الثقة",
    "details": "تفاصيل التحقيق",
    "legal_hold": "الحجز القانوني",
    "retention_until": "الاحتفاظ حتى",
    "format": "الصيغة",
    "original_filename": "اسم الأصل",
    "parser_version": "إصدار المحلل",
    "accepted": "السجلات المقبولة",
    "rejected": "السجلات المرفوضة",
    "head_sha256": "بصمة رأس سلسلة الحيازة",
    "entries": "عدد حركات الحيازة",
    "summary": "الملخص التنفيذي",
    "case": "بيانات القضية ونطاق التحقيق",
    "context": "الهدف وقرار التنبيه ونتيجة الهجوم",
    "metrics": "قياسات مراحل الاستجابة",
    "members": "المسؤوليات",
    "asset": "الأصول ونطاق الأثر",
    "indicator": "المؤشرات المرصودة والمثبتة",
    "timeline": "الخط الزمني والتعليقات",
    "hypothesis": "الفرضيات والأدلة",
    "foothold": "أقدم نقطة اختراق مثبتة وحدود الاستنتاج",
    "root_cause": "الأسباب الجذرية و5 Whys",
    "playbook": "كتيبات الاستجابة ونتائج الخطوات",
    "response": "الاستجابة والاحتواء والتحقق",
    "escalation": "سجل التصعيد والاستلام والاستجابة",
    "war_room": "قرارات غرفة التحقيق المشتركة",
    "corrective": "التوصيات والإجراءات التصحيحية",
    "reputation": "نتائج السمعة المستوردة يدويًا",
    "analysis": "التحليل المحلي",
    "alerts": "التنبيهات",
    "tasks": "المهام",
    "evidence": "فهرس الأدلة وبصماتها",
    "imports": "الأصول المستوردة وإصدارات المعالجة",
    "custody": "سلامة سلسلة الحيازة",
    "history": "تاريخ حالات القضية",
    "limitations": "حدود التقرير والتحليل",
    "title": "العنوان",
    "reason": "السبب",
    "objective": "الهدف",
    "status": "الحالة",
    "classification": "تصنيف السرية",
    "attack_outcome": "نتيجة الهجوم",
    "alert_verdict": "قرار التنبيه",
    "sha256": "بصمة SHA-256",
    "source_version": "إصدار القضية",
    "generated_at": "وقت إعداد النسخة",
    "evidence_id": "مرجع الدليل",
    "performed_at": "وقت التنفيذ",
    "performed_by": "من نفذ الإجراء",
    "conclusion": "الاستنتاج",
    "limitations_text": "حدود الاستنتاج",
    "event_time": "وقت الحدث",
    "question": "السؤال",
    "answer": "الإجابة",
    "reference": "مرجع القضية",
    "revision": "إصدار التقرير",
    "profile": "سياسة مشاركة التقرير",
    "integrity_valid": "سلامة السلسلة عند إعداد التقرير",
}
ENUM_LABELS = {
    "interactive": "دخول تفاعلي",
    "network_logon": "دخول عبر الشبكة",
    "batch_logon": "دخول مهمة مجدولة",
    "service_logon": "دخول خدمة",
    "unlock_logon": "فتح القفل",
    "network_cleartext": "مصادقة شبكة بكلمة مرور غير مجزأة",
    "new_credentials": "بيانات اعتماد جديدة",
    "remote_interactive": "دخول تفاعلي عن بُعد",
    "cached_interactive": "دخول تفاعلي ببيانات مخزنة",
    "cached_remote_interactive": "دخول بعيد ببيانات مخزنة",
    "cached_unlock": "فتح القفل ببيانات مخزنة",
    "would_drop": "كان سيُحظر (would_drop)",
    "drop": "أُسقطت الحزمة (drop)",
    "credential_assignment": "بيانات اعتماد مكشوفة",
    "bearer_token": "رمز وصول مكشوف",
    "private_key": "مفتاح خاص مكشوف",
    "payment_card": "رقم بطاقة",
    "iban": "IBAN",
    "log": "سجل مصدر",
    "record": "سجل تحقيق أو إجراء",
    "note": "ملاحظة تحقيق",
    "documentation_time": "وقت التوثيق؛ ليس وقت وقوع الهجوم",
    "reported_action_time": "وقت إجراء مسجل بواسطة المنفذ",
    "investigator_observation_time": "وقت ملاحظة أدخله المحقق",
    "hypothesis_time": "توقيت فرضية غير مؤكدة",
    "escalation_time": "وقت إحالة داخل الفريق؛ ليس وقت وقوع الهجوم",
    "source": "وقت مسجل في المصدر",
    "source_year_and_zone_declared": "وقت المصدر مع سنة ومنطقة زمنية معلنتين",
    "source_year_assumed_not_verified": "سنة المصدر مفترضة وغير متحققة",
    "ingestion_fallback_not_observed_time": "وقت استيراد بديل؛ لا يثبت وقت الحدث",
    "new": "مسودة",
    "open": "مفتوحة",
    "investigating": "قيد التحقيق",
    "awaiting_review": "بانتظار المراجعة",
    "closed": "مغلقة",
    "reopened": "أعيد فتحها",
    "successful": "ناجح",
    "success": "ناجح",
    "failed": "فشل",
    "blocked": "محجوب أو فاشل",
    "partial": "نجاح جزئي",
    "unknown": "غير معروف",
    "undetermined": "غير محسوم",
    "malicious": "خبيث",
    "benign": "حميد",
    "false_positive": "إيجابي كاذب",
    "internal": "داخلي",
    "confidential": "سري",
    "restricted": "مقيد",
    "critical": "حرج",
    "high": "عالٍ",
    "medium": "متوسط",
    "low": "منخفض",
    "soc_manager": "مدير الفريق",
    "investigator": "محقق",
    "reviewer": "مراجع",
    "analyst": "محلل",
    "owner": "مسؤول القضية",
    "l1": "المستوى الأول",
    "l2": "المستوى الثاني",
    "monitoring": "المراقبة",
}


def display(value) -> str:
    text = str(value) if value is not None else "غير مسجل"
    return re.sub("[\u202a-\u202e\u2066-\u2069]", lambda match: f"\\u{ord(match[0]):04x}", text)


INTERNAL_FIELDS = {"schema", "revision", "version", "source_version", "parser_version", "system_key", "display_title"}


def lines(value, depth=0):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in INTERNAL_FIELDS:
                continue
            if isinstance(item, list) and all(not isinstance(cell, (dict, list)) for cell in item):
                yield depth, f"{LABELS.get(key, key)}: " + ("، ".join(display(cell) for cell in item) if item else "—")
            elif isinstance(item, (dict, list)):
                yield depth, "عناصر الخط الزمني" if key == "entries" and isinstance(item, list) else LABELS.get(key, key)
                yield from lines(item, depth + 1)
            else:
                value = "غير قابل للحساب" if item is None and key.endswith("_seconds") else display(item)
                if key in {
                    "status",
                    "status_at_preparation",
                    "severity",
                    "priority",
                    "classification",
                    "attack_outcome",
                    "alert_verdict",
                    "role",
                    "responsibility",
                    "time_basis",
                    "entry_type",
                    "kind",
                    "action",
                    "logon_type",
                    "outcome",
                } and isinstance(item, str):
                    value = ENUM_LABELS.get(item, item)
                yield depth, f"{LABELS.get(key, key)}: {value}"
    elif isinstance(value, list):
        if not value:
            yield depth, "لا توجد عناصر مسجلة"
        if all(not isinstance(item, (dict, list)) for item in value):
            if value:
                yield depth, "، ".join(display(item) for item in value)
        else:
            for item in value:
                if isinstance(item, dict):
                    yield depth, record_heading(item)
                    heading_key = record_heading_key(item)
                    item = {key: cell for key, cell in item.items() if key != heading_key}
                yield from lines(item, depth + 1)
    else:
        yield depth, display(value)


def network_report_content(value):
    """Retain engine and grouping identities in the snapshot, not the reader's tables."""
    return {
        key: [{field: cell for field, cell in item.items() if field != "key"} for item in entry] if key == "items" else entry
        for key, entry in value.items()
        if key != "engine"
    }


def record_heading_key(item):
    for key in ("event_id", "reference", "title", "name", "question", "original_filename", "id"):
        if item.get(key) not in (None, ""):
            return key
    return None


def record_heading(item):
    key = record_heading_key(item)
    if key:
        return f"{LABELS.get(key, key)}: {display(item[key])}"
    if item.get("source_ip") and item.get("destination_ip"):
        return f"{item['source_ip']} → {item['destination_ip']}"
    return "تفاصيل العنصر"


def report_table(value, *, localize=False):
    """Render structured evidence as labelled cells, never ordinal-only rows."""
    rows = []

    def row(label, cell, translate_value=False):
        label_copy = " data-ui-copy" if localize and label in LABELS.values() else ""
        value_copy = " data-ui-copy" if localize and translate_value else ""
        rows.append(
            f'<tr><th scope="row"{label_copy}>{html.escape(display(label))}</th><td><bdi dir="auto"{value_copy}>{html.escape(display(cell))}</bdi></td></tr>'
        )

    def group(label, record=None):
        content = html.escape(display(label))
        if localize:
            if record:
                key = record_heading_key(record)
                if key:
                    caption = html.escape(LABELS.get(key, key))
                    system_copy = " data-ui-copy" if key == "title" and TITLES.get(record.get("system_key"), (None, None))[1] == record[key] else ""
                    content = f'<span data-ui-copy>{caption}</span>: <bdi dir="auto"{system_copy}>{html.escape(display(record[key]))}</bdi>'
            elif label in LABELS.values() or label == "تفاصيل العنصر":
                content = f"<span data-ui-copy>{content}</span>"
        rows.append(f'<tr class="report-group"><th colspan="2">{content}</th></tr>')

    def walk(item, label="التفاصيل"):
        if isinstance(item, dict):
            for key, cell in item.items():
                if key in INTERNAL_FIELDS:
                    continue
                caption = LABELS.get(key) or str(key)
                if isinstance(cell, dict):
                    group(caption)
                    walk(cell, caption)
                elif isinstance(cell, list):
                    walk(cell, caption)
                else:
                    text = next(lines({key: cell}))[1][len(caption) + 2 :]
                    row(caption, text, cell is None or (text != display(cell) and text in ENUM_LABELS.values()))
        elif isinstance(item, list):
            if all(not isinstance(cell, (dict, list)) for cell in item):
                row(label, "، ".join(display(cell) for cell in item) if item else "—")
            else:
                for cell in item:
                    group(record_heading(cell) if isinstance(cell, dict) else label, cell if isinstance(cell, dict) else None)
                    if isinstance(cell, dict):
                        heading_key = record_heading_key(cell)
                        cell = {key: value for key, value in cell.items() if key != heading_key}
                    walk(cell, label)
        else:
            row(label, item)

    walk(value)
    copy = " data-ui-copy" if localize else ""
    return f'<table class="qa-table report-facts"><thead><tr><th{copy}>الحقل</th><th{copy}>القيمة</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table>"


def sections(payload):
    assessment = payload.get("investigation_assessment")
    if assessment:
        yield "قرارات التحقيق", {"status": assessment["status"], "updated_at": assessment["updated_at"], "prepared_by": assessment["prepared_by"]}
        for question in assessment["resolved_questions"]:
            yield question["question"], question["answer_label"]
        if assessment.get("executive_note"):
            yield "خلاصة المحقق", assessment["executive_note"]
        if assessment.get("manager_decision"):
            yield "مراجعة المدير", {key: assessment[key] for key in ("manager_decision", "manager_comment", "acknowledged_by", "acknowledged_at")}
    for key in ("summary", "case", "context", "metrics", "scope", "members", "alerts"):
        if payload.get(key):
            yield LABELS[key], payload[key]
    for kind in (
        "asset",
        "indicator",
        "timeline",
        "hypothesis",
        "foothold",
        "root_cause",
        "playbook",
        "response",
        "escalation",
        "war_room",
        "reputation",
        "analysis",
        "corrective",
    ):
        records = payload.get("records", {}).get(kind, [])
        if records:
            yield (
                LABELS[kind],
                [
                    {**record.get("payload", {}), **{key: value for key, value in record.items() if key not in {"payload", "kind", "created_by", "updated_by"}}}
                    for record in records
                ],
            )
    for title, key in (
        ("فحص المحتوى والترميزات", "content_inspection"),
        ("تحليل الشبكة", "network_analysis"),
        ("نتائج الأجهزة", "endpoint_results"),
        ("أمن الأنظمة والحاويات", "runtime_events"),
        ("تنبيهات الشبكة", "network_alerts"),
        ("تسجيل الدخول", "logon_events"),
        ("الخط الزمني المشترك للأدلة والتحقيق والإجراءات", "chronology"),
        ("الإثراء المحلي ومصادر السمعة وإصداراتها", "observables"),
        ("SLA وجمع الأدلة ومراجعة ما بعد الحادثة", "workflow"),
        ("توثيق MITRE ATT&CK وإصداره وأدلته", "techniques"),
        ("خط زمني للسجلات المختارة كأدلة وتوقيت مصادرها", "evidenced_timeline"),
        ("الملاحظات المشتركة الموروثة", "shared_notes"),
        ("نتائج الإغلاق الموروثة محفوظة بتاريخها", "legacy_closure"),
    ):
        if payload.get(key):
            yield title, network_report_content(payload[key]) if key == "network_analysis" else payload[key]
    for key in ("tasks", "evidence", "imports", "custody", "history", "limitations"):
        if payload.get(key):
            content = payload[key]
            if key == "tasks":
                content = [{**task, "title": task_title(task["title"], task.get("system_key"), "ar")} for task in content]
            yield LABELS[key], content


def line_html(text):
    label, separator, value = text.partition(": ")
    if separator:
        return f'{html.escape(label)}: <bdi dir="auto">{html.escape(value)}</bdi>'
    return f'<bdi dir="auto">{html.escape(text)}</bdi>'


def render_html(payload) -> str:
    case = payload["case"]
    content = []
    outline = []
    for index, (title, value) in enumerate(sections(payload), 1):
        outline.append(f'<li><a href="#report-section-{index}">{html.escape(title)}</a></li>')
        content_lines = list(lines(value))
        rows = []
        for line_index, (depth, text) in enumerate(content_lines):
            heading = " report-group-heading" if line_index + 1 < len(content_lines) and content_lines[line_index + 1][0] > depth else ""
            rows.append(f'<p class="report-line depth-{min(depth, 3)}{heading}">{line_html(text)}</p>')
        content.append(f'<section id="report-section-{index}" class="report-section"><h2>{html.escape(title)}</h2>{"".join(rows)}</section>')
    digest = hashlib.sha256(canonical(payload).encode()).hexdigest()
    title_class = ' class="report-title-long"' if len(case["title"]) > 100 else ""
    cover = f'<header class="report-cover"><p class="report-wordmark" lang="en" dir="ltr">SOCify</p><p dir="ltr">TACTICAL WORKBENCH</p><p>تقرير فرز وتحقيق سريع في حادثة أمنية</p><h1{title_class}><bdi dir="auto">{html.escape(display(case["title"]))}</bdi></h1><p><bdi dir="ltr">{html.escape(case["reference"])}</bdi> · الإصدار {payload["revision"]}</p></header><p class="report-note">نسخة ثابتة من بيانات القضية عند إعدادها. اعتماد هذه النسخة محفوظ منفصلًا في سجل المنصة. البصمة أدناه تخص JSON المعياري، لا بايتات PDF.</p><p dir="ltr">SHA-256: <bdi>{digest}</bdi></p>'
    navigation = '<nav class="report-outline" aria-label="أقسام التقرير"><h2>محتويات التقرير</h2><ul>' + "".join(outline) + "</ul></nav>"
    style = (
        report_style()
        + ".report-cover{break-inside:avoid}.report-cover h1.report-title-long{font-size:20pt;line-height:1.5}.report-section{break-before:auto}.report-section:first-of-type{break-before:page}.report-line{white-space:pre-wrap;overflow-wrap:anywhere;margin:0 0 10pt;font-size:14pt}.report-group-heading{break-after:avoid;font-weight:700}.depth-1{padding-inline-start:10pt}.depth-2,.depth-3{padding-inline-start:18pt}"
    )
    return f'<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><title>{html.escape(case["reference"])}</title><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; font-src data:; img-src data:"><style>{style}</style></head><body>{cover}{navigation}{"".join(content)}</body></html>'


def bundled_report_asset_fetcher(url, timeout=10, ssl_context=None):
    from weasyprint.urls import URLFetcherResponse, URLFetchingError

    root = Path(__file__).resolve().parent.parent / "static" / "fonts"
    for filename in {
        "Almarai-Regular.woff2",
        "Almarai-Bold.woff2",
        "IBMPlexSans.woff2",
        "BalooBhaijaan2.woff2",
        "IBMPlexSansArabic-Regular.woff2",
        "IBMPlexSansArabic-Bold.woff2",
        *(font["file"] for font in report_fonts()),
    }:
        content = (root / filename).read_bytes()
        if url == "data:font/woff2;base64," + base64.b64encode(content).decode():
            return URLFetcherResponse(url, body=content, headers={"Content-Type": "font/woff2"})
    raise URLFetchingError("Only bundled SOCify report fonts are permitted")


def render_docx(payload) -> bytes:
    from docx import Document
    from docx.enum.table import WD_TABLE_DIRECTION
    from docx.shared import Pt

    document = Document()
    section = document.sections[0]
    section.page_width, section.page_height = Pt(595), Pt(842)
    section.top_margin, section.bottom_margin = Pt(42), Pt(40)
    section.left_margin, section.right_margin = Pt(44), Pt(44)
    tokens = design_tokens()
    ink = tokens["colors"]["paper-text"][0].lstrip("#")
    for name, size in [("Normal", 14), ("Title", 24), ("Heading 1", 20), ("Heading 2", 18)]:
        configure_style(document.styles[name], tokens["typography"]["en"]["family"], tokens["typography"]["ar"]["family"], size, ink, name != "Normal")
    embed_report_fonts(document)
    wordmark = document.add_paragraph().add_run("SOCify")
    wordmark.font.name = tokens["typography"]["display"]["en"]
    wordmark.font.size = Pt(26)
    document.add_heading("SOCify Tactical Workbench", 0)
    title = document.add_paragraph(style="Heading 1")
    set_direction(title)
    add_report_run(title, display(payload["case"]["title"]), True)
    document.add_paragraph(display(payload["case"]["reference"]))
    notice = document.add_paragraph()
    set_direction(notice)
    add_report_run(notice, "نسخة ثابتة؛ راجع سجل الاعتماد في المنصة. تعرض الأوقات كما سجلت، ولا يعني وقت إعداد التقرير وقت اكتشاف الحادث.")
    for section_index, (title, value) in enumerate(sections(payload)):
        heading = document.add_paragraph(style="Heading 1")
        set_direction(heading)
        add_report_run(heading, title, True)
        if section_index == 0:
            heading.paragraph_format.page_break_before = True
        content_lines = list(lines(value))
        table = document.add_table(rows=0, cols=2)
        table.table_direction = WD_TABLE_DIRECTION.RTL
        table.autofit = False
        table.columns[0].width, table.columns[1].width = Pt(145), Pt(362)
        for line_index, (depth, text) in enumerate(content_lines):
            is_heading = line_index + 1 < len(content_lines) and content_lines[line_index + 1][0] > depth
            label, separator, value = text.partition(": ")
            cells = table.add_row().cells
            if is_heading or not separator or label not in LABELS.values():
                cell = cells[0].merge(cells[1])
                paragraph = cell.paragraphs[0]
                set_direction(paragraph)
                paragraph.paragraph_format.keep_with_next = is_heading
                paragraph.paragraph_format.space_before = Pt(8)
                add_report_run(paragraph, text, is_heading)
            else:
                for index, content in enumerate((label, value)):
                    paragraph = cells[index].paragraphs[0]
                    set_direction(paragraph, any("\u0600" <= character <= "\u06ff" for character in content))
                    paragraph.paragraph_format.space_after = Pt(6)
                    add_report_run(paragraph, content, index == 0)
    output = io.BytesIO()
    document.save(output)
    return output.getvalue()


def render_files(payload):
    from weasyprint import HTML

    html_document = render_html(payload)
    markdown = [
        "# SOCify Tactical Workbench",
        "",
        html.escape(display(payload["case"]["title"])).replace("`", "\\u0060"),
        "",
        "نسخة ثابتة؛ راجع سجل الاعتماد في المنصة.",
        "",
    ]
    for title, value in sections(payload):
        markdown.extend([f"## {title}", "", "```text"])
        markdown.extend(text.replace("`", "\\u0060") for _, text in lines(value))
        markdown.extend(["```", ""])
    return {
        "json": canonical(payload).encode(),
        "html": html_document.encode(),
        "md": "\n".join(markdown).encode(),
        "docx": render_docx(payload),
        "pdf": HTML(string=html_document, url_fetcher=bundled_report_asset_fetcher).write_pdf(),
    }
