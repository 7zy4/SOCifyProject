import base64
import hashlib
import html
import io
import re
from pathlib import Path

from .autopsy_domain import canonical
from .report_brand import report_style

FORMATS = {
    "json": "application/json",
    "html": "text/html",
    "md": "text/markdown",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "pdf": "application/pdf",
}
LABELS = {
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
    "performed_by": "المنفذ",
    "conclusion": "الاستنتاج",
    "limitations_text": "حدود الاستنتاج",
    "event_time": "وقت الحدث",
    "question": "لماذا؟",
    "answer": "الإجابة",
    "reference": "مرجع القضية",
    "revision": "إصدار التقرير",
    "profile": "سياسة مشاركة التقرير",
    "integrity_valid": "سلامة السلسلة عند إعداد التقرير",
}


def display(value) -> str:
    text = str(value) if value is not None else "غير مسجل"
    return re.sub("[\u202a-\u202e\u2066-\u2069]", lambda match: f"\\u{ord(match[0]):04x}", text)


def lines(value, depth=0):
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                yield depth, LABELS.get(key, key)
                yield from lines(item, depth + 1)
            else:
                yield depth, f"{LABELS.get(key, key)}: {display(item)}"
    elif isinstance(value, list):
        if not value:
            yield depth, "لا توجد عناصر مسجلة"
        for index, item in enumerate(value, 1):
            yield depth, f"— {index} —"
            yield from lines(item, depth + 1)
    else:
        yield depth, display(value)


def sections(payload):
    for key in ("summary", "case", "context", "metrics", "members", "alerts"):
        if key in payload:
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
        yield LABELS[kind], records
    yield "توثيق MITRE ATT&CK وإصداره وأدلته", payload.get("techniques", [])
    yield "الملاحظات المشتركة الموروثة", payload.get("shared_notes", [])
    for key in ("tasks", "evidence", "imports", "custody", "history", "limitations"):
        yield LABELS[key], payload.get(key, [])


def render_html(payload) -> str:
    case = payload["case"]
    content = []
    for title, value in sections(payload):
        rows = "".join(f'<p class="report-line depth-{min(depth, 3)}">{html.escape(text)}</p>' for depth, text in lines(value))
        content.append(f'<section class="report-section"><h2>{html.escape(title)}</h2>{rows}</section>')
    digest = hashlib.sha256(canonical(payload).encode()).hexdigest()
    cover = f'<header class="report-cover"><p dir="ltr">SOCify Digital Autopsy</p><h1>{html.escape(display(case["title"]))}</h1><p>{html.escape(case["reference"])} · الإصدار {payload["revision"]}</p></header><p class="report-note">نسخة ثابتة من بيانات القضية عند إعدادها. اعتماد هذه النسخة محفوظ منفصلًا في سجل المنصة. البصمة أدناه تخص JSON المعياري، لا بايتات PDF.</p><p>SHA-256: <bdi>{digest}</bdi></p>'
    style = (
        report_style()
        + ".report-line{white-space:pre-wrap;overflow-wrap:anywhere;margin:0 0 10pt;font-size:14pt}.depth-1{padding-inline-start:10pt}.depth-2,.depth-3{padding-inline-start:18pt}"
    )
    return f'<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><title>{html.escape(case["reference"])}</title><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; font-src data:"><style>{style}</style></head><body>{cover}{"".join(content)}</body></html>'


def local_font_fetcher(url, timeout=10, ssl_context=None):
    from weasyprint.urls import URLFetchingError

    root = Path(__file__).resolve().parent.parent / "static" / "fonts"
    for filename in ("BalooBhaijaan2.woff2", "IBMPlexSansArabic-Regular.woff2", "IBMPlexSansArabic-Bold.woff2"):
        content = (root / filename).read_bytes()
        if url == "data:font/woff2;base64," + base64.b64encode(content).decode():
            return {"string": content, "mime_type": "font/woff2"}
    raise URLFetchingError("Only bundled SOCify report fonts are permitted")


def render_docx(payload) -> bytes:
    from docx import Document
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Pt, RGBColor

    document = Document()
    section = document.sections[0]
    section.page_width, section.page_height = Pt(595), Pt(842)
    section.top_margin, section.bottom_margin = Pt(42), Pt(40)
    section.left_margin, section.right_margin = Pt(44), Pt(44)
    normal = document.styles["Normal"]
    normal.font.name, normal.font.size, normal.font.color.rgb = "IBM Plex Sans Arabic", Pt(14), RGBColor.from_string("1D3461")
    for name in ("Title", "Heading 1", "Heading 2"):
        document.styles[name].font.name = "Baloo Bhaijaan 2"
        document.styles[name].font.color.rgb = RGBColor.from_string("1C4286")
    document.add_heading("SOCify Digital Autopsy", 0)
    document.add_heading(display(payload["case"]["title"]), 1)
    document.add_paragraph(f"{payload['case']['reference']} · {payload['revision']}")
    document.add_paragraph("نسخة ثابتة؛ راجع سجل الاعتماد في المنصة. تعرض الأوقات كما سجلت، ولا يعني وقت إعداد التقرير وقت اكتشاف الحادث.")
    for title, value in sections(payload):
        document.add_heading(title, 1)
        for depth, text in lines(value):
            paragraph = document.add_paragraph(text)
            paragraph.paragraph_format.left_indent = Pt(min(depth, 3) * 8)
            bidi = OxmlElement("w:bidi")
            bidi.set(qn("w:val"), "1")
            paragraph._p.get_or_add_pPr().append(bidi)
    output = io.BytesIO()
    document.save(output)
    return output.getvalue()


def render_files(payload):
    from weasyprint import HTML

    html_document = render_html(payload)
    markdown = ["# SOCify Digital Autopsy", "", html.escape(display(payload["case"]["title"])).replace("`", "\\u0060"), "", "نسخة ثابتة؛ راجع سجل الاعتماد في المنصة.", ""]
    for title, value in sections(payload):
        markdown.extend([f"## {title}", "", "```text"])
        markdown.extend(text.replace("`", "\\u0060") for _, text in lines(value))
        markdown.extend(["```", ""])
    return {
        "json": canonical(payload).encode(),
        "html": html_document.encode(),
        "md": "\n".join(markdown).encode(),
        "docx": render_docx(payload),
        "pdf": HTML(string=html_document, url_fetcher=local_font_fetcher).write_pdf(),
    }
