import copy
import hashlib
import io

import pytest
from defusedxml import ElementTree as ET
from docx import Document

from socify.autopsy_domain import canonical
from socify.autopsy_report_render import directional_html, lines, render_docx, render_html, report_blocks, report_table, sections


def test_investigation_report_keeps_the_record_content_and_identity_without_storage_wrappers():
    payload = {
        "case": {"title": "Retained investigation", "reference": "CASE-REPORT"},
        "revision": 1,
        "records": {
            "timeline": [
                {
                    "id": 42,
                    "kind": "timeline",
                    "version": 3,
                    "created_by": 81,
                    "updated_by": 82,
                    "created_by_name": "Noura retained author",
                    "updated_by_name": "Hadi retained reviewer",
                    "payload": {"title": "Reviewed login", "notes": "<b>Source retained</b>", "event_time": "2026-11-02T09:00:00Z", "evidence_id": 17},
                }
            ]
        },
    }
    original = copy.deepcopy(payload)
    content = dict(sections(payload))["الخط الزمني والتعليقات"]
    text = "\n".join(text for _, text in lines(content))
    assert text.count("العنوان: Reviewed login") == 1
    assert text.count("المعرف: 42") == 1
    assert "ملاحظات التحقيق: <b>Source retained</b>" in text
    assert "مرجع الدليل: 17" in text and "2026-11-02T09:00:00Z" in text
    assert "المؤلف: Noura retained author" in text and "آخر محرر: Hadi retained reviewer" in text
    assert "معرف المؤلف" not in text and "معرف آخر محرر" not in text
    assert "payload" not in text and "notes:" not in text
    for document in (render_html(payload), report_table(content)):
        assert "&lt;b&gt;Source retained&lt;/b&gt;" in document
        assert document.count("Reviewed login") == 1
        assert "ملاحظات التحقيق" in document
    assert payload == original


def test_number_only_record_identity_is_labelled_once():
    records = [{"id": 52, "notes": "Retained observation"}]
    assert sum(text == "المعرف: 52" for _, text in lines(records)) == 1
    table = report_table(records)
    assert table.count("52") == 1
    assert "المعرف: 52" in table


def test_report_questions_precede_answers_even_after_canonical_key_sorting():
    records = [{"answer": "An expired exception remained active.", "question": "Why was access allowed?"}]
    text = "\n".join(text for _, text in lines(records))
    assert text.startswith("السؤال: Why was access allowed?\nالإجابة:")
    table = report_table(records, localize=True)
    assert table.index("Why was access allowed?") < table.index("An expired exception remained active.")
    assert table.count("Why was access allowed?") == 1
    assert "<span data-ui-copy>السؤال</span>" in table
    imports = [{"accepted_records": 12, "original_filename": "collected.jsonl"}]
    assert list(lines(imports))[0] == (0, "اسم الأصل: collected.jsonl")


@pytest.mark.parametrize(
    ("source", "latin"),
    [
        ("الأسباب الجذرية و5 Whys", "5 Whys"),
        ("الرابط: https://evidence.example.test/path/", "https://evidence.example.test/path/"),
        ("وقت الحدث: 2026-10-20T10:01:00Z", "2026-10-20T10:01:00Z"),
        ('الدليل: <img src="https://evidence.example.test/">', '<img src="https://evidence.example.test/">'),
    ],
)
def test_mixed_direction_fragments_preserve_literal_evidence_and_isolate_latin_order(source, latin):
    root = ET.fromstring("<root>" + directional_html(source) + "</root>")
    assert "".join(root.itertext()) == source
    assert any(node.attrib == {"dir": "ltr"} and node.text == latin for node in root.findall("bdi"))
    assert root.find(".//img") is None


def test_export_keeps_short_evidence_together_and_repeats_identity_only_with_long_record_digest():
    short = {"id": 2, "title": "Retained evidence", "details": "فحص مختصر / Short review", "sha256": "a" * 64}
    long = {"id": 9, "title": "Long evidence", "details": "ملاحظة طويلة / Long observation " * 100, "sha256": "b" * 64}
    payload = {"case": {"title": "تحقيق / Investigation", "reference": "CASE-PAGING"}, "revision": 1, "evidence": [short, long]}
    before = canonical(payload)
    blocks = list(report_blocks(payload["evidence"]))
    assert [compact for _, _, compact in blocks] == [True, False]
    assert [line for _, block, _ in blocks for line in block] == list(lines(payload["evidence"]))
    rendered = render_html(payload)
    assert rendered.count('class="report-entry report-entry-compact"') == 1
    assert rendered.count('class="report-integrity"') == 1
    assert rendered.count("Long evidence") == 2
    assert rendered.count("Retained evidence") == 1
    assert long["sha256"] in rendered and short["sha256"] in rendered
    assert canonical(payload) == before


def test_latin_isolation_handles_long_unbroken_values_without_removing_spaces_or_newlines():
    source = "  الدليل https://evidence.example.test/" + "a" * 4096 + " \n\tنهاية: " + "B" * 2048 + "  "
    root = ET.fromstring("<root>" + directional_html(source) + "</root>")
    assert "".join(root.itertext()) == source
    assert len(root.findall("bdi")) == 2


def test_report_explains_generated_scope_and_timing_without_rewriting_retained_evidence():
    literal = "Retained text / نص محفوظ: containment: negative interval excluded; checked_clear; alert_review; <script>"
    payload = {
        "case": {"title": "تحقيق / Investigation", "reference": "CASE-DIAGNOSTICS", "status": "escalated"},
        "revision": 1,
        "context": {"reason": "alert_review"},
        "metrics": {
            "containment_delay_seconds": None,
            "acknowledgement_delay_seconds": 0,
            "issues": [
                "containment: negative interval excluded",
                "recovery: future timestamp",
                "detection: missing or invalid timestamp",
                "unknown: retained diagnostic",
            ],
        },
        "scope": {"asset_records": 2, "counts_by_assessment": {"checked_clear": 1, "confirmed": 1}, "excluded_observations": 1},
        "evidence": [{"id": 1, "title": "Retained evidence", "details": literal, "sha256": "a" * 64}],
    }
    original = canonical(payload)
    expected_hash = hashlib.sha256(original.encode()).hexdigest()
    content = dict(sections(payload))
    metrics = "\n".join(text for _, text in lines(content["قياسات مراحل الاستجابة"]))
    scope = "\n".join(text for _, text in lines(content["نطاق الفحص وحدود الاستنتاج"]))
    assert "وقت الاحتواء المثبت: نهاية الفترة تسبق بدايتها؛ لم تُحسب المدة" in metrics
    assert "وقت التعافي المثبت: طابع زمني مستقبلي؛ استُبعد من القياس" in metrics
    assert "وقت الرصد المثبت: الوقت مفقود أو غير صالح؛ لم تُحسب المدة" in metrics
    assert "unknown: retained diagnostic" in metrics
    assert "المدة حتى الاحتواء بالثواني: غير قابل للحساب" in metrics
    assert "المدة حتى الإقرار بالثواني: 0" in metrics
    assert "عدد الأصول الموثقة: 2" in scope and "فُحص ضمن نطاق موثق: 1" in scope and "متأثر مؤكد: 1" in scope
    assert content["الهدف وقرار التنبيه ونتيجة الهجوم"]["reason"] == "مراجعة تنبيه"
    rendered = render_html(payload)
    assert expected_hash in rendered and "مصعّدة" in rendered and "&lt;script&gt;" in rendered
    document = Document(io.BytesIO(render_docx(payload)))
    cells = [cell.text for table in document.tables for row in table.rows for cell in row.cells]
    assert literal in cells and "غير قابل للحساب" in cells and "0" in cells
    assert "عدد الأصول الموثقة" in cells and "فُحص ضمن نطاق موثق" in cells and "مصعّدة" in cells
    assert hashlib.sha256(canonical(payload).encode()).hexdigest() == expected_hash
    assert canonical(payload) == original
