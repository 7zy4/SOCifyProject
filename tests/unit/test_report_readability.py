import copy

from socify.autopsy_report_render import lines, render_html, report_table, sections


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
