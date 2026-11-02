"""Read a retained report through its review view, without raw schema labels."""

import re

import pytest
from playwright.sync_api import expect

from tests.e2e.test_batch_boundary_journeys import upload_logs
from tests.e2e.test_review_workflow import review_session


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_report_review_has_meaningful_sections_and_identifiable_evidence(app, language):
    with review_session(app, language, "report-review-readable-evidence") as (j, _manager, result):
        upload_logs(j, "identity-review.json", "Identity review evidence")
        j.click("link", "التقارير والمراجعة")
        j.click("button", "إعداد تقرير جديد")
        revision = j.page.locator(".report-revision")
        revision.locator("summary").filter(has_text=j.text("عرض بيانات النسخة للمراجعة")).click()
        preview = revision.locator(".report-preview")
        labels = preview.locator(":scope > dl > dt").all_text_contents()
        assert not [label for label in labels if re.fullmatch(r"[a-z]+(?:_[a-z]+)+", label)], labels
        assert "schema" not in labels and j.text("إصدار التقرير") not in labels and j.text("إصدار القضية") not in labels
        expect(preview.get_by_text(j.text("كامل للاستخدام الداخلي المصرح"), exact=True)).to_be_visible()
        expect(preview.get_by_text(j.text("نتائج الأجهزة"), exact=True)).to_have_count(0)
        heading = preview.locator("dt").filter(has_text=j.text("الأصول المستوردة وإصدارات المعالجة"))
        details = heading.locator("+ dd > details")
        details.locator(":scope > summary").click()
        expect(details.locator("dt").first).to_contain_text("identity-review.json")
        for width in (390, 1440):
            j.page.set_viewport_size({"width": width, "height": 1000})
            assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        result["outcomes"] = [
            "readable review headings",
            "empty unrelated sections omitted",
            "evidence identified by retained filename",
            "snapshot remains available",
        ]
