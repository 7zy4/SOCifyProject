"""Read, share and recover the specific evidence scope granted to an analyst."""

import csv
import io
import json
from pathlib import Path

import pytest
from playwright.sync_api import expect

from tests.e2e.test_review_workflow import review_session


def upload_logs(journey, filename, title):
    journey.click("link", "السجلات والأدلة")
    journey.page.locator("input[name=file]").set_input_files(
        {
            "name": filename,
            "mimeType": "application/json",
            "buffer": json.dumps([{"title": title, "timestamp": "2026-11-02T09:00:00Z", "hostname": "REVIEW-SRV"}]).encode(),
        }
    )
    journey.click("button", "استيراد وفحص فوري")
    expect(journey.page.get_by_role("cell", name=title, exact=True)).to_be_visible()


def restrict_batch(journey, filename, analyst_name=None):
    row = journey.page.locator("tr").filter(has=journey.page.get_by_role("cell", name=filename, exact=True))
    journey.click("button", "إدارة الدفعة", row)
    dialog = journey.page.get_by_role("dialog")
    dialog.locator("input[name=scope]").fill(journey.page.evaluate("autopsyLabel('restricted')"))
    members = dialog.get_by_label(journey.text("أعضاء الدفعة"), exact=True)
    if analyst_name:
        option = members.locator("option").filter(has_text=analyst_name).first
        members.select_option(option.get_attribute("value"))
    else:
        members.select_option([])
    dialog.locator("input[name=reason]").fill("Separate the sensitive identity records from the assigned review")
    journey.click("button", "حفظ", dialog)
    journey.click("button", "إغلاق", dialog)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", ["batch-assigned-scope", "batch-live-revocation", "batch-export-boundary", "batch-access-restored"])
def test_analyst_only_uses_the_granted_batch(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        manager.login("manager@socify.local")
        manager.page.goto(j.case_url)
        manager.settle()
        upload_logs(manager, "assigned.json", "Assigned review record")
        upload_logs(manager, "sensitive.json", "Restricted identity review record")
        name = j.page.evaluate("state.user.name")
        j.click("link", "السجلات والأدلة")
        expect(j.page.get_by_role("cell", name="Restricted identity review record", exact=True)).to_be_visible()
        if scenario == "batch-export-boundary":
            j.click("link", "التقارير والمراجعة")
            previous_export = j.page.get_by_role("link", name=j.text("تصدير حزمة الفريق"), exact=True).get_attribute("href")
            j.click("link", "السجلات والأدلة")
        restrict_batch(manager, "sensitive.json")
        if scenario == "batch-live-revocation":
            stale = j.page.locator("tr").filter(has=j.page.get_by_role("cell", name="Restricted identity review record", exact=True))
            j.click("button", "تفاصيل السجل", stale)
            expect(j.page.locator("#global-message")).to_be_visible()
            expect(j.page.get_by_role("dialog")).to_have_count(0)
            j.click("button", "بحث السجلات")
        else:
            j.page.reload()
            j.settle()
        expect(j.page.get_by_role("cell", name="Assigned review record", exact=True)).to_be_visible()
        expect(j.page.locator("main")).not_to_contain_text("Restricted identity review record")
        expect(j.page.locator("main")).not_to_contain_text("sensitive.json")
        expect(j.page.get_by_role("link", name=j.text("التقارير والمراجعة"), exact=True)).to_have_count(0)
        if scenario == "batch-export-boundary":
            label = j.page.evaluate("() => SOCifyLocale.template`${'CSV'} · بيانات وصفية محجوبة`")
            with j.page.expect_download() as exported:
                j.page.get_by_role("link", name=label, exact=True).click()
            content = Path(exported.value.path()).read_text(encoding="utf-8-sig")
            rows = list(csv.DictReader(io.StringIO(content)))
            assert len(rows) == 1 and rows[0]["title"] == "[REDACTED]"
            assert "Restricted identity review record" not in content
            response = j.page.goto(j.base + previous_export)
            assert response.status in {403, 404}
            assert "Restricted identity review record" not in j.page.locator("body").inner_text()
            j.page.goto(j.case_url + "?tab=logs")
            j.settle()
        if scenario == "batch-access-restored":
            restrict_batch(manager, "sensitive.json", name)
            j.page.reload()
            j.settle()
            expect(j.page.get_by_role("cell", name="Restricted identity review record", exact=True)).to_be_visible()
            expect(j.page.get_by_role("link", name=j.text("التقارير والمراجعة"), exact=True)).to_be_visible()
        for width in (390, 1440):
            j.page.set_viewport_size({"width": width, "height": 1000})
            assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        result["outcomes"] = ["only granted batch displayed", "restricted metadata absent after refresh", scenario]
