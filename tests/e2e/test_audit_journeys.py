"""User tasks for finding decisions and older activity in the retained audit history."""

import pytest
from playwright.sync_api import expect

from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_review_workflow import ARTIFACTS, review_session
from tests.e2e.test_scope_selection_journeys import PRIMARY, approve, open_card


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario", ["audit-case-decision-search", "audit-operation-resource-filter", "audit-empty-search-recover", "audit-history-pagination"]
)
def test_audit_user_goal(app, language, scenario):
    app.config.update(REQUIRE_CASE_APPROVAL=True, REQUIRE_INVESTIGATION_SELECTION=True, DEMO_MODE=False)
    with review_session(app, language, scenario) as (_analyst, manager, result):
        manager.login("manager@socify.local")
        open_card(manager, PRIMARY)
        approve(manager)
        reference = manager.state()["reference"]
        if scenario == "audit-history-pagination":
            for index in range(26):
                manager.nav("إدارة القضايا")
                manager.click("button", "إنشاء قضية")
                dialog = manager.page.get_by_role("dialog")
                dialog.locator("input[name=title]").fill(f"Later audit intake {index + 1:02}")
                manager.click("button", "حفظ", dialog)
            result["setup_only_case_requests"] = 26
        manager.nav("سجل التدقيق")
        form = manager.page.get_by_role("form", name=manager.text("بحث سجل التدقيق"))
        if scenario == "audit-case-decision-search":
            form.get_by_role("searchbox", name=manager.text("بحث"), exact=True).fill(reference)
            form.locator("select[name=action]").select_option("review")
            form.locator("select[name=resource]").select_option("case")
            manager.click("button", "بحث", form)
            rows = manager.page.locator("tbody tr")
            expect(rows).to_have_count(1)
            expect(rows).to_contain_text(reference)
            expect(rows).to_contain_text(PRIMARY)
            expect(rows.locator("td").nth(1)).not_to_be_empty()
            expect(rows.locator("details")).not_to_have_attribute("open", "")
            rows.locator("summary").click()
            expect(rows.locator("details")).to_contain_text(manager.text("معتمد"))
            result["outcomes"] = ["case reference locates its retained approval", "responsible actor and decision can be read", "details open on demand"]
        elif scenario == "audit-operation-resource-filter":
            form.locator("select[name=action]").select_option("login")
            form.locator("select[name=resource]").select_option("auth")
            form.locator("select[name=result]").select_option("success")
            manager.click("button", "بحث", form)
            rows = manager.page.locator("tbody tr")
            assert rows.count() >= 2
            for cell in rows.locator("td:nth-child(3)").all():
                expect(cell).to_have_text(manager.text("تسجيل الدخول"))
            manager.page.reload()
            manager.settle()
            expect(form.locator("select[name=action]")).to_have_value("login")
            expect(form.locator("select[name=resource]")).to_have_value("auth")
            expect(form.locator("select[name=result]")).to_have_value("success")
            result["outcomes"] = ["combine operation, resource and outcome filters", "applied filters survive reload"]
        elif scenario == "audit-empty-search-recover":
            query = "No matching decision in this workspace"
            form.locator("input[name=q]").fill(query)
            manager.click("button", "بحث", form)
            expect(manager.page.locator("#workspace")).to_contain_text(manager.text("لا توجد نتائج"))
            expect(form.locator("input[name=q]")).to_have_value(query)
            manager.click("button", "مسح المرشحات", form)
            expect(form.locator("input[name=q]")).to_have_value("")
            assert manager.page.locator("tbody tr").count() > 0
            result["outcomes"] = ["empty query result is clear", "clearing filters recovers the actual retained history"]
        else:
            form.locator("select[name=action]").select_option("create")
            form.locator("select[name=resource]").select_option("case")
            manager.click("button", "بحث", form)
            expect(manager.page.locator("tbody tr")).to_have_count(25)
            expect(manager.page.locator("tbody")).not_to_contain_text(reference)
            manager.click("button", "التالي")
            expect(manager.page.locator("tbody tr")).to_have_count(2)
            expect(manager.page.locator("tbody")).to_contain_text(reference)
            manager.page.reload()
            manager.settle()
            expect(manager.page.locator("tbody")).to_contain_text(reference)
            expect(form.locator("select[name=action]")).to_have_value("create")
            manager.page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-older.png"), full_page=True)
            manager.click("button", "السابق")
            expect(manager.page.locator("tbody tr")).to_have_count(25)
            expect(manager.page.locator("tbody")).not_to_contain_text(reference)
            result["outcomes"] = [
                "older case activity is reachable beyond the first page",
                "filters and page survive reload",
                "return to newer retained activity",
            ]
        assert_accessible(manager.page)
        for width in [390, 1440]:
            manager.page.set_viewport_size({"width": width, "height": 1000})
            assert manager.page.evaluate("document.documentElement.scrollWidth <= innerWidth"), width
            manager.page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-{width}.png"), full_page=True)
