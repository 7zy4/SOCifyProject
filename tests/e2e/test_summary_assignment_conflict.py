"""Review a colleague's newer responsibility before replacing it."""

import pytest
from playwright.sync_api import expect

from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_case_membership_journeys import member_row
from tests.e2e.test_case_summary_recovery_journeys import member_form
from tests.e2e.test_followup_handoff_journeys import evidence_images, manager_case
from tests.e2e.test_review_workflow import ARTIFACTS, ReviewJourney, review_session


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_responsibility_change_requires_review_of_a_colleagues_newer_assignment(app, language):
    with review_session(app, language, "summary-member-colleague-conflict") as (j, manager, result):
        manager_case(j, manager)
        person = j.page.evaluate("state.user.name")
        form = member_form(manager, person)
        page = manager.page.context.browser.new_page(locale="ar-SA" if language == "ar" else "en-US")
        page.on("pageerror", lambda error: result["browser_errors"].append(str(error)))
        colleague = ReviewJourney(page, manager.base, result["steps"])
        colleague.login("manager@socify.local")
        colleague.case_id, colleague.case_url = j.case_id, j.case_url
        page.goto(j.case_url)
        colleague.settle()
        other = member_form(colleague, person)
        other.locator("[name=responsibility]").fill(page.evaluate("caseResponsibilityLabel('owner')"))
        colleague.click("button", "حفظ", other)
        manager.click("button", "حفظ", form)
        expect(form.locator("[role=alert]")).to_be_visible()
        expect(form.locator("[role=alert]")).to_have_text(manager.text("راجع تحديثات القضية قبل متابعة الحفظ"))
        member = next(row for row in manager.state()["members"] if row["user_id"] == j.page.evaluate("state.user.id"))
        assert member["responsibility"] == "owner", "A stale responsibility form must not undo the colleague's newer assignment"
        expect(member_row(manager, person)).to_contain_text(manager.text("مسؤول القضية"))
        form.locator("details.case-form-review > summary").click()
        assert_accessible(manager.page)
        for width in (390, 1440):
            manager.page.set_viewport_size({"width": width, "height": 1000})
            assert manager.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            current_value = form.locator("details.case-form-review").get_by_role("cell", name=manager.text("مسؤول القضية"), exact=True)
            expect(current_value).to_be_visible()
            bounds = current_value.bounding_box()
            assert bounds and bounds["x"] >= 0 and bounds["x"] + bounds["width"] <= width, (
                "The current responsibility must be readable without horizontal scrolling"
            )
            form.screenshot(path=str(ARTIFACTS / f"{result['scenario']}-{language}-review-{width}.png"))
        manager.click("button", "متابعة بعد المراجعة", form)
        manager.click("button", "حفظ", form)
        expect(member_row(manager, person)).to_contain_text(manager.page.evaluate("caseResponsibilityLabel('reviewer')"))
        page.close()
        evidence_images(manager, result)
        result["outcomes"] = [
            "A stale assignment cannot replace the colleague's responsibility",
            "The manager reviews current ownership, retains their draft and explicitly saves it",
        ]
