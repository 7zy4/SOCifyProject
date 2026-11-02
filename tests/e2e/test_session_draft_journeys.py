"""Continue a real browser draft after a separate session revokes access."""

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import expect

from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_draft_recovery import fill_answers
from tests.e2e.test_review_workflow import ARTIFACTS, review_session


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", ["session-draft-reauthentication", "session-different-account", "session-dialog-reauthentication"])
def test_expired_session_preserves_the_user_task(app, language, scenario):
    with review_session(app, language, scenario) as (j, other, result):
        page = j.page
        note = "Pending identity approval: preserve this unsaved assessment."
        if scenario == "session-dialog-reauthentication":
            j.click("link", "التحقيق والخط الزمني")
            label = page.evaluate("() => SOCifyLocale.template`إضافة ${autopsyLabel('hypothesis')}`")
            page.get_by_role("button", name=label, exact=True).click()
            form_dialog = page.get_by_role("dialog")
            form_dialog.locator("input[name=title]").fill("Identity approval hypothesis")
            form_dialog.locator("textarea[name=statement]").fill(note)
            form_dialog.locator("input[name=assessment]").fill(page.evaluate("autopsyLabel('open')"))
        else:
            j.click("link", "التقارير والمراجعة")
            fill_answers(j, note)
        other.login("analyst@socify.local")
        other.page.goto(other.base + "/profile")
        other.settle()
        sessions = other.page.evaluate("() => api('/api/auth/sessions')")
        original = next(item for item in sessions["items"] if not item["is_current"] and not item["revoked_at"])
        row = other.page.locator("tr").filter(has=other.page.get_by_role("cell", name=str(original["id"]), exact=True))
        other.click("button", "إلغاء الجلسة", row)
        page.on("dialog", lambda dialog: dialog.dismiss())
        if scenario == "session-dialog-reauthentication":
            j.click("button", "حفظ", form_dialog)
        else:
            j.click("button", "حفظ إجابات التقرير")
        recovery = page.get_by_role("dialog", name=j.text("تجديد الجلسة"), exact=True)
        expect(recovery).to_be_visible()
        assert_accessible(page)
        page.set_viewport_size({"width": 390, "height": 844})
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-recovery.png"))
        page.set_viewport_size({"width": 1440, "height": 1000})
        if scenario != "session-dialog-reauthentication":
            expect(page.locator("input[name=executive_note]")).to_have_value(note)
        with page.context.expect_page() as opened:
            recovery.get_by_role("link", name=j.text("تسجيل الدخول"), exact=True).click()
        login = opened.value
        login.wait_for_load_state()
        login.locator("input[name=email]").fill("manager@socify.local" if scenario == "session-different-account" else "analyst@socify.local")
        login.locator("input[name=password]").fill(DEMO_LOGIN_VALUE)
        login.locator("button[type=submit]").click()
        login.wait_for_url("**/cases")
        if scenario == "session-different-account":
            j.click("button", "متابعة العمل", recovery)
            expect(recovery.get_by_role("alert")).to_contain_text(j.text("سجّل الدخول بالحساب نفسه لمتابعة هذه المسودة."))
            expect(page.locator("input[name=executive_note]")).to_have_value(note)
            login.locator(".account-menu summary").click()
            login.locator("form[action='/logout'] button").click()
            login.wait_for_url("**/login")
            login.locator("input[name=email]").fill("analyst@socify.local")
            login.locator("input[name=password]").fill(DEMO_LOGIN_VALUE)
            login.locator("button[type=submit]").click()
            login.wait_for_url("**/cases")
        j.click("button", "متابعة العمل", recovery)
        expect(recovery).not_to_be_visible()
        login.close()
        if scenario == "session-dialog-reauthentication":
            expect(form_dialog.locator("textarea[name=statement]")).to_have_value(note)
            j.click("button", "حفظ", form_dialog)
            expect(form_dialog).not_to_be_visible()
            records = page.evaluate("id => api(`/api/cases/${id}/records?kind=hypothesis`)", j.case_id)
            assert records["items"][0]["payload"]["statement"] == note
        else:
            j.click("button", "حفظ إجابات التقرير")
            page.reload()
            j.settle()
            expect(page.locator("input[name=executive_note]")).to_have_value(note)
        assert not page.evaluate("SOCifyDrafts.hasChanges()")
        result["outcomes"] = [
            "revoked session could not save",
            "draft retained in the document",
            "same account reauthenticated",
            "explicit retry persisted the original draft",
        ]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_signing_in_again_in_another_tab_preserves_the_original_draft(app, language):
    with review_session(app, language, "session-tab-signin-draft") as (j, _other, result):
        j.click("link", "التقارير والمراجعة")
        note = "Retain this assessment while I sign in again in another tab."
        fill_answers(j, note)
        j.page.locator(".account-menu summary").click()
        with j.page.context.expect_page() as opened:
            j.page.locator(".account-menu a[href='/profile']").click(button="middle")
        tab = opened.value
        tab.locator("#workspace[aria-busy=false]").wait_for()
        tab.locator(".account-menu summary").click()
        tab.locator("form[action='/logout'] button").click()
        tab.wait_for_url("**/login")
        tab.locator("input[name=email]").fill("analyst@socify.local")
        tab.locator("input[name=password]").fill(DEMO_LOGIN_VALUE)
        tab.locator("button[type=submit]").click()
        tab.wait_for_url("**/cases")
        statuses = []
        j.page.on(
            "response",
            lambda response: statuses.append(response.status) if response.request.method == "PUT" and response.url.endswith("/quick-report") else None,
        )
        j.click("button", "حفظ إجابات التقرير")
        recovery = j.page.get_by_role("dialog", name=j.text("تجديد الجلسة"), exact=True)
        expect(recovery).to_be_visible()
        expect(j.page.locator("input[name=executive_note]")).to_have_value(note)
        j.click("button", "متابعة العمل", recovery)
        j.click("button", "حفظ إجابات التقرير")
        assert statuses == [400, 200]
        j.page.reload()
        j.settle()
        expect(j.page.locator("input[name=executive_note]")).to_have_value(note)
        tab.close()
        result["outcomes"] = [
            "old document token rejected after another-tab sign-in",
            "renewal checked the same identity",
            "explicit retry saved the original assessment",
        ]
