import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import expect

from tests.e2e.test_review_workflow import review_session


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_invitee_can_correct_an_email_without_reopening_the_invitation(app, language):
    with review_session(app, language, "correct-invitation-email") as (_analyst, manager, result):
        manager.login("manager@socify.local")
        manager.nav("الفريق")
        invite = manager.page.locator("section.panel").filter(has=manager.page.get_by_role("heading", name=manager.text("دعوة عضو جديد"), exact=True))
        invite.locator("input[name=email]").fill("layan@example.test")
        invite.locator("input[name=role]").fill(manager.page.evaluate("() => autopsyLabel('analyst')"))
        manager.click("button", "حفظ", invite)
        url = manager.page.get_by_label(manager.text("رابط التسجيل بالدعوة"), exact=True).input_value()
        manager.click("button", "إغلاق", manager.page.get_by_role("dialog"))
        page = manager.page.context.browser.new_page(locale="ar-SA" if language == "ar" else "en-US")
        page.goto(url)
        page.wait_for_load_state("networkidle")
        token = page.locator("input[name=invitation_token]").input_value()
        assert "invitation_token" not in page.url
        page.locator("input[name=name]").fill("Layan")
        page.locator("input[name=email]").fill("wrong@example.test")
        page.locator("input[name=password]").fill(DEMO_LOGIN_VALUE)
        page.locator("button[type=submit]").click()
        expect(page.get_by_role("alert")).to_be_visible()
        assert page.locator("input[name=invitation_token]").input_value() == token
        expect(page.locator("input[name=name]")).to_have_value("Layan")
        expect(page.locator("input[name=email]")).to_have_value("wrong@example.test")
        expect(page.locator("input[name=password]")).to_have_value("")
        if language == "en":
            expect(page.get_by_role("alert")).to_contain_text("invitation")
        page.locator("input[name=email]").fill("layan@example.test")
        page.locator("input[name=password]").fill(DEMO_LOGIN_VALUE)
        page.locator("button[type=submit]").click()
        page.wait_for_url("**/login")
        page.locator("input[name=email]").fill("layan@example.test")
        page.locator("input[name=password]").fill(DEMO_LOGIN_VALUE)
        page.locator("button[type=submit]").click()
        page.wait_for_url("**/cases")
        assert page.evaluate("async () => (await api('/api/auth/me')).user.role") == "analyst"
        page.close()
        result["outcomes"] = [
            "wrong email rejected with translated feedback",
            "name, email and invitation retained",
            "password not retained",
            "corrected email joined the assigned team role",
        ]
