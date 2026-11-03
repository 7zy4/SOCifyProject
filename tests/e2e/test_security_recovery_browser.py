"""Exercise the full recovery-code journey through the account interface."""

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import expect

from socify.security import totp_code
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_review_workflow import review_session


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_new_recovery_code_works_for_login_and_account_reverification(app, language):
    with review_session(app, language, "security-recovery-code", create_case=False) as (j, _manager, result):
        j.page.goto(j.base + "/profile")
        j.settle()
        if j.page.locator("html").get_attribute("lang") != language:
            j.page.locator("[data-language-toggle]").click()
            j.settle()
        start = j.page.get_by_role("button", name=j.text("بدء إعداد MFA"), exact=True).locator("..")
        start.locator("input[name=current_password]").fill(DEMO_LOGIN_VALUE)
        j.click("button", "بدء إعداد MFA", start)
        dialog = j.page.locator("dialog[open]")
        secret = dialog.get_by_role("textbox", name=j.text("مفتاح إعداد المصادقة"), exact=True).input_value()
        dialog.locator("input[name=code]").fill(totp_code(secret))
        j.click("button", "تأكيد وتفعيل المصادقة", dialog)
        codes = j.page.locator("dialog[open] textarea").input_value().splitlines()
        assert len(codes) == 10 and all(len(code) == 32 for code in codes)
        j.page.keyboard.press("Escape")
        j.settle()
        j.page.locator(".account-menu > summary").click()
        j.click("button", "خروج", j.page.locator(".account-menu"))
        j.page.wait_for_url("**/login*")
        j.page.locator("input[name=email]").fill("analyst@socify.local")
        j.page.locator("input[name=password]").fill(DEMO_LOGIN_VALUE)
        j.page.locator(".auth-mfa > summary").click()
        j.page.locator("input[name=mfa_code]").fill(codes[0])
        expect(j.page.locator("input[name=mfa_code]")).to_have_value(codes[0])
        j.page.locator("button[type=submit]").click()
        j.page.wait_for_url("**/cases")
        j.page.goto(j.base + "/profile")
        j.settle()
        disable = j.page.get_by_role("button", name=j.text("إلغاء MFA بعد التحقق"), exact=True).locator("..")
        disable.locator("input[name=current_password]").fill(DEMO_LOGIN_VALUE)
        disable.locator("input[name=code]").fill(codes[0])
        j.click("button", "إلغاء MFA بعد التحقق", disable)
        expect(disable.get_by_role("status")).not_to_be_empty()
        assert j.page.evaluate("async () => (await api('/api/auth/mfa/status')).enabled")
        disable.locator("input[name=current_password]").fill(DEMO_LOGIN_VALUE)
        disable.locator("input[name=code]").fill(codes[1])
        expect(disable.locator("input[name=code]")).to_have_value(codes[1])
        j.click("button", "إلغاء MFA بعد التحقق", disable)
        expect(j.page.get_by_role("button", name=j.text("بدء إعداد MFA"), exact=True)).to_be_visible()
        assert not j.page.evaluate("async () => (await api('/api/auth/mfa/status')).enabled")
        for width in (390, 1440):
            j.page.set_viewport_size({"width": width, "height": 1000})
            assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            assert_accessible(j.page)
        result["kind"] = "security acceptance journey on isolated synthetic account"
        result["outcomes"] = [
            "enrolled through UI",
            "128-bit recovery code accepted at login",
            "used code rejected",
            "unused code accepted for account verification",
        ]
