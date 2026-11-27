"""A new team's manager sees the set-up checklist on the case list, marks a step, and hides it."""

import re
import threading

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

from tests.e2e.browser_helpers import account_menu, assert_accessible, launch_browser


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_manager_marks_a_set_up_step_and_hides_the_checklist(app, language):
    app.config.update(WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def text(ar, en):
        return ar if language == "ar" else en

    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(locale="ar-SA" if language == "ar" else "en-US", viewport={"width": 1440, "height": 1000})
            page.set_default_timeout(15000)
            page.add_init_script(path="node_modules/axe-core/axe.min.js")
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            base = f"http://127.0.0.1:{server.server_port}"
            page.goto(base + "/login")
            page.locator("#email").fill("manager@socify.local")
            page.locator("#password").fill(DEMO_LOGIN_VALUE)
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/cases")
            checklist = page.locator(".onboarding-panel")
            expect(checklist.get_by_role("heading", name=text("ابدأ مع SOCify", "Get started with SOCify"), exact=True)).to_be_visible()
            expect(checklist.locator(".onboarding-steps > li")).to_have_count(6)
            summary = checklist.locator(".onboarding-progress")
            before = int(re.search(r"\d+", summary.inner_text())[0])
            step = checklist.locator(".onboarding-steps > li").filter(has_text="ATT&CK")
            expect(step).to_contain_text(text("لم يتم", "Not done"))
            step.get_by_role("button", name=text("تحديد كمنجز", "Mark as done"), exact=True).click()
            step = page.locator(".onboarding-panel .onboarding-steps > li").filter(has_text="ATT&CK")
            expect(step.get_by_role("button", name=text("إلغاء التحديد", "Clear mark"), exact=True)).to_be_visible()
            expect(page.locator(".onboarding-progress")).to_contain_text(str(before + 1))
            for theme in ("light", "dark"):
                account_menu(page).locator(f'[data-theme-option="{theme}"]').click()
                page.keyboard.press("Escape")
                for width in (390, 1440):
                    page.set_viewport_size({"width": width, "height": 1000})
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                    assert_accessible(page)
            page.locator(".onboarding-panel").get_by_role("button", name=text("إخفاء القائمة", "Hide checklist"), exact=True).click()
            expect(page.locator(".onboarding-panel")).to_have_count(0)
            page.reload()
            page.locator('#workspace[aria-busy="false"]').wait_for()
            expect(page.locator(".onboarding-panel")).to_have_count(0)
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
