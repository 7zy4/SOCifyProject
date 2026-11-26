"""A manager creates an API token on the team page, sees it once, uses it, and revokes it."""

import threading

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

from tests.e2e.browser_helpers import assert_accessible, launch_browser


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_manager_creates_uses_and_revokes_a_token(app, language):
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
            page.goto(base + "/team")
            tokens = page.locator("section.panel").filter(has=page.get_by_role("heading", name=text("رموز API", "API tokens"), exact=True))
            expect(tokens).to_contain_text(text("لا توجد رموز API", "No API tokens"))
            tokens.get_by_label(text("اسم الرمز", "Token name"), exact=True).fill("SIEM read access")
            tokens.get_by_label(text("قراءة القضايا", "Read cases"), exact=True).check()
            tokens.get_by_role("button", name=text("إنشاء رمز", "Create token"), exact=True).click()
            dialog = page.get_by_role("dialog")
            value = dialog.locator("[data-api-token]").input_value()
            assert value.startswith("socify_pat_")
            assert_accessible(page)
            dialog.get_by_role("button", name=text("إغلاق", "Close"), exact=True).click()
            expect(tokens.locator("tbody tr")).to_have_count(1)
            assert value not in page.content()
            used = page.request.get(base + "/api/cases", headers={"Authorization": f"Bearer {value}"})
            assert used.status == 200
            for width in (390, 1440):
                page.set_viewport_size({"width": width, "height": 1000})
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                assert_accessible(page)
            page.once("dialog", lambda prompt: prompt.accept())
            tokens.get_by_role("button", name=text("إلغاء الرمز", "Revoke token"), exact=True).click()
            expect(tokens.locator("tbody tr")).to_contain_text(text("ملغى", "Revoked"))
            assert page.request.get(base + "/api/cases", headers={"Authorization": f"Bearer {value}"}).status == 401
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
