"""An analyst sees a new assignment under the bell, opens it to reach the case, and the count clears."""

import threading

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

from tests.e2e.browser_helpers import assert_accessible, launch_browser


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_an_assignment_reaches_the_bell_and_opens_the_case(app, client, login_as, user_ids, language):
    login_as("soc_manager")
    made = client.post(
        "/api/cases", json={"title": "VPN brute force", "reason": "alert_review", "objective": "Contain and scope", "assignee": user_ids["analyst"]}
    )
    assert made.status_code == 201, made.json
    case = made.json
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
            page.locator("#email").fill("analyst@socify.local")
            page.locator("#password").fill(DEMO_LOGIN_VALUE)
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/cases")
            bell = page.locator(".sidebar .notification-bell")
            expect(bell.locator(".notification-count")).to_have_text("1")
            expect(bell).to_have_attribute("aria-label", text("الإشعارات، 1 غير مقروءة", "Notifications, 1 unread"))
            bell.click()
            panel = page.get_by_role("region", name=text("الإشعارات", "Notifications"))
            item = panel.get_by_role("link").first
            expect(item).to_contain_text(case["reference"])
            expect(item).to_contain_text("VPN brute force")
            assert_accessible(page)
            page.keyboard.press("Escape")
            expect(panel).to_have_count(0)
            expect(bell).to_be_focused()
            for width in (390, 1440):
                page.set_viewport_size({"width": width, "height": 1000})
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.set_viewport_size({"width": 1440, "height": 1000})
            bell.click()
            panel.get_by_role("link").first.click()
            page.wait_for_url(f"**/cases/{case['id']}")
            expect(page.locator(".sidebar .notification-count")).to_be_hidden()
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
