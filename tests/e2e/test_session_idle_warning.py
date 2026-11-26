"""The page warns before an idle session ends, keeps it on request, and returns to sign-in when the server has ended it."""

import sqlite3
import threading
from datetime import timedelta

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

from socify.timeutils import utc_now
from tests.e2e.browser_helpers import assert_accessible, launch_browser


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_idle_warning_keeps_the_session_and_an_ended_session_returns_to_sign_in(app, language):
    app.config.update(WTF_CSRF_ENABLED=True, SESSION_IDLE_SECONDS=300)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(locale="ar-SA" if language == "ar" else "en-US", viewport={"width": 390, "height": 900})
            page.set_default_timeout(15000)
            page.add_init_script(path="node_modules/axe-core/axe.min.js")
            page.add_init_script(f"try {{ localStorage.setItem('socify-interface-language', '{language}'); }} catch (_) {{}}")
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.clock.install()
            base = f"http://127.0.0.1:{server.server_port}"
            page.goto(base + "/login")
            page.locator("#email").fill("analyst@socify.local")
            page.locator("#password").fill(DEMO_LOGIN_VALUE)
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/cases")
            page.wait_for_load_state("networkidle")
            warning = page.locator("#session-idle-warning")
            expect(warning).to_have_count(0)
            # With a five-minute limit the page warns two minutes before its conservative deadline of four minutes.
            page.clock.fast_forward("02:05")
            expect(warning).to_be_visible()
            expect(warning).to_contain_text("two minutes" if language == "en" else "دقيقتين")
            stay = warning.get_by_role("button", name="Stay signed in" if language == "en" else "البقاء متصلًا", exact=True)
            expect(stay).to_be_focused()
            assert_accessible(page)
            with page.expect_request(lambda request: request.url.endswith("/api/auth/me")) as kept:
                stay.click()
            assert "x-socify-activity" not in kept.value.headers
            expect(warning).to_have_count(0)
            # The server ends the session while the page is idle; the next background check finds out without extending it.
            connection = sqlite3.connect(app.config["DATABASE"])
            with connection:
                connection.execute(
                    "UPDATE auth_sessions SET last_seen_at = ? WHERE revoked_at IS NULL",
                    ((utc_now() - timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),),
                )
            connection.close()
            with page.expect_request(lambda request: request.url.endswith("/api/auth/me")) as checked:
                page.clock.fast_forward("04:05")
            assert checked.value.headers.get("x-socify-activity") == "background"
            page.wait_for_url("**/login?next=%2Fcases&reason=idle")
            expect(page.get_by_role("status")).to_contain_text("inactivity" if language == "en" else "لعدم النشاط")
            assert page.locator("input[name=next]").input_value() == "/cases"
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
