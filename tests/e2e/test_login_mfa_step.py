"""The second sign-in step opens the code field and keeps what the user already typed."""

import sqlite3
import threading
import time

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

from socify.security import encrypt_secret, generate_totp_secret, totp_code
from socify.timeutils import iso_now
from tests.e2e.browser_helpers import assert_accessible, launch_browser


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_mfa_challenge_opens_and_focuses_the_code_field_without_losing_the_password(app, user_ids, language):
    app.config.update(WTF_CSRF_ENABLED=True)
    secret = generate_totp_secret()
    with app.app_context():
        ciphertext = encrypt_secret(secret)
    connection = sqlite3.connect(app.config["DATABASE"])
    with connection:
        connection.execute(
            "INSERT INTO mfa_enrollments (user_id, secret_ciphertext, enabled, verified_at, updated_at) VALUES (?, ?, 1, ?, ?)",
            (user_ids["analyst"], ciphertext, iso_now(), iso_now()),
        )
    connection.close()
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(locale="ar-SA" if language == "ar" else "en-US", viewport={"width": 390, "height": 900})
            page.add_init_script(path="node_modules/axe-core/axe.min.js")
            page.add_init_script(f"try {{ localStorage.setItem('socify-interface-language', '{language}'); }} catch (_) {{}}")
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            base = f"http://127.0.0.1:{server.server_port}"
            page.goto(base + "/login?next=/cases%3Fview%3Dmine")
            expect(page.locator("html")).to_have_attribute("lang", language)
            expect(page.locator("details.auth-mfa")).not_to_have_attribute("open", "")
            page.locator("#email").fill("analyst@socify.local")
            page.locator("#password").fill(DEMO_LOGIN_VALUE)
            with page.expect_response("**/api/auth/login") as challenge:
                page.locator("button[type=submit]").click()
            assert challenge.value.status == 428
            expect(page.locator("details.auth-mfa")).to_have_attribute("open", "")
            expect(page.locator("#mfa_code")).to_be_focused()
            expect(page.get_by_role("alert")).to_contain_text("authenticator" if language == "en" else "رمز المصادقة")
            expect(page.locator("#email")).to_have_value("analyst@socify.local")
            expect(page.locator("#password")).to_have_value(DEMO_LOGIN_VALUE)
            assert page.evaluate("localStorage.getItem('socify-login-mfa')") == "1"
            assert_accessible(page)
            page.locator("#mfa_code").fill(totp_code(secret, int(time.time())))
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/cases?view=mine")
            # A new visit without the session cookie shows that this browser remembers the code step.
            # Leave the case list first, so none of its requests can bring the session cookie back.
            page.wait_for_load_state("networkidle")
            page.goto("about:blank")
            page.context.clear_cookies()
            page.goto(base + "/login")
            expect(page.locator("details.auth-mfa")).to_have_attribute("open", "")
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
