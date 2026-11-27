"""A manager sets the team's response-time policy on the Team page; an analyst reads it; new cases follow it."""

import threading

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

from tests.e2e.browser_helpers import assert_accessible, launch_browser


def _login(page, base, email):
    page.goto(base + "/login")
    page.locator("#email").fill(email)
    page.locator("#password").fill(DEMO_LOGIN_VALUE)
    page.locator("button[type=submit]").click()
    page.wait_for_url("**/cases")


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_manager_sets_the_team_sla_policy_and_an_analyst_reads_it(app, database, language):
    app.config.update(WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def text(ar, en):
        return ar if language == "ar" else en

    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            context = browser.new_context(locale="ar-SA" if language == "ar" else "en-US", viewport={"width": 1440, "height": 1000})
            page = context.new_page()
            page.set_default_timeout(15000)
            page.add_init_script(path="node_modules/axe-core/axe.min.js")
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            base = f"http://127.0.0.1:{server.server_port}"
            _login(page, base, "manager@socify.local")
            page.goto(base + "/team")
            policy = page.locator("section.panel").filter(has=page.get_by_role("heading", name=text("مهلة الاستجابة", "Response time allowance"), exact=True))
            expect(policy).to_contain_text(text("لا توجد سياسة", "No policy"))
            hours = policy.get_by_label(text("حرجة", "Critical"), exact=True)
            expect(hours).to_have_attribute("lang", "en")
            hours.fill("0.5")
            policy.get_by_label(text("تقويم الاحتساب", "Calculation calendar"), exact=True).select_option("business")
            expect(policy.get_by_label(text("ساعة بدء العمل", "Business start hour"), exact=True)).to_be_visible()
            assert_accessible(page)
            policy.get_by_role("button", name=text("حفظ السياسة", "Save policy"), exact=True).click()
            policy = page.locator("section.panel").filter(has=page.get_by_role("heading", name=text("مهلة الاستجابة", "Response time allowance"), exact=True))
            expect(policy.locator(".sla-policy-grid li")).to_have_count(4)
            expect(policy.locator(".sla-policy-grid li").first).to_contain_text(text("30 دقيقة", "30 min"))
            row = database.execute("SELECT minutes, calendar FROM team_sla_policies").fetchone()
            assert '"critical": 30' in row["minutes"] and '"business"' in row["calendar"]
            for width in (390, 1440):
                page.set_viewport_size({"width": width, "height": 1000})
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            context.clear_cookies()
            page.set_viewport_size({"width": 1440, "height": 1000})
            _login(page, base, "analyst@socify.local")
            page.goto(base + "/team")
            policy = page.locator("section.panel").filter(has=page.get_by_role("heading", name=text("مهلة الاستجابة", "Response time allowance"), exact=True))
            expect(policy.locator(".sla-policy-grid li")).to_have_count(4)
            expect(policy.locator("form")).to_have_count(0)
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
