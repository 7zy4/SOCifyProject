import threading
from urllib.parse import parse_qs, urlparse

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from tests.e2e.test_browser import launch_browser


@pytest.mark.e2e
def test_language_toggle_persists_and_preserves_case_content(app, tmp_path):
    app.config.update(LEGACY_TRAINING_TESTS=False, ALLOW_REGISTRATION=False)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    output = tmp_path / "language-screenshots"
    output.mkdir(exist_ok=True)
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            root = f"http://127.0.0.1:{server.server_port}"
            page.goto(root + "/login")
            assert page.locator("html").get_attribute("lang") == "ar"
            page.screenshot(path=str(output / "login-ar-desktop.png"), full_page=True)
            page.set_viewport_size({"width": 390, "height": 844})
            page.screenshot(path=str(output / "login-ar-mobile.png"), full_page=True)
            page.get_by_role("button", name="Switch interface to English").click()
            page.wait_for_function("document.documentElement.lang === 'en'")
            assert page.locator("html").get_attribute("dir") == "ltr"
            page.get_by_label("Email", exact=True).fill("manager@socify.local")
            page.get_by_label("Password", exact=True).fill(DEMO_LOGIN_VALUE)
            page.screenshot(path=str(output / "login-en-mobile.png"), full_page=True)
            page.set_viewport_size({"width": 1440, "height": 1000})
            page.screenshot(path=str(output / "login-en-desktop.png"), full_page=True)
            page.get_by_role("button", name="Sign in", exact=True).click()
            page.wait_for_url("**/cases")
            page.get_by_role("heading", name="Team cases", exact=True).wait_for()
            result = page.evaluate("""async () => await api('/api/cases', {method:'POST', body:{
                title:'القضايا', reason:'forensic_review', objective:'Keep case evidence and authored interface translations separate'
            }})""")
            page.reload()
            page.get_by_role("heading", name="Team cases", exact=True).wait_for()
            page.get_by_role("cell", name="القضايا", exact=True).wait_for()
            assert page.locator("html").get_attribute("lang") == "en"
            page.goto(root + f"/cases/{result['id']}?tab=reports")
            page.get_by_role("heading", name="Reports and review", exact=True).wait_for()
            sharing = page.get_by_label("Report sharing policy", exact=True)
            assert sharing.input_value() == "Full report for authorized internal use"
            assert sharing.evaluate("element => element.autopsyValue()") == "full"
            page.screenshot(path=str(output / "reports-en-desktop.png"), full_page=True)
            page.goto(root + "/cases")
            page.get_by_role("heading", name="Team cases", exact=True).wait_for()
            page.screenshot(path=str(output / "cases-en-desktop.png"), full_page=True)
            page.set_viewport_size({"width": 390, "height": 844})
            page.screenshot(path=str(output / "cases-en-mobile.png"), full_page=True)
            page.goto(root + f"/cases/{result['id']}?tab=investigation")
            page.get_by_role("heading", name="القضايا", exact=True).first.wait_for()
            assert page.locator("html").get_attribute("dir") == "ltr"
            page.screenshot(path=str(output / "case-en-mobile.png"), full_page=True)
            page.get_by_role("button", name="تغيير لغة الواجهة إلى العربية").click()
            page.wait_for_function("document.documentElement.lang === 'ar'")
            page.get_by_role("heading", name="القضايا", exact=True).first.wait_for()
            assert page.locator("html").get_attribute("dir") == "rtl"
            assert parse_qs(urlparse(page.url).query)["tab"] == ["investigation"]
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
