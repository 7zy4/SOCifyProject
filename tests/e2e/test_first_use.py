import json
import threading

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

from tests.e2e.test_browser import assert_accessible, launch_browser


@pytest.mark.e2e
@pytest.mark.parametrize("language,width", [("ar", 390), ("en", 1440)])
def test_first_visit_can_reach_case_alerts_from_log_intake(app, language, width):
    app.config.update(LEGACY_TRAINING_TESTS=False, WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(locale="ar-SA" if language == "ar" else "en-US", viewport={"width": width, "height": 1000})
            page.add_init_script(path="node_modules/axe-core/axe.min.js")
            root = f"http://127.0.0.1:{server.server_port}"
            page.goto(root + "/login")
            expect(page.locator("html")).to_have_attribute("lang", language)
            assert page.evaluate("localStorage.getItem('socify-interface-language')") is None
            page.locator("input[name=email]").fill("analyst@socify.local")
            page.locator("input[name=password]").fill(DEMO_LOGIN_VALUE)
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/cases")
            page.goto(root + "/log-management")
            page.locator('#workspace[aria-busy="false"]').wait_for()

            def text(ar, en):
                return ar if language == "ar" else en

            page.get_by_role("button", name=text("إنشاء قضية", "Create case"), exact=True).click()
            dialog = page.get_by_role("dialog")
            dialog.locator("input[name=title]").fill("First investigation")
            dialog.get_by_role("button", name=text("حفظ", "Save"), exact=True).click()
            page.wait_for_url("**/cases/*?tab=logs")
            page.locator('#workspace[aria-busy="false"]').wait_for()
            case_id = page.url.split("/cases/")[1].split("?")[0]
            assert not page.locator('input[name="source_label"]').is_visible()
            assert not page.locator('input[name="credential"]').is_visible()
            assert not page.get_by_role("button", name=text("اعتماد الاستيراد", "Approve import"), exact=True).is_visible()
            page.get_by_text(text("خيارات الاستيراد", "Import options"), exact=True).click()
            expect(page.locator('input[name="source_label"]')).to_be_visible()
            page.get_by_text(text("خيارات الاستيراد", "Import options"), exact=True).click()
            content = json.dumps(
                [
                    {
                        "title": "First finding",
                        "hostname": "APP-SRV01",
                        "process_name": "powershell.exe",
                        "command_line": "powershell.exe -EncodedCommand YQ==",
                        "timestamp": "2026-11-02T02:20:00Z",
                    }
                ]
            ).encode()
            page.locator('input[name="file"]').set_input_files({"name": "events.json", "mimeType": "application/json", "buffer": content})
            page.get_by_role("button", name=text("استيراد وفحص فوري", "Quick import and scan"), exact=True).click()
            review = page.get_by_role("link", name=text("مراجعة التنبيهات", "Review alerts"), exact=True)
            expect(review).to_be_visible()
            assert f"case_id={case_id}" in review.get_attribute("href")
            review.click()
            page.locator("[data-alert-row]").first.wait_for()
            assert page.locator("[data-alert-row]").count() == 1
            page.locator("[data-alert-toggle]").first.click()
            expect(page.locator(".dossier-view")).to_contain_text("APP-SRV01")
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            assert_accessible(page)
            denied = page.goto(root + "/cases/999999")
            assert denied.status == 404
            expect(page.get_by_role("heading", name=text("الصفحة غير متاحة", "Page unavailable"), exact=True)).to_be_visible()
            page.get_by_role("link", name=text("العودة إلى القضايا", "Return to cases"), exact=True).click()
            page.wait_for_url("**/cases")
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
