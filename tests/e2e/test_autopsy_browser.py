import json
import shutil
import threading
from pathlib import Path

import pytest
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server


@pytest.mark.e2e
def test_case_first_operational_browser_with_csrf_and_mobile_layout(app):
    app.config.update(LEGACY_TRAINING_TESTS=False, ALLOW_REGISTRATION=False, WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=shutil.which("chromium"))
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            page.add_init_script(path=str(Path("node_modules/axe-core/axe.min.js").resolve()))
            page.goto(f"http://127.0.0.1:{server.server_port}/login")
            page.locator("input[name=email]").fill("analyst@socify.local")
            page.locator("input[name=password]").fill("Training-Safe-Password-2026!")
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/cases")
            assert page.locator("#primary-nav a[href='/lab']").count() == 0
            page.get_by_role("button", name="إنشاء قضية", exact=True).click()
            dialog = page.get_by_role("dialog")
            dialog.locator("input[name=title]").fill("Browser autopsy case")
            dialog.locator("input[name=reason]").fill("مراجعة تنبيه")
            dialog.locator("textarea[name=objective]").fill("Verify impact using retained evidence")
            dialog.get_by_role("button", name="حفظ", exact=True).click()
            page.wait_for_url("**/cases/*")
            page.get_by_role("heading", name="Browser autopsy case", exact=True).first.wait_for()
            assert page.locator("textarea[name=objective]").input_value() == "Verify impact using retained evidence"
            page.get_by_role("link", name="الأصول والمؤشرات", exact=True).click()
            page.get_by_role("button", name="إضافة الأصول والأجهزة", exact=True).click()
            dialog = page.get_by_role("dialog")
            dialog.locator("input[name=name]").fill("Internal web defender")
            dialog.locator("input[name=type]").fill("خادم ويب")
            dialog.locator("input[name=role]").fill("مدافع أو هدف")
            dialog.get_by_role("button", name="حفظ", exact=True).click()
            page.get_by_role("heading", name="Internal web defender", exact=True).wait_for()
            violations = page.evaluate("async () => (await axe.run(document)).violations.filter(item => ['serious', 'critical'].includes(item.impact))")
            assert not violations, [(item["id"], item["nodes"]) for item in violations]
            for width in (360, 390, 768, 1440):
                page.set_viewport_size({"width": width, "height": 1000})
                assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), width
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.e2e
def test_case_import_preview_commit_and_export_browser(app):
    app.config.update(LEGACY_TRAINING_TESTS=False, ALLOW_REGISTRATION=False, WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=shutil.which("chromium"))
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            page.add_init_script(path=str(Path("node_modules/axe-core/axe.min.js").resolve()))
            page.goto(f"http://127.0.0.1:{server.server_port}/login")
            page.locator("input[name=email]").fill("analyst@socify.local")
            page.locator("input[name=password]").fill("Training-Safe-Password-2026!")
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/cases")
            page.get_by_role("button", name="إنشاء قضية", exact=True).click()
            dialog = page.get_by_role("dialog")
            dialog.locator("input[name=title]").fill("Browser import investigation")
            dialog.locator("input[name=reason]").fill("مراجعة تنبيه")
            dialog.locator("textarea[name=objective]").fill("Preserve and inspect the original log evidence")
            dialog.get_by_role("button", name="حفظ", exact=True).click()
            page.wait_for_url("**/cases/*")
            page.get_by_role("link", name="السجلات والأدلة", exact=True).click()
            raw = b'{"title":"Browser linked log","event_time":"2026-10-24T12:00:00Z","source_ip":"192.0.2.20"}\n'
            page.locator("input[type=file]").set_input_files({"name": "browser-evidence.jsonl", "mimeType": "application/x-ndjson", "buffer": raw})
            page.get_by_role("button", name="معاينة السجلات والبصمة", exact=True).click()
            page.locator("pre").filter(has_text="Browser linked log").wait_for()
            page.get_by_role("button", name="اعتماد الاستيراد", exact=True).click()
            page.get_by_role("cell", name="Browser linked log", exact=True).first.wait_for()
            with page.expect_download() as capture:
                page.get_by_role("link", name="تنزيل الأصل", exact=True).click()
            assert Path(capture.value.path()).read_bytes() == raw
            with page.expect_download() as capture:
                page.locator("a[href*='format=json&redacted=0']").click()
            data = json.loads(Path(capture.value.path()).read_text())
            assert data[0]["title"] == "Browser linked log"
            assert data[0]["source_ip"] == "192.0.2.20"
            violations = page.evaluate("async () => (await axe.run(document)).violations.filter(item => ['serious', 'critical'].includes(item.impact))")
            assert not violations, [(item["id"], item["nodes"]) for item in violations]
            page.set_viewport_size({"width": 390, "height": 1000})
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
