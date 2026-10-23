import shutil
import threading
from pathlib import Path

import pytest
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server


def launch_browser(playwright):
    executable = shutil.which("chromium") or shutil.which("google-chrome")
    return playwright.chromium.launch(executable_path=executable) if executable else playwright.chromium.launch()


def new_page(browser, **kwargs):
    axe_path = Path("node_modules/axe-core/axe.min.js").resolve()
    if not axe_path.exists():
        raise AssertionError("axe-core is required for browser accessibility tests")
    page = browser.new_page(**kwargs)
    page.add_init_script(path=str(axe_path))
    return page


def assert_accessible(page) -> None:
    results = page.evaluate("async () => await axe.run(document, {resultTypes: ['violations']})")
    violations = [item for item in results["violations"] if item["impact"] in {"serious", "critical"}]
    assert not violations, [(item["id"], item["impact"], [node["target"] for node in item["nodes"]]) for item in violations]


@pytest.mark.e2e
def test_browser_login_rtl_navigation_and_mobile_layout(app) -> None:
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = new_page(browser, viewport={"width": 390, "height": 844})
            response = page.goto(f"http://127.0.0.1:{server.server_port}/login")
            assert response is not None and response.ok
            assert page.locator("html").get_attribute("dir") == "rtl"
            assert page.locator("input[name=email]").is_visible()
            assert page.locator("input[name=password]").is_visible()
            page.locator("input[name=email]").fill("analyst@socify.local")
            page.locator("input[name=password]").fill("Training-Safe-Password-2026!")
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/dashboard")
            assert page.locator("main").is_visible()
            assert page.locator("nav").is_visible()
            assert_accessible(page)
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.e2e
def test_browser_training_requires_explicit_assessment_submission(app) -> None:
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = new_page(browser)
            base = f"http://127.0.0.1:{server.server_port}"
            page.goto(base + "/login")
            page.locator("input[name=email]").fill("analyst@socify.local")
            page.locator("input[name=password]").fill("Training-Safe-Password-2026!")
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/dashboard")
            page.goto(base + "/lab")
            page.get_by_role("button", name="بدء جلسة").first.click()
            page.get_by_role("button", name="تسليم التقييم بعد التحقيق").first.wait_for()
            page.goto(base + "/scores")
            page.get_by_text("لا توجد نتائج", exact=True).first.wait_for(state="visible")
            page.goto(base + "/lab")
            page.get_by_role("button", name="تسليم التقييم بعد التحقيق").first.click()
            page.get_by_text("تم اعتماد المحاولة وحساب الدرجة", exact=False).wait_for()
            page.goto(base + "/scores")
            page.locator("#workspace table tbody tr").first.wait_for()
            assert page.locator("#workspace table tbody tr").count() >= 1
            assert page.get_by_text("لا توجد نتائج", exact=True).count() == 0
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.e2e
def test_browser_case_workspace_supports_investigation_actions(app) -> None:
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = new_page(browser, viewport={"width": 1440, "height": 1000})
            base = f"http://127.0.0.1:{server.server_port}"
            page.goto(base + "/login")
            page.locator("input[name=email]").fill("analyst@socify.local")
            page.locator("input[name=password]").fill("Training-Safe-Password-2026!")
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/dashboard")
            page.goto(base + "/incidents")
            page.get_by_role("button", name="تحقيق جديد").first.click()
            page.locator("#case-form input[name=title]").fill("Browser investigation workspace")
            page.locator("#case-form textarea[name=description]").fill("Verified through the interactive browser workflow")
            page.locator("#case-form button[type=submit]").click()
            row = page.locator("tbody tr").filter(has_text="Browser investigation workspace")
            row.get_by_role("button").click()
            page.get_by_role("heading", name="دورة الحياة").wait_for()
            page.locator("form").filter(has_text="ملاحظة التحقيق").locator("textarea[name=body]").fill("تم التحقق من مصدر السجل وسلامة الأثر")
            page.get_by_role("button", name="إضافة الملاحظة").click()
            page.get_by_text("تم التحقق من مصدر السجل وسلامة الأثر").wait_for()
            page.get_by_role("button", name="إكمال").first.click()
            workflow = page.locator("#case-transition-form")
            workflow.locator("select[name=status]").select_option("open")
            workflow.locator("input[name=reason]").fill("بدء التحقيق الموثق")
            workflow.get_by_role("button", name="تسجيل الانتقال").click()
            page.locator(".case-workspace").get_by_text("open", exact=True).first.wait_for()
            assert page.get_by_role("heading", name="الأدلة وسلسلة الحيازة").is_visible()
            assert page.get_by_role("heading", name="سجل النشاط").is_visible()
            assert_accessible(page)
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.e2e
def test_browser_import_preview_commit_and_evidence_controls(app) -> None:
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = new_page(browser, viewport={"width": 1440, "height": 1000})
            base = f"http://127.0.0.1:{server.server_port}"
            page.goto(base + "/login")
            page.locator("input[name=email]").fill("analyst@socify.local")
            page.locator("input[name=password]").fill("Training-Safe-Password-2026!")
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/dashboard")
            page.goto(base + "/imports")
            payload = b'{"source":"browser-import","event_type":"browser_event","severity":"low","title":"Browser import"}'
            page.locator("input[type=file]").set_input_files({"name": "browser.jsonl", "mimeType": "application/x-ndjson", "buffer": payload})
            page.get_by_role("button", name="معاينة").click()
            page.get_by_text('"commit_required": true', exact=False).wait_for()
            page.get_by_role("button", name="تحقق واستورد").click()
            page.get_by_text('"accepted": 1', exact=False).wait_for()
            page.reload()
            row = page.locator("tbody tr").filter(has_text="browser.jsonl")
            row.get_by_text("completed", exact=True).wait_for()
            assert row.get_by_role("link", name="الدليل الخام").is_visible()
            assert row.get_by_text("100%", exact=True).is_visible()
            assert_accessible(page)
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
