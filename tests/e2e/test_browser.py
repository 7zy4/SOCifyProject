import threading

import pytest
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server


@pytest.mark.e2e
def test_browser_login_rtl_navigation_and_mobile_layout(app) -> None:
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page(viewport={"width": 390, "height": 844})
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
            browser = playwright.chromium.launch()
            page = browser.new_page()
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
            assert page.get_by_text("لا توجد نتائج", exact=True).first.is_visible()
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
