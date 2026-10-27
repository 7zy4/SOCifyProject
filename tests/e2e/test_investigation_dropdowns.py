import shutil
import threading

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server


@pytest.mark.e2e
def test_branded_choices_and_documented_why_answers(app, tmp_path):
    app.config.update(LEGACY_TRAINING_TESTS=False, ALLOW_REGISTRATION=False)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=shutil.which("chromium"))
            page = browser.new_page(viewport={"width": 390, "height": 844})
            page.goto(f"http://127.0.0.1:{server.server_port}/login")
            page.locator("input[name=email]").fill("analyst@socify.local")
            page.locator("input[name=password]").fill(DEMO_LOGIN_VALUE)
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/cases")
            page.get_by_role("button", name="إنشاء قضية", exact=True).click()
            dialog = page.get_by_role("dialog")
            dialog.locator(".choice-toggle").first.click()
            dialog.get_by_role("option", name="مراجعة تنبيه", exact=True).click()
            assert dialog.locator("input[name=reason]").input_value() == "مراجعة تنبيه"
            assert dialog.locator("input[name=reason]").get_attribute("aria-expanded") == "false"
            classification = dialog.locator("input[name=classification]")
            classification.focus()
            classification.press("ArrowDown")
            assert dialog.get_by_role("option").first.evaluate("el => el === document.activeElement")
            page.keyboard.press("Escape")
            assert classification.evaluate("el => el === document.activeElement")
            classification.press("ArrowDown")
            classification.press("Enter")
            assert dialog.is_visible()
            assert classification.input_value()
            page.screenshot(path=str(tmp_path / "investigation-dropdown-mobile.png"), full_page=True)
            dialog.get_by_role("button", name="إغلاق", exact=True).click()
            page.evaluate('autopsyModal("Why answers", autopsyForm({whys: {whys: true}}, async () => {}))')
            dialog = page.get_by_role("dialog")
            dialog.get_by_role("button", name="إضافة سؤال لماذا").click()
            dialog.get_by_label("محور الإجابة").select_option(label="فجوة في المراقبة")
            answer = dialog.get_by_label("الإجابة", exact=True)
            assert answer.input_value() == "فجوة في المراقبة: "
            assert answer.evaluate("el => !el.checkValidity()")
            answer.fill("Evidence-backed statement remains editable")
            assert answer.evaluate("el => el.checkValidity()")
            dialog.get_by_label("محور الإجابة").select_option(label="خطأ بشري")
            assert answer.input_value() == "Evidence-backed statement remains editable"
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
