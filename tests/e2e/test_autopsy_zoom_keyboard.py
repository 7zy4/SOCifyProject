import shutil
import threading

import pytest
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server


@pytest.mark.e2e
def test_200_percent_content_zoom_keyboard_modal_and_searchable_choices(app):
    app.config.update(LEGACY_TRAINING_TESTS=False, ALLOW_REGISTRATION=False, WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=shutil.which("chromium"))
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            root = f"http://127.0.0.1:{server.server_port}"
            page.goto(root + "/login")
            page.locator("input[name=email]").fill("manager@socify.local")
            page.locator("input[name=password]").fill("Training-Safe-Password-2026!")
            page.locator("button[type=submit]").focus()
            page.keyboard.press("Enter")
            page.wait_for_url("**/cases")
            case = page.evaluate(
                "async () => await api('/api/cases',{method:'POST',body:{title:'Native browser zoom acceptance',reason:'forensic_review',objective:'Verify readable keyboard operated investigation at native 200 percent zoom'}})"
            )
            page.goto(root + f"/cases/{case['id']}?tab=analysis")
            page.get_by_role("heading", name="العينات والتحليل الساكن", exact=True).wait_for()
            page.evaluate("document.documentElement.style.zoom='2'")
            assert page.evaluate("Number(getComputedStyle(document.documentElement).zoom) === 2")
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            add = page.get_by_role("button", name="إضافة المؤشرات", exact=True)
            add.focus()
            page.keyboard.press("Enter")
            dialog = page.get_by_role("dialog")
            assert dialog.evaluate("el => el.contains(document.activeElement)")
            assert dialog.evaluate("el => el.getBoundingClientRect().right <= innerWidth && el.getBoundingClientRect().left >= 0")
            choice = dialog.locator("input[name=type]")
            label = choice.evaluate("el => document.getElementById(el.getAttribute('list')).options[0].value")
            choice.focus()
            choice.fill(label)
            page.keyboard.press("Tab")
            assert choice.input_value() == label
            page.keyboard.press("Escape")
            assert page.get_by_role("dialog").count() == 0
            assert add.evaluate("el => el === document.activeElement")
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
