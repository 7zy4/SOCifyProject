import json
import math
import os
import shutil
import threading

import pytest
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from tests.e2e.test_browser import launch_browser


@pytest.mark.e2e
@pytest.mark.parametrize("zoom_mode", ["css", "native"])
@pytest.mark.parametrize("analysis_view", ["files", "observables"])
def test_200_percent_zoom_keyboard_modal_and_searchable_choices(app, tmp_path, zoom_mode, analysis_view):
    app.config.update(LEGACY_TRAINING_TESTS=False, ALLOW_REGISTRATION=False, WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            if zoom_mode == "native":
                profile = tmp_path / "browser-profile"
                preferences = profile / "Default" / "Preferences"
                preferences.parent.mkdir(parents=True)
                zoom_level = math.log(2) / math.log(1.2)
                preferences.write_text(json.dumps({"partition": {"default_zoom_level": {"x": zoom_level, "1": zoom_level}}}))
                browser = playwright.chromium.launch_persistent_context(
                    str(profile),
                    channel=os.environ.get("SOCIFY_BROWSER_CHANNEL", "chromium"),
                    executable_path=shutil.which("chromium"),
                    headless=not bool(os.environ.get("DISPLAY")),
                    no_viewport=True,
                    locale="ar-SA",
                    args=["--window-size=1440,1000"],
                )
                page = browser.pages[0]
            else:
                browser = launch_browser(playwright)
                page = browser.new_page(locale="ar-SA", viewport={"width": 1440, "height": 1000})
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
            page.goto(root + f"/cases/{case['id']}?tab=analysis&analysis={analysis_view}")
            page.get_by_role("heading", name="المؤشرات" if analysis_view == "observables" else "العينات والتحليل الساكن", exact=True).wait_for()
            if zoom_mode == "native":
                assert page.evaluate("window.devicePixelRatio >= 1.99 && window.innerWidth <= 768"), "Native browser zoom did not reduce the CSS viewport"
                assert page.evaluate("Number(getComputedStyle(document.documentElement).zoom) === 1")
            else:
                page.evaluate("document.documentElement.style.zoom='2'")
                assert page.evaluate("Number(getComputedStyle(document.documentElement).zoom) === 2")
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), page.evaluate(
                "Array.from(document.querySelectorAll('main *')).filter(e=>e.getBoundingClientRect().right>innerWidth+1||e.getBoundingClientRect().left < -1).slice(0,12).map(e=>[e.tagName,e.className,e.getBoundingClientRect().width])"
            )
            if analysis_view == "files":
                page.locator(".analysis-tools a[href*='analysis=observables']").click()
                page.get_by_role("heading", name="المؤشرات", exact=True).wait_for()
                if zoom_mode == "css":
                    page.evaluate("document.documentElement.style.zoom='2'")
            add = page.get_by_role("button", name="إضافة المؤشرات", exact=True)
            add.focus()
            page.keyboard.press("Enter")
            dialog = page.get_by_role("dialog")
            assert dialog.evaluate("el => el.contains(document.activeElement)")
            assert dialog.evaluate("el => el.getBoundingClientRect().right <= innerWidth && el.getBoundingClientRect().left >= 0")
            choice = dialog.locator("input[name=type]")
            label = choice.evaluate("el => document.getElementById(el.getAttribute('list')).options[0].value")
            choice.focus()
            choice.press_sequentially(label[:1])
            choice.press("ArrowDown")
            choice.press("Enter")
            page.keyboard.press("Tab")
            assert choice.input_value() == label
            page.once("dialog", lambda confirmation: confirmation.accept())
            page.keyboard.press("Escape")
            assert page.get_by_role("dialog").count() == 0
            assert add.evaluate("el => el === document.activeElement")
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
