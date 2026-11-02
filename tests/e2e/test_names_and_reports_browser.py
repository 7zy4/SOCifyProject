import re
import threading
from pathlib import Path

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from tests.e2e.test_browser import assert_accessible, launch_browser
from tests.unit.test_snort import snort


@pytest.mark.e2e
@pytest.mark.parametrize("language,width", [("ar", 1440), ("en", 390)])
def test_account_language_and_labelled_network_report(app, language, width):
    app.config.update(LEGACY_TRAINING_TESTS=False, WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    output = Path("artifacts/account-report/screenshots")
    output.mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={"width": width, "height": 1000})
            page.add_init_script(path=str(Path("node_modules/axe-core/axe.min.js").resolve()))
            page.add_init_script(f"if(!localStorage.getItem('socify-interface-language')) localStorage.setItem('socify-interface-language','{language}');")
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            base = f"http://127.0.0.1:{server.server_port}"
            page.goto(base + "/login")
            page.locator("input[name=email]").fill("manager@socify.local")
            page.locator("input[name=password]").fill(DEMO_LOGIN_VALUE)
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/cases")
            page.goto(base + "/profile")
            form = page.locator("[data-display-name-form]")
            form.locator("input[name=name_ar]").fill("نورة")
            form.locator("input[name=name_en]").fill("Noura")
            form.locator("button[type=submit]").click()
            page.wait_for_function("() => document.querySelector('[data-account-name]')?.dataset.nameEn === 'Noura'")
            page.locator('#workspace[aria-busy="false"]').wait_for()
            # Explicitly exercise both directions with persistent saved names.
            first = "نورة" if language == "ar" else "Noura"
            other = "Noura" if language == "ar" else "نورة"
            page.locator("[data-language-toggle]").click()
            page.wait_for_function("expected => document.querySelector('[data-account-name]').textContent === expected", arg=other)
            page.locator('#workspace[aria-busy="false"]').wait_for()
            page.locator("[data-language-toggle]").click()
            page.wait_for_function("expected => document.querySelector('[data-account-name]').textContent === expected", arg=first)
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            assert_accessible(page)
            page.screenshot(path=str(output / f"profile-{language}.png"), full_page=True)
            case = page.evaluate(
                """async record => {
                const c=await api('/api/cases',{method:'POST',body:{title:'نورة — مراجعة تنبيه الشبكة'}});
                await api(`/api/cases/${c.id}/imports`,{method:'POST',body:{filename:'snort.json',content:JSON.stringify([record])}});
                return c;
            }""",
                snort(),
            )
            page.goto(base + "/monitoring")
            page.locator("[data-alert-row]").first.wait_for()
            assert first in page.locator(".monitoring-surface").inner_text()
            page.locator("[data-alert-toggle]").first.click()
            page.locator(".dossier-view").wait_for()
            assert "1:1000000:2" in page.locator(".dossier-view").inner_text()
            assert "نورة — مراجعة تنبيه الشبكة" in page.locator(".dossier-view").inner_text()
            assert_accessible(page)
            page.evaluate(
                """async id => {
                const guide=await api(`/api/cases/${id}/quick-report`);
                await api(`/api/cases/${id}/quick-report`,{method:'PUT',body:{answers:Object.fromEntries(guide.questions.map(q=>[q.id,q.options[0].value]))}});
            }""",
                case["id"],
            )
            page.goto(base + f"/cases/{case['id']}/quick-report/print")
            page.locator(".report-facts").first.wait_for()
            assert first in page.locator(".meta-grid").inner_text()
            assert "معرف قاعدة الرصد" in page.locator(".report-sheet").inner_text()
            for text in page.locator(".report-facts tr").all_inner_texts():
                assert not re.fullmatch(r"[\d\s—]+", text)
            assert page.evaluate(
                "Array.from(document.querySelectorAll('.report-facts tbody tr')).every(row => row.cells.length === 2 || (row.cells.length === 1 && row.cells[0].tagName === 'TH' && row.cells[0].colSpan === 2))"
            )
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            assert_accessible(page)
            page.screenshot(path=str(output / f"network-report-{language}.png"), full_page=True)
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
