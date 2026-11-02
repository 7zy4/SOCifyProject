import threading
from pathlib import Path

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from tests.e2e.test_browser import assert_accessible, launch_browser
from tests.unit.test_falco import falco


@pytest.mark.e2e
@pytest.mark.parametrize("language,width", [("ar", 1440), ("en", 390)])
def test_runtime_context_typography_and_case_report(app, language, width):
    app.config.update(LEGACY_TRAINING_TESTS=False, WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    output = Path("artifacts/runtime/screenshots")
    output.mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(locale="ar-SA", viewport={"width": width, "height": 1000})
            page.add_init_script(path=str(Path("node_modules/axe-core/axe.min.js").resolve()))
            page.add_init_script(
                f"localStorage.setItem('socify-interface-language','{language}');localStorage.setItem('socify-interface-theme','{'dark' if language == 'ar' else 'light'}');"
            )
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            base = f"http://127.0.0.1:{server.server_port}"
            page.goto(base + "/login")
            page.locator("input[name=email]").fill("manager@socify.local")
            page.locator("input[name=password]").fill(DEMO_LOGIN_VALUE)
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/cases")
            page.locator('#workspace[aria-busy="false"]').wait_for()
            case = page.evaluate(
                """async record => {
                const c=await api('/api/cases',{method:'POST',body:{title:'Checkout container investigation'}});
                await api(`/api/cases/${c.id}/imports`,{method:'POST',body:{filename:'runtime.json',content:JSON.stringify([record])}});
                return c;
            }""",
                falco(),
            )
            page.goto(base + "/monitoring")
            page.locator("[data-alert-row]").first.wait_for()
            assert page.evaluate(
                "Array.from(document.querySelectorAll('.monitoring-surface time')).every(el => getComputedStyle(el).fontFamily === getComputedStyle(document.querySelector('.alert-name')).fontFamily)"
            )
            version = "إصدار القاعدة" if language == "ar" else "Rule version"
            assert version not in page.locator(".monitoring-surface").inner_text()
            page.locator("[data-alert-toggle]").first.click()
            page.locator(".dossier-view").wait_for()
            assert version not in page.locator(".dossier-view").inner_text()
            assert "telemetry_schema" not in page.locator(".dossier-view").inner_text()
            assert page.locator(".dossier-view table").count() == 1
            assert "payments" in page.locator(".dossier-view").inner_text()
            assert "checkout-7" in page.locator(".dossier-view").inner_text()
            assert (
                "collector-pod-7"
                in page.get_by_role("row", name=("حساس الجمع" if language == "ar" else "Collector") + " collector-pod-7", exact=True).inner_text()
            )
            assert "JetBrains Mono" in page.locator(".dossier-view pre").evaluate("el => getComputedStyle(el).fontFamily")
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            assert_accessible(page)
            page.evaluate("window.scrollTo(0,0)")
            page.screenshot(path=str(output / f"runtime-{language}-{width}.png"), full_page=True)
            page.evaluate(
                """async id => {
                const guide=await api(`/api/cases/${id}/quick-report`);
                await api(`/api/cases/${id}/quick-report`,{method:'PUT',body:{answers:Object.fromEntries(guide.questions.map(q=>[q.id,q.options[0].value]))}});
            }""",
                case["id"],
            )
            page.goto(base + f"/cases/{case['id']}/quick-report/print")
            page.locator(".report-sheet").wait_for()
            assert "checkout-7" in page.locator(".report-sheet").inner_text()
            assert page.evaluate(
                "Array.from(document.querySelectorAll('.meta-grid .mono')).every(el => getComputedStyle(el).fontFamily === getComputedStyle(document.body).fontFamily)"
            )
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            assert_accessible(page)
            page.screenshot(path=str(output / f"runtime-report-{language}-{width}.png"), full_page=True)
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
