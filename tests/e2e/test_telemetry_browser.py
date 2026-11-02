import threading
from pathlib import Path

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

from tests.e2e.test_browser import assert_accessible, launch_browser
from tests.integration.test_telemetry_workflow import eve, osquery
from tests.unit.test_telemetry import zeek


@pytest.mark.e2e
@pytest.mark.parametrize("language,theme,width", [("ar", "dark", 1440), ("en", "light", 1440), ("ar", "light", 390), ("en", "dark", 390)])
def test_telemetry_investigation_and_evidence_navigation(app, language, theme, width):
    app.config.update(LEGACY_TRAINING_TESTS=False, WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    output = Path("artifacts/reference-review/screenshots")
    output.mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(locale="ar-SA", viewport={"width": width, "height": 1000})
            page.add_init_script(path=str(Path("node_modules/axe-core/axe.min.js").resolve()))
            page.add_init_script(f"localStorage.setItem('socify-interface-language','{language}');localStorage.setItem('socify-interface-theme','{theme}');")
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
                """async logs => {
                const c=await api('/api/cases',{method:'POST',body:{title:'Network incident review'}});
                await api(`/api/cases/${c.id}/imports`,{method:'POST',body:{filename:'sensor.json',content:JSON.stringify(logs)}});
                return c;
            }""",
                [*[zeek(i) for i in range(10)], eve(), osquery()],
            )
            page.goto(base + f"/cases/{case['id']}?tab=analysis&analysis=network")
            page.locator(".network-results table").wait_for()
            assert page.locator(".analysis-tools a[aria-current=page]").inner_text() == ("الشبكة" if language == "ar" else "Network")
            assert page.locator(".analysis-workspace .panel").count() == 1
            page.locator(".network-results button").first.click()
            page.locator(".network-detail table").wait_for()
            assert "203.0.113.9" in page.locator(".network-detail").inner_text()
            assert page.locator(".network-detail .evidence-links button").count() == 10
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            assert_accessible(page)
            page.evaluate("window.scrollTo(0,0)")
            page.screenshot(path=str(output / f"network-{language}-{theme}-{width}.png"), full_page=True)
            page.locator(".network-detail .evidence-links button").first.click()
            page.get_by_role("dialog").wait_for()
            assert '"uid": "C0"' in page.get_by_role("dialog").inner_text()
            page.keyboard.press("Escape")
            page.locator(".analysis-tools a[href*='analysis=endpoints']").click()
            page.locator(".endpoint-results details").first.wait_for()
            assert page.locator(".endpoint-results details").count() == 2
            page.locator(".endpoint-results summary").first.click()
            assert "station-9" in page.locator(".endpoint-results table").first.inner_text()
            page.locator("select[name=query_action]").select_option("added")
            page.locator(".telemetry-view form button[type=submit]").click()
            expect(page.locator(".endpoint-results details")).to_have_count(1)
            page.locator(".endpoint-results summary").click()
            assert "agent --run" in page.locator(".endpoint-results").inner_text()
            assert_accessible(page)
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.evaluate("window.scrollTo(0,0)")
            page.screenshot(path=str(output / f"endpoints-{language}-{theme}-{width}.png"), full_page=True)
            page.locator(".analysis-tools a[href*='analysis=content']").click()
            page.locator(".content-inspection").wait_for()
            assert page.locator("input[name=sample]").count() == 0
            page.locator(".analysis-tools a[href*='analysis=files']").click()
            page.locator("input[name=sample]").wait_for()
            # Production tool route uses the same workspace and retains its case selection.
            page.goto(base + f"/sandbox?case_id={case['id']}&analysis=network")
            page.locator(".network-results table").wait_for()
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
