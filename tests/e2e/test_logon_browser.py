import threading
from pathlib import Path

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from tests.e2e.test_browser import assert_accessible, launch_browser, new_page
from tests.unit.test_windows_logon import logon_xml


@pytest.mark.e2e
@pytest.mark.parametrize("language,width", [("ar", 1440), ("en", 390)])
def test_logon_investigation_and_report_layout(app, language, width):
    app.config.update(LEGACY_TRAINING_TESTS=False, WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    output = Path("artifacts/logon/screenshots")
    output.mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = new_page(browser, viewport={"width": width, "height": 1000})
            page.add_init_script(f"localStorage.setItem('socify-interface-language','{language}');")
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            base = f"http://127.0.0.1:{server.server_port}"
            page.goto(base + "/login")
            page.locator("input[name=email]").fill("manager@socify.local")
            page.locator("input[name=password]").fill(DEMO_LOGIN_VALUE)
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/cases")
            page.locator('#workspace[aria-busy="false"]').wait_for()
            content = "<Events>" + "".join([*(logon_xml(i) for i in range(5)), logon_xml(5, 4624)]) + "</Events>"
            case = page.evaluate(
                """async content => {
                    const c=await api('/api/cases',{method:'POST',body:{title:'مراجعة الدخول إلى خادم التطبيقات',severity:'high'}});
                    await api(`/api/cases/${c.id}/imports`,{method:'POST',body:{filename:'Security.xml',content}});
                    return c;
                }""",
                content,
            )
            page.goto(base + "/monitoring")
            row = page.locator("[data-alert-row]").filter(has_text="Successful Windows Logon After Repeated Failures")
            row.locator("[data-alert-toggle]").click()
            page.locator(".dossier-view").wait_for()
            assert page.locator('[data-dossier-section="event"]').count() == 6
            assert "auth_target" not in page.locator(".dossier-view").inner_text()
            assert "CORP" in page.locator(".dossier-view").inner_text()
            assert ("دخول تفاعلي عن بُعد" if language == "ar" else "Remote interactive") in page.locator(".dossier-view").inner_text()
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            assert_accessible(page)
            page.screenshot(path=str(output / f"logon-investigation-{language}.png"))
            page.locator('[data-dossier-section="event"]').last.screenshot(path=str(output / f"logon-details-{language}.png"))
            page.evaluate(
                """async id => {
                    const guide=await api(`/api/cases/${id}/quick-report`);
                    await api(`/api/cases/${id}/quick-report`,{method:'PUT',body:{answers:Object.fromEntries(guide.questions.map(q=>[q.id,q.options[0].value])),executive_note:'خمس محاولات فاشلة تبعها دخول ناجح للحساب نفسه. يلزم التحقق من صاحب الحساب قبل تحديد ما إذا كان الدخول مصرحًا.'}});
                }""",
                case["id"],
            )
            page.goto(base + f"/cases/{case['id']}/quick-report/print")
            report = page.locator(".report-facts").last
            report.wait_for()
            assert "0x98c1" in report.inner_text() and "النتيجة" in report.inner_text()
            assert "auth_target" not in report.inner_text()
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            assert_accessible(page)
            report.screenshot(path=str(output / f"logon-report-{language}.png"))
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
