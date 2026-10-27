import threading
from pathlib import Path

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

from tests.e2e.test_browser import assert_accessible, launch_browser
from tests.integration.test_soc_workbench import alert, message


@pytest.mark.e2e
def test_soc_triage_case_tools_email_and_immediate_report_permissions(app, database, user_ids):
    app.config.update(LEGACY_TRAINING_TESTS=False, ALLOW_REGISTRATION=False, WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    output = Path("work/soc-console/previews")
    output.mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            page.add_init_script("if (!localStorage.getItem('socify-interface-language')) localStorage.setItem('socify-interface-language','en')")
            page.add_init_script(path=str(Path("node_modules/axe-core/axe.min.js").resolve()))
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            base = f"http://127.0.0.1:{server.server_port}"
            page.goto(base + "/login")
            page.get_by_label("Email", exact=True).fill("manager@socify.local")
            page.get_by_label("Password", exact=True).fill(DEMO_LOGIN_VALUE)
            page.get_by_role("button", name="Sign in", exact=True).click()
            page.wait_for_url("**/cases")
            page.wait_for_function("() => document.querySelector('#workspace').getAttribute('aria-busy') === 'false'")
            case = page.evaluate("""async () => {
                const c = await api('/api/cases',{method:'POST',body:{title:'Identity gateway access review',reason:'alert_review',objective:'Document retained evidence and response decisions.',severity:'high'}});
                await api(`/api/cases/${c.id}/records/asset`,{method:'POST',body:{name:'Identity gateway',type:'identity_provider',role:'defender',address:'192.0.2.20',operating_system:'Linux',assessment:'suspected'}});
                return c;
            }""")
            for index in range(31):
                alert(database, case["id"], f"UI-{index}", "critical" if index % 2 else "high")
            page.goto(base + "/monitoring")
            expect(page.locator("[data-alert-row]")).to_have_count(25)
            assert page.locator(".desktop-window,.desktop-taskbar,.case-folder-grid").count() == 0
            page.locator("[data-theme-select]").select_option("dark")
            page.screenshot(path=str(output / "monitoring-en-dark.png"), full_page=False)
            assert_accessible(page)
            expand = page.locator(".row-expand").first
            expand.click()
            expect(expand).to_have_attribute("aria-expanded", "true")
            expect(page.locator(".alert-detail-cell:visible")).to_contain_text("Synthetic finding")
            expand.click()
            page.get_by_role("link", name="Next", exact=True).click()
            expect(page.locator("[data-alert-row]")).to_have_count(6)
            page.get_by_label("Severity", exact=True).select_option("critical")
            page.get_by_role("button", name="Apply", exact=True).click()
            expect(page.locator("[data-alert-row]")).to_have_count(15)
            assert "severity=critical" in page.url and "page=1" in page.url
            page.get_by_role("link", name="Investigation Channel", exact=False).click()
            expect(page.locator("[data-alert-row]")).to_have_count(0)
            page.goto(base + f"/cases/{case['id']}")
            page.get_by_role("heading", name=case["title"], exact=True).wait_for()
            expect(page.locator("#primary-nav [data-section=email-security]")).to_have_attribute("href", f"/email-security?case_id={case['id']}")
            page.locator("#primary-nav [data-section=endpoint-security]").click()
            expect(page.locator(".asset-table")).to_contain_text("192.0.2.20")
            page.get_by_role("button", name="View Asset", exact=True).click()
            expect(page.locator("dialog")).to_contain_text("Identity gateway")
            page.get_by_role("button", name="Close", exact=True).click()
            page.locator("#primary-nav [data-section=email-security]").click()
            page.locator("input[type=file][name=email]").set_input_files({"name": "investigation.eml", "mimeType": "message/rfc822", "buffer": message()})
            page.get_by_role("button", name="Quarantine & inspect email", exact=True).click()
            page.get_by_role("heading", name="Synthetic suspicious message", exact=True).wait_for()
            assert page.locator(".email-review img,.email-review iframe").count() == 0
            assert page.evaluate("typeof window.pwned === 'undefined'")
            page.get_by_text("Observed URLs", exact=False).click()
            expect(page.locator(".email-links")).to_contain_text("https://example.test/hidden")
            assert page.locator(".email-links a").count() == 0
            assert_accessible(page)
            page.screenshot(path=str(output / "email-en-dark.png"), full_page=True)
            page.goto(base + f"/cases/{case['id']}")
            page.locator("[data-quick-report]").click()
            page.wait_for_url(f"**/cases/{case['id']}?tab=reports")
            expect(page.locator(".report-revision")).to_have_count(1)
            report = database.execute("SELECT payload FROM autopsy_reports WHERE case_id=?", (case["id"],)).fetchone()[0]
            assert "eml_static_v1" in report
            assert database.execute("SELECT COUNT(*) FROM autopsy_reports WHERE case_id=?", (case["id"],)).fetchone()[0] == 1
            page.locator("[data-theme-select]").select_option("light")
            page.goto(base + "/monitoring")
            page.screenshot(path=str(output / "monitoring-en-light.png"), full_page=False)
            page.locator("[data-language-toggle]").click()
            page.wait_for_function("() => document.documentElement.lang === 'ar' && document.querySelector('#workspace').getAttribute('aria-busy') === 'false'")
            page.locator("[data-theme-select]").select_option("dark")
            assert_accessible(page)
            page.screenshot(path=str(output / "monitoring-ar-dark.png"), full_page=False)
            page.set_viewport_size({"width": 390, "height": 844})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.get_by_role("button", name="فتح القائمة", exact=True).click()
            expect(page.locator(".sidebar")).to_be_visible()
            page.keyboard.press("Escape")
            expect(page.get_by_role("button", name="فتح القائمة", exact=True)).to_have_attribute("aria-expanded", "false")
            page.screenshot(path=str(output / "monitoring-ar-dark-mobile.png"), full_page=True)
            page.set_viewport_size({"width": 1440, "height": 1000})
            database.execute("UPDATE users SET role='reviewer' WHERE id=?", (user_ids["auditor"],))
            database.execute(
                "INSERT INTO autopsy_case_members(case_id,user_id,responsibility,assigned_by,assigned_at) VALUES (?,?,'reviewer',?,'2026-10-27T00:00:00Z')",
                (case["id"], user_ids["auditor"], user_ids["soc_manager"]),
            )
            page.get_by_role("button", name="خروج", exact=True).click()
            page.wait_for_url("**/login")
            page.get_by_label("البريد الإلكتروني", exact=True).fill("auditor@socify.local")
            page.get_by_label("كلمة المرور", exact=True).fill(DEMO_LOGIN_VALUE)
            page.get_by_role("button", name="دخول إلى المنصة", exact=True).click()
            page.wait_for_url("**/cases")
            page.goto(base + f"/endpoint-security?case_id={case['id']}")
            expect(page.locator(".asset-table")).to_contain_text("Identity gateway")
            assert page.get_by_role("button", name="إضافة أصل", exact=True).count() == 0
            page.goto(base + f"/email-security?case_id={case['id']}")
            page.get_by_role("heading", name="Synthetic suspicious message", exact=True).wait_for()
            assert page.locator("input[name=email][type=file]").count() == 0
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
