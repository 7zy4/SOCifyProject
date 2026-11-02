import threading
from pathlib import Path

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from tests.e2e.test_browser import assert_accessible, launch_browser


@pytest.mark.e2e
@pytest.mark.parametrize("language,theme,width", [("ar", "dark", 1440), ("en", "light", 1440), ("ar", "light", 390), ("en", "dark", 390)])
def test_uploaded_case_dashboard_dossier_and_explicit_report_answers(app, language, theme, width):
    app.config.update(LEGACY_TRAINING_TESTS=False, WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    output = Path("artifacts/soc-insights")
    output.mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={"width": width, "height": 1000})
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
            case = page.evaluate("""async () => {
                const c=await api('/api/cases',{method:'POST',body:{title:'Endpoint investigation',severity:'high'}});
                await api(`/api/cases/${c.id}/imports`,{method:'POST',body:{filename:'endpoint.json',content:JSON.stringify([{title:'Process execution',hostname:'workstation-23',process_name:'powershell.exe',command_line:'powershell.exe -enc AAAA'}])}});
                return c;
            }""")
            page.goto(base + "/performance?member=team")
            page.locator(".insight-counters").wait_for()
            assert page.title() == ("أداء الفريق | SOCify" if language == "ar" else "Team performance | SOCify")
            assert page.locator(".insight-counter strong").first.inner_text() in {"1", "١"}
            assert_accessible(page)
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.screenshot(path=str(output / f"team-{language}-{theme}-{width}.png"), full_page=True)
            page.locator("select[name=days]").select_option("7")
            page.locator(".filter-row button[type=submit]").click()
            page.wait_for_url("**/performance?days=7&member=team")
            page.locator(".insight-counters").wait_for()
            page.goto(base + "/performance?member=me&days=7")
            page.locator(".insight-counters").wait_for()
            assert_accessible(page)
            page.screenshot(path=str(output / f"analyst-{language}-{theme}-{width}.png"), full_page=True)
            page.goto(base + "/monitoring")
            page.locator("[data-alert-row]").first.wait_for()
            assert page.locator(".dossier-view:visible").count() == 0
            page.locator("[data-alert-toggle]").first.click()
            page.locator(".dossier-view").wait_for()
            page.locator("button.row-expand").first.click()
            assert page.locator(".dossier-view:visible").count() == 0
            page.locator("[data-alert-toggle]").first.click()
            assert page.locator(".dossier-view").inner_text().find("workstation-23") >= 0
            assert page.locator(".dossier-view table").count() == 1
            assert page.locator(".dossier-view details").count() == 0
            process = "العملية" if language == "ar" else "Process"
            assert "powershell.exe" in page.get_by_role("row", name=f"{process} powershell.exe", exact=True).inner_text()
            assert page.locator(".dossier-view pre:visible").count() == 1
            assert page.locator(".monitoring-view .pagination").count() == 0
            assert page.locator(".alert-property-table").evaluate_all("tables => tables.every(table => table.scrollWidth <= table.clientWidth + 2)")
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            assert_accessible(page)
            page.evaluate("window.scrollTo(0,0)")
            page.screenshot(path=str(output / f"investigation-{language}-{theme}-{width}.png"), full_page=True)
            page.goto(base + f"/cases/{case['id']}?tab=reports")
            page.locator("select[name=incident_classification]").wait_for(state="attached")
            # No classification or conclusion is selected on the user's behalf.
            assert page.locator("select[name=incident_classification]").input_value() == ""
            # Persist actual decisions, then verify their values in the expanded table.
            await_data = page.evaluate(
                """async id => {
                const base=`/api/cases/${id}`;
                const guide=await api(base+'/quick-report');
                const answers=Object.fromEntries(guide.questions.map(q=>[q.id,q.options[0].value]));
                await api(base+'/quick-report',{method:'PUT',body:{answers,executive_note:'Reviewed investigation conclusion'}});
                const other=await api('/api/cases',{method:'POST',body:{title:'Second investigation'}});
                await api(`/api/cases/${other.id}/imports`,{method:'POST',body:{filename:'second.json',content:JSON.stringify([{hostname:'workstation-24',process_name:'powershell.exe',command_line:'powershell.exe -enc BBBB'}])}});
                return answers;
            }""",
                case["id"],
            )
            assert await_data
            page.goto(base + f"/monitoring?q={case['reference']}")
            page.locator("button.row-expand").first.click()
            page.locator(".dossier-view").wait_for()
            assert "Reviewed investigation conclusion" in page.locator('[data-dossier-section="decisions"]').inner_text()
            assert page.locator('[data-dossier-section="decisions"] th[scope="row"]').count() == 10
            assert page.locator(".dossier-view table").count() == 1
            assert_accessible(page)
            page.screenshot(path=str(output / f"decisions-{language}-{theme}-{width}.png"), full_page=True)
            # Multiple pages retain working list navigation outside the disclosure.
            page.goto(base + "/monitoring?page_size=1")
            page.locator(".monitoring-pagination").wait_for()
            first_alert = page.locator("[data-alert-row]").get_attribute("data-alert-row")
            assert page.locator(".monitoring-surface .pagination, .alert-detail-cell .pagination").count() == 0
            page.get_by_role("link", name="التالي" if language == "ar" else "Next", exact=True).click()
            page.wait_for_url("**/monitoring?page_size=1&page=2")
            page.locator("[data-alert-row]").wait_for()
            assert page.locator("[data-alert-row]").get_attribute("data-alert-row") != first_alert
            page.goto(base + f"/endpoint-security?case_id={case['id']}&host=workstation-23")
            page.locator(".evidence-event summary").first.wait_for()
            page.locator(".evidence-event summary").first.click()
            assert "powershell.exe -enc AAAA" in page.locator("#workspace").inner_text()
            assert_accessible(page)
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.evaluate("window.scrollTo(0,0)")
            page.screenshot(path=str(output / f"hosts-{language}-{theme}-{width}.png"), full_page=True)
            inspected = page.evaluate("""async () => {
                const c=await api('/api/cases',{method:'POST',body:{title:'Content investigation'}});
                const logs=[
                    {title:'Configuration exposure',message:'api_key='+['Ab3!','Cd4@','Ef5#','Gh6'].join('')},
                    {title:'Financial export',message:'4111111111111111',iban:'GB82WEST12345698765432'},
                    {title:'Encoded content',message:btoa("Invoke-Expression ('text')")}
                ];
                await api(`/api/cases/${c.id}/imports`,{method:'POST',body:{filename:'content.json',content:JSON.stringify(logs)}});
                const guide=await api(`/api/cases/${c.id}/quick-report`);
                await api(`/api/cases/${c.id}/quick-report`,{method:'PUT',body:{answers:Object.fromEntries(guide.questions.map(q=>[q.id,q.options[0].value]))}});
                return c;
            }""")
            page.goto(base + f"/cases/{inspected['id']}?tab=analysis")
            page.locator(".content-inspection details").first.wait_for()
            assert page.locator(".content-inspection details").count() == 3
            for summary in page.locator(".content-inspection summary").all():
                summary.click()
            inspection_text = page.locator(".content-inspection").inner_text()
            assert "Invoke-Expression" in inspection_text
            assert "Ab3!Cd4@Ef5#Gh6" not in inspection_text
            assert "4111111111111111" not in inspection_text
            assert "GB82WEST12345698765432" not in inspection_text
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            assert_accessible(page)
            page.screenshot(path=str(output / f"content-{language}-{theme}-{width}.png"), full_page=True)
            page.goto(base + f"/monitoring?q={inspected['reference']}")
            page.locator("[data-alert-toggle]").first.click()
            page.locator('[data-dossier-section="inspection"]').wait_for()
            assert page.locator(".dossier-view table").count() == 1
            assert_accessible(page)
            page.goto(base + f"/cases/{inspected['id']}/quick-report/print")
            page.locator(".content-inspection-report").first.wait_for()
            assert page.locator(".content-inspection-report").count() == 3
            assert "Invoke-Expression" in page.locator(".report-sheet").inner_text()
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            assert_accessible(page)
            page.screenshot(path=str(output / f"content-report-{language}-{theme}-{width}.png"), full_page=True)
            page.goto(base + "/performance")
            page.locator(".insight-counters").wait_for()
            assert not errors, errors
            page.locator(".account-menu summary").click()
            assert_accessible(page)
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.screenshot(path=str(output / f"account-{language}-{theme}-{width}.png"))
            page.locator("[data-account-switch]").click()
            page.wait_for_url("**/login")
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
