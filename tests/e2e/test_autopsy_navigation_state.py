import shutil
import threading
from urllib.parse import parse_qs, urlparse

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server


@pytest.fixture
def operational_browser(app):
    app.config.update(LEGACY_TRAINING_TESTS=False, ALLOW_REGISTRATION=False, WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=shutil.which("chromium"))
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            root = f"http://127.0.0.1:{server.server_port}"
            page.goto(root + "/login")
            page.locator("input[name=email]").fill("manager@socify.local")
            page.locator("input[name=password]").fill(DEMO_LOGIN_VALUE)
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/cases")
            yield page, root, errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.e2e
def test_case_server_rejection_retains_editable_name_reason_objective_and_retry(operational_browser):
    page, _, errors = operational_browser
    page.get_by_role("button", name="إنشاء قضية", exact=True).click()
    dialog = page.get_by_role("dialog")
    dialog.locator("input[name=title]").fill("x")
    dialog.locator("input[name=reason]").fill("مراجعة تنبيه")
    objective = "Preserve this investigator draft after a server validation error"
    dialog.locator("textarea[name=objective]").fill(objective)
    with page.expect_response(lambda response: response.url.endswith("/api/cases") and response.request.method == "POST") as rejected:
        dialog.get_by_role("button", name="حفظ", exact=True).click()
    assert rejected.value.status == 422
    dialog.get_by_role("alert").wait_for(state="visible")
    assert dialog.locator("input[name=title]").input_value() == "x"
    assert dialog.locator("input[name=reason]").input_value() == "مراجعة تنبيه"
    assert dialog.locator("textarea[name=objective]").input_value() == objective
    dialog.locator("input[name=title]").fill("Corrected incident draft")
    dialog.get_by_role("button", name="حفظ", exact=True).click()
    page.wait_for_url("**/cases/*")
    assert page.locator("textarea[name=objective]").input_value() == objective
    assert not errors


@pytest.mark.e2e
def test_team_list_batch_search_pagination_and_saved_timeline_filters_survive_navigation(operational_browser):
    page, _, errors = operational_browser
    created = page.evaluate(
        "async () => {const c=await api('/api/cases',{method:'POST',body:{title:'Browser saved case context',reason:'forensic_review',objective:'Verify stable case and filter navigation'}});const j=await api(`/api/cases/${c.id}/imports`,{method:'POST',body:{filename:'retained.json',content:JSON.stringify(Array.from({length:51},(_,i)=>({title:'Retained event '+i,severity:'high',event_time:'2026-10-20T10:00:00Z'})))}});return {caseId:c.id,jobId:j.id};}"
    )
    page.reload()
    cases = page.get_by_role("form", name="بحث القضايا", exact=True)
    cases.locator("input[name=q]").fill("saved case context")
    cases.get_by_role("button", name="بحث", exact=True).click()
    page.get_by_role("cell", name="Browser saved case context", exact=True).wait_for()
    page.reload()
    assert page.get_by_role("form", name="بحث القضايا").locator("input[name=q]").input_value() == "saved case context"
    page.get_by_role("link", name="فتح القضية", exact=True).click()
    page.get_by_role("link", name="السجلات والأدلة", exact=True).click()
    page.get_by_role("link", name="سجلات هذه النسخة", exact=True).click()
    logs = page.get_by_role("form", name="بحث سجلات القضية", exact=True)
    logs.locator("input[name=q]").fill("Retained")
    logs.get_by_role("button", name="بحث السجلات", exact=True).click()
    page.get_by_role("link", name="السجلات التالية", exact=True).click()
    page.reload()
    assert parse_qs(urlparse(page.url).query)["page"] == ["2"]
    assert parse_qs(urlparse(page.url).query)["job_id"] == [str(created["jobId"])]
    page.get_by_role("link", name="الملخص والمسؤوليات", exact=True).click()
    page.get_by_role("link", name="السجلات والأدلة", exact=True).click()
    assert page.get_by_role("form", name="بحث سجلات القضية").locator("input[name=q]").input_value() == "Retained"
    assert parse_qs(urlparse(page.url).query)["page"] == ["2"]
    page.get_by_role("link", name="التحقيق والخط الزمني", exact=True).click()
    page.locator("input[name=timeline_q]").fill("Retained")
    page.locator("select[name=timeline_severity]").select_option("high")
    page.locator("input[name=timeline_start]").fill("2026-10-20T09:00")
    page.locator("input[name=timeline_end]").fill("2026-10-20T11:00")
    page.get_by_role("button", name="تطبيق الفلاتر", exact=True).click()
    page.get_by_role("button", name="حفظ منظر البحث", exact=True).click()
    dialog = page.get_by_role("dialog")
    dialog.locator("input[name=title]").fill("Retained scoped timeline view")
    dialog.get_by_role("button", name="حفظ", exact=True).click()
    page.get_by_role("button", name="Retained scoped timeline view", exact=True).wait_for()
    page.reload()
    assert page.locator("input[name=timeline_q]").input_value() == "Retained"
    assert page.locator("select[name=timeline_severity]").input_value() == "high"
    assert page.locator("input[name=timeline_start]").input_value() == "2026-10-20T09:00"
    page.locator("input[name=timeline_q]").fill("")
    page.locator("select[name=timeline_severity]").select_option("")
    page.get_by_role("button", name="تطبيق الفلاتر", exact=True).click()
    page.get_by_role("button", name="Retained scoped timeline view", exact=True).click()
    assert page.locator("input[name=timeline_q]").input_value() == "Retained"
    page.get_by_role("link", name="الاستجابة والتصعيد", exact=True).click()
    page.get_by_role("link", name="التحقيق والخط الزمني", exact=True).click()
    assert page.locator("select[name=timeline_severity]").input_value() == "high"
    page.get_by_role("link", name="جميع القضايا", exact=True).click()
    assert page.get_by_role("form", name="بحث القضايا").locator("input[name=q]").input_value() == "saved case context"
    assert not errors
