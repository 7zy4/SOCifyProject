"""Follow retained-log analysis from a user action to an evidenced result."""

import json
import time

import pytest
from playwright.sync_api import expect

from scripts.local_services import local_worker_services
from tests.e2e.test_assignment_handoff_journeys import role_permission
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_case_continuity_journeys import panel
from tests.e2e.test_followup_handoff_journeys import evidence_images, manager_case
from tests.e2e.test_review_workflow import ARTIFACTS, review_session


def upload(j, count=2, name="scan-events.json", address="192.0.2.21", prefix="Gateway retained session"):
    j.page.goto(j.case_url + "?tab=logs")
    j.settle()
    content = [
        {"title": f"{prefix} {index + 1:04d}", "source_ip": address, "hostname": "retained-gw", "timestamp": "2026-11-02T09:00:00Z"} for index in range(count)
    ]
    j.page.locator("input[name=file]").set_input_files({"name": name, "mimeType": "application/json", "buffer": json.dumps(content).encode()})
    j.click("button", "استيراد وفحص فوري")


def detection(j):
    return panel(j, "الإثراء والكشف ومراجعة التنبيهات")


def open_detection(j):
    j.page.goto(j.case_url + "?tab=analysis&analysis=detection")
    j.settle()


def queue(j, mode="rules"):
    form = detection(j).locator("form").filter(has=j.page.locator("input[name=mode]"))
    form.locator("input[name=mode]").fill(j.text("مقارنة بالسجلات السابقة" if mode == "anomaly" else "فحص القواعد"))
    with j.page.expect_response(lambda response: response.request.method == "POST" and response.url.endswith("/detection")) as response:
        j.click("button", "حفظ", form)
    assert response.value.ok, response.value.text()
    return response.value.json()["id"]


def job(j, identifier):
    return j.page.evaluate("path=>api(path)", f"/api/cases/{j.case_id}/jobs/{identifier}")


def finish(j, app, identifier, expected="completed"):
    with local_worker_services(app.config):
        deadline = time.monotonic() + 50
        while time.monotonic() < deadline:
            result = job(j, identifier)
            if result["state"] == expected:
                return result
            j.page.wait_for_timeout(250)
        raise AssertionError(f"Analysis did not reach {expected}: {result}")


def read_result(j):
    dialog = j.page.get_by_role("dialog").last
    j.click("button", "عرض النتيجة", dialog)
    dialog = j.page.get_by_role("dialog").last
    expect(dialog.get_by_role("table").first).to_be_visible()
    return dialog


def result_value(j, dialog, label):
    return dialog.locator("tr").filter(has=j.page.get_by_role("rowheader", name=j.text(label), exact=True)).get_by_role("cell")


def choose_start(j, title):
    form = detection(j).locator("form").filter(has=j.page.locator("input[name=mode]"))
    form.locator("input[name=start_event]").fill(title)
    form.get_by_role("option").filter(has_text=title).click()


def publish_rule(manager):
    manager.nav("مكتبة التحليل المحلي")
    area = panel(manager, "تحقق ونشر Sigma subset")
    source = "title: Gateway retained match\nlogsource:\n  category: socify_normalized\ndetection:\n  selected:\n    title|contains: Gateway retained session\n  condition: selected\nlevel: high\n"
    area.locator("input[type=file]").nth(0).set_input_files({"name": "gateway.yml", "mimeType": "text/yaml", "buffer": source.encode()})
    fixtures = {"positive": [{"title": "Gateway retained session 0001"}], "negative": [{"title": "Routine unrelated activity"}]}
    area.locator("input[type=file]").nth(1).set_input_files({"name": "examples.json", "mimeType": "application/json", "buffer": json.dumps(fixtures).encode()})
    area.locator("input[name=reason]").fill("Match the retained gateway events for this scoped investigation")
    manager.click("button", "حفظ", area)
    expect(manager.page.get_by_role("cell", name="Gateway retained match", exact=True)).to_be_visible()


def capture_result(j, dialog, result):
    assert_accessible(j.page)
    dialog.screenshot(path=str(ARTIFACTS / f"{result['scenario']}-{result['language']}-result.png"))
    j.page.set_viewport_size({"width": 390, "height": 1000})
    assert dialog.evaluate("e=>e.scrollWidth <= e.clientWidth")
    for table in dialog.locator("table").all():
        assert table.evaluate("e=>e.scrollWidth <= e.clientWidth")
    if dialog.get_by_role("button", name=j.text("عرض السجل"), exact=True).count():
        evidence = dialog.get_by_role("button", name=j.text("عرض السجل"), exact=True).first
        evidence.scroll_into_view_if_needed()
        expect(evidence).to_be_in_viewport(ratio=1)
        dialog.evaluate("e=>e.scrollTop=0")
    dialog.screenshot(path=str(ARTIFACTS / f"{result['scenario']}-{result['language']}-result-mobile.png"))
    j.page.set_viewport_size({"width": 1440, "height": 1000})


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", ["detection-readable-result", "detection-reload-progress", "detection-anomaly-insufficient"])
def test_analyst_follows_retained_log_analysis(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        manager_case(j, manager)
        upload(j)
        open_detection(j)
        identifier = queue(j, "anomaly" if scenario == "detection-anomaly-insufficient" else "rules")
        if scenario == "detection-reload-progress":
            j.page.reload()
            j.settle()
            j.click("button", "متابعة الفحص")
        result["observed_job"] = finish(j, app, identifier)
        dialog = j.page.get_by_role("dialog").last
        j.click("button", "عرض النتيجة", dialog)
        dialog = j.page.get_by_role("dialog").last
        expect(dialog.locator("table")).to_be_visible()
        expect(dialog).not_to_contain_text("next_after_id")
        if scenario == "detection-anomaly-insufficient":
            expect(dialog).to_contain_text(j.text("السجلات السابقة غير كافية للمقارنة"))
        dialog.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-result.png"))
        result["outcomes"] = [scenario, "a real worker completed the queued analysis", "the analyst read a structured result"]
        j.click("button", "إغلاق", dialog)
        evidence_images(j, result)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "detection-anomaly-new-pair",
        "detection-anomaly-known-pair",
        "detection-repeat-alerts",
        "detection-continue-batch",
        "detection-cancel-retry",
        "detection-permission-recovery",
        "detection-changed-case-recovery",
        "detection-status-network-recovery",
        "detection-reopen-old-result",
    ],
)
def test_analyst_completes_analysis_under_changed_conditions(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        manager_case(j, manager)
        anomaly = scenario.startswith("detection-anomaly-")
        upload(j, 26 if anomaly else 1001 if scenario == "detection-continue-batch" else 2)
        if anomaly:
            upload(j, 1, name="candidate.json", address="198.51.100.9" if scenario.endswith("new-pair") else "192.0.2.21", prefix="Candidate session")
        if scenario == "detection-repeat-alerts":
            publish_rule(manager)
        open_detection(j)
        if anomaly:
            choose_start(j, "Candidate session 0001")
        identifier = queue(j, "anomaly" if anomaly else "rules")
        dialog = j.page.get_by_role("dialog")
        if scenario == "detection-cancel-retry":
            j.click("button", "إلغاء المعالجة", dialog)
            assert job(j, identifier)["state"] == "cancelled"
            j.click("button", "إعادة المحاولة", dialog)
            assert job(j, identifier)["state"] == "queued"
        elif scenario == "detection-permission-recovery":
            role_permission(manager, "cases.update", False)
            result["failed_attempt"] = finish(j, app, identifier, "failed")
            expect(dialog).to_contain_text(j.text("تغيرت صلاحيات الفحص أو نطاق القضية"))
            expect(dialog.get_by_role("button", name=j.text("إعادة المحاولة"), exact=True)).to_have_count(0)
            role_permission(manager, "cases.update", True)
            j.click("button", "إغلاق", dialog)
            j.page.reload()
            j.settle()
            j.click("button", "متابعة الفحص")
            dialog = j.page.get_by_role("dialog")
            j.click("button", "إعادة المحاولة", dialog)
        elif scenario == "detection-changed-case-recovery":
            manager.page.goto(j.case_url)
            manager.settle()
            context = panel(manager, "سبب القضية وهدفها ونتيجتها")
            context.locator("summary").click()
            context.locator("textarea[name=objective]").fill("Review the changed gateway investigation scope")
            manager.click("button", "حفظ", context)
            result["failed_attempt"] = finish(j, app, identifier, "failed")
            expect(dialog).to_contain_text(j.text("تغيرت القضية؛ ابدأ فحصًا جديدًا لمراجعة السجلات الحالية"))
            expect(dialog.get_by_role("button", name=j.text("إعادة المحاولة"), exact=True)).to_have_count(0)
            j.click("button", "إغلاق", dialog)
            identifier = queue(j)
        elif scenario == "detection-status-network-recovery":
            path = f"**/api/cases/{j.case_id}/jobs/{identifier}"
            j.page.route(path, lambda route: route.abort("internetdisconnected"), times=1)
            expect(dialog.get_by_role("button", name=j.text("إعادة المحاولة"), exact=True)).to_be_visible(timeout=10000)
            j.click("button", "إعادة المحاولة", dialog)
            expect(dialog).to_contain_text(j.text("بانتظار المعالجة"))
        result["completed_job"] = finish(j, app, identifier)
        dialog = read_result(j)
        if anomaly:
            expect(result_value(j, dialog, "سجلات المقارنة السابقة")).to_have_text("26")
            expect(result_value(j, dialog, "اختلافات تحتاج المراجعة")).to_have_text("1" if scenario.endswith("new-pair") else "0")
            if scenario.endswith("new-pair"):
                expect(dialog).to_contain_text(j.text("الاختلاف لا يثبت نشاطًا خبيثًا"))
                j.click("button", "عرض السجل", dialog)
                detail = j.page.get_by_role("dialog").last
                expect(detail).to_contain_text("Candidate session 0001")
                j.click("button", "إغلاق", detail)
        elif scenario == "detection-continue-batch":
            expect(result_value(j, dialog, "السجلات المفحوصة")).to_have_text("1,000")
            with j.page.expect_response(lambda response: response.request.method == "POST" and response.url.endswith("/detection")) as next_job:
                j.click("button", "استكمال فحص الدفعة التالية", dialog)
            following = next_job.value.json()["id"]
            result["continued_job"] = finish(j, app, following)
            dialog = read_result(j)
            expect(result_value(j, dialog, "السجلات المفحوصة")).to_have_text("1")
            expect(dialog.get_by_role("button", name=j.text("استكمال فحص الدفعة التالية"), exact=True)).to_have_count(0)
        elif scenario == "detection-repeat-alerts":
            first = j.page.evaluate("id=>api(`/api/cases/${id}/alerts`)", j.case_id)["items"]
            assert len(first) == 2
            expect(dialog.get_by_role("link", name=j.text("عرض التنبيهات"), exact=True)).to_be_visible()
            j.click("button", "إغلاق", dialog)
            second = queue(j)
            finish(j, app, second)
            dialog = read_result(j)
            assert j.page.evaluate("id=>api(`/api/cases/${id}/alerts`)", j.case_id)["items"] == first
            expect(result_value(j, dialog, "التنبيهات الجديدة")).to_have_text("0")
        elif scenario == "detection-reopen-old-result":
            original = result["completed_job"]["result_record_id"]
            j.click("button", "إغلاق", dialog)
            upload(j, 1, name="later.json", prefix="Later gateway session")
            open_detection(j)
            second = queue(j)
            finish(j, app, second)
            dialog = read_result(j)
            expect(result_value(j, dialog, "السجلات المفحوصة")).to_have_text("3")
            j.click("button", "إغلاق", dialog)
            j.page.reload()
            j.settle()
            j.page.get_by_role("button", name=j.text("متابعة الفحص"), exact=True).nth(1).click()
            j.settle()
            dialog = read_result(j)
            expect(result_value(j, dialog, "السجلات المفحوصة")).to_have_text("2")
            assert job(j, identifier)["result_record_id"] == original
        capture_result(j, dialog, result)
        j.click("button", "إغلاق", dialog)
        evidence_images(j, result)
        result["outcomes"] = [scenario, "real retained logs and worker result", "user task completed through the interface"]
