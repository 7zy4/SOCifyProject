"""Analysts complete documented response work with evidence and independent approval."""

import json

import pytest
from playwright.sync_api import expect

from socify.db import get_db
from tests.e2e.test_batch_boundary_journeys import upload_logs
from tests.e2e.test_review_workflow import review_session


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_template_author_can_cancel_navigation_without_losing_the_draft(app, language):
    with review_session(app, language, "procedure-template-draft") as (_analyst, j, result):
        j.login("manager@socify.local")
        j.nav("كتيبات الاستجابة")
        j.page.get_by_label(j.text("اسم القالب أو اسم الإصدار السابق"), exact=True).fill("Preserve the response plan")
        step = j.page.locator("fieldset")
        step.get_by_label(j.text("العنوان"), exact=True).fill("Check retained identity evidence")
        seen = []
        j.page.once("dialog", lambda dialog: (seen.append(dialog.type), dialog.dismiss()))
        j.nav("إدارة القضايا")
        assert seen == ["beforeunload"]
        expect(j.page.get_by_label(j.text("اسم القالب أو اسم الإصدار السابق"), exact=True)).to_have_value("Preserve the response plan")
        j.click("button", "حفظ إصدار مسودة")
        j.nav("إدارة القضايا")
        j.nav("كتيبات الاستجابة")
        expect(j.page.locator("article.card")).to_contain_text("Preserve the response plan")
        expect(j.page.locator("article.card > p")).to_have_text(j.text("مسودة"))
        result["outcomes"] = ["cancelled navigation retained template draft", "explicit save persisted the template", "saved work permitted navigation"]


def set_status(journey, dialog, status, notes):
    dialog.locator("input[name=status]").fill(journey.page.evaluate("s => autopsyLabel(s)", status))
    dialog.locator("textarea[name=notes]").fill(notes)


def procedure(journey):
    return journey.page.evaluate("id => api(`/api/cases/${id}/records?kind=playbook`)", journey.case_id)["items"][0]


def create_procedure(manager, case_url, approval=False):
    manager.nav("كتيبات الاستجابة")
    manager.page.get_by_label(manager.text("اسم القالب أو اسم الإصدار السابق"), exact=True).fill("Identity response review")
    step = manager.page.locator("fieldset")
    step.get_by_label(manager.text("العنوان"), exact=True).fill("Verify the identity provider result")
    step.get_by_label(manager.text("التفاصيل"), exact=True).fill("Retain the identity provider approval before closing the response.")
    step.get_by_label(manager.text("تتطلب اعتماد المدير"), exact=True).set_checked(approval)
    manager.click("button", "حفظ إصدار مسودة")
    manager.click("button", "اعتماد ونشر هذا الإصدار")
    manager.page.goto(case_url + "?tab=response")
    manager.settle()
    manager.page.locator("input[name=template]").press("ArrowDown")
    manager.page.get_by_role("option").filter(has_text="Identity response review").first.click()
    manager.click("button", "إضافة نسخة للقضية")


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    ["procedure-missing-evidence", "procedure-failed-recovery", "procedure-manager-exception", "procedure-independent-approval", "benign-import-no-alert"],
)
def test_documented_response_tasks_have_honest_outcomes(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        if scenario == "benign-import-no-alert":
            upload_logs(j, "routine.json", "Scheduled backup completed successfully")
            j.click("link", "مراجعة التنبيهات")
            expect(j.page.locator("[data-alert-row]")).to_have_count(0)
            expect(j.page.locator("#workspace .empty")).to_be_visible()
            records = j.page.evaluate("id => api(`/api/cases/${id}/logs`)", j.case_id)
            assert records["total"] == 1
            alerts = j.page.evaluate("id => api(`/api/cases/${id}/alerts`)", j.case_id)
            assert alerts["total"] == 0
            result["outcomes"] = ["benign fixture imported", "no fabricated detection", "empty monitoring result visible"]
            return
        manager.login("manager@socify.local")
        manager.page.goto(j.case_url)
        manager.settle()
        upload_logs(manager, "approval.json", "Identity approval retained")
        create_procedure(manager, j.case_url, scenario == "procedure-independent-approval")
        j.click("link", "الاستجابة والتصعيد")
        j.click("button", "تحديث الخطوة")
        dialog = j.page.get_by_role("dialog")
        if scenario == "procedure-missing-evidence":
            set_status(j, dialog, "completed", "Waiting for retained evidence")
            j.click("button", "حفظ", dialog)
            expect(dialog.get_by_role("alert")).to_be_visible()
            assert procedure(j)["payload"]["steps"][0]["status"] == "pending"
            set_status(j, dialog, "in_progress", "Evidence collection requested")
            j.click("button", "حفظ", dialog)
            assert procedure(j)["payload"]["steps"][0]["status"] == "in_progress"
            result["outcomes"] = ["required completion without evidence rejected", "draft retained", "in-progress work saved"]
        elif scenario == "procedure-manager-exception":
            set_status(j, dialog, "not_applicable", "Identity provider review is outside the confirmed scope")
            j.click("button", "حفظ", dialog)
            expect(dialog.get_by_role("alert")).to_be_visible()
            assert procedure(j)["payload"]["steps"][0]["status"] == "pending"
            j.page.once("dialog", lambda value: value.accept())
            j.click("button", "إغلاق", dialog)
            manager.page.reload()
            manager.settle()
            manager.click("button", "تحديث الخطوة")
            decision = manager.page.get_by_role("dialog")
            set_status(manager, decision, "not_applicable", "Manager reviewed the scope and approved this exception")
            manager.click("button", "حفظ", decision)
            j.page.reload()
            j.settle()
            step = procedure(j)["payload"]["steps"][0]
            assert step["status"] == "not_applicable" and step["approved_by"] == manager.page.evaluate("state.user.id")
            result["outcomes"] = ["analyst cannot waive required step", "manager exception recorded", "team sees final decision"]
        else:
            if scenario == "procedure-failed-recovery":
                set_status(j, dialog, "failed", "Requested approval record was unavailable during the first attempt")
                j.click("button", "حفظ", dialog)
                assert procedure(j)["payload"]["steps"][0]["status"] == "failed"
                j.click("button", "تحديث الخطوة")
            set_status(j, dialog, "completed", "Retained identity approval confirms the requested response")
            dialog.locator("input[name=evidence_id]").press("ArrowDown")
            dialog.get_by_role("option").first.click()
            j.click("button", "حفظ", dialog)
            if scenario == "procedure-independent-approval":
                assert procedure(j)["payload"]["steps"][0]["status"] == "awaiting_approval"
                manager.page.reload()
                manager.settle()
                manager.click("button", "تحديث الخطوة")
                decision = manager.page.get_by_role("dialog")
                set_status(manager, decision, "completed", "Independent manager review confirmed the retained approval")
                manager.click("button", "حفظ", decision)
                j.page.reload()
                j.settle()
                assert procedure(j)["payload"]["steps"][0]["approved_by"] == manager.page.evaluate("state.user.id")
            record = procedure(j)
            assert record["payload"]["steps"][0]["status"] == "completed"
            if scenario == "procedure-failed-recovery":
                with app.app_context():
                    history = get_db().execute("SELECT payload FROM autopsy_record_revisions WHERE record_id=? ORDER BY version", (record["id"],)).fetchall()
                states = [json.loads(row["payload"])["steps"][0]["status"] for row in history]
                assert states == ["pending", "failed", "completed"]
            result["outcomes"] = [scenario, "completion backed by retained case evidence", "prior decisions retained"]
        for width in [390, 1440]:
            j.page.set_viewport_size({"width": width, "height": 1000})
            assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
