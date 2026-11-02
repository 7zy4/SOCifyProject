"""Follow response requirements through closure checks, handoffs and template changes."""

import pytest
from playwright.sync_api import expect

from tests.e2e.test_batch_boundary_journeys import restrict_batch, upload_logs
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_procedure_goal_journeys import procedure, set_status
from tests.e2e.test_review_workflow import ARTIFACTS, review_session

SCENARIOS = [
    "closure-required-procedure",
    "closure-pending-approval",
    "closure-optional-failure",
    "closure-reopened-procedure",
    "procedure-template-republication",
    "procedure-concurrent-correction",
    "procedure-role-boundary",
    "procedure-duplicate-attachment",
    "procedure-handoff-readable-outcome",
    "procedure-evidence-access-recovery",
]
GAP = "خطوات كتيب استجابة إلزامية"


def publish(journey, *, required=True, approval=False, manager_only=False, replacement=False):
    journey.nav("كتيبات الاستجابة")
    if replacement:
        journey.click("button", "إنشاء إصدار قابل للتعديل من هذا القالب")
    else:
        journey.page.get_by_label(journey.text("اسم القالب أو اسم الإصدار السابق"), exact=True).fill("Identity closure checklist")
    row = journey.page.locator("fieldset")
    row.get_by_label(journey.text("العنوان"), exact=True).fill("Review additional identity records" if replacement else "Verify retained identity approval")
    row.get_by_label(journey.text("التفاصيل"), exact=True).fill("Check the retained approval against the investigated activity.")
    row.get_by_label(journey.text("إلزامية"), exact=True).set_checked(required)
    row.get_by_label(journey.text("تتطلب اعتماد المدير"), exact=True).set_checked(approval)
    if manager_only:
        row.get_by_label(journey.text("دور المنفذ"), exact=True).select_option("manager")
    journey.click("button", "حفظ إصدار مسودة")
    journey.click("button", "اعتماد ونشر هذا الإصدار")


def attach(journey):
    journey.page.goto(journey.case_url + "?tab=response")
    journey.settle()
    journey.page.locator("input[name=template]").press("ArrowDown")
    journey.page.get_by_role("option").filter(has_text="Identity closure checklist").first.click()
    journey.click("button", "إضافة نسخة للقضية")


def update(journey, status, notes, *, evidence=False):
    journey.click("button", "تحديث الخطوة")
    dialog = journey.page.get_by_role("dialog")
    set_status(journey, dialog, status, notes)
    if evidence:
        dialog.locator("input[name=evidence_id]").press("ArrowDown")
        dialog.get_by_role("option").filter(has_text="approval.json").first.click()
    journey.click("button", "حفظ", dialog)
    return dialog


def requirements(journey, expected):
    journey.click("link", "التقارير والمراجعة")
    details = journey.page.locator(".closure-requirements")
    if details.get_attribute("open") is None:
        details.locator("summary").click()
    link = details.get_by_role("link", name=journey.text(GAP), exact=True)
    expect(link).to_have_count(1 if expected else 0)
    return details


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", SCENARIOS)
def test_response_requirements_remain_actionable_during_review(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        manager.login("manager@socify.local")
        manager.case_url = j.case_url
        manager.page.goto(j.case_url)
        manager.settle()
        upload_logs(manager if scenario == "procedure-evidence-access-recovery" else j, "approval.json", "Retained identity approval for response review")
        j.assessment("Identity approval is retained; complete the assigned response review.")
        publish(
            manager,
            required=scenario != "closure-optional-failure",
            approval=scenario == "closure-pending-approval",
            manager_only=scenario == "procedure-role-boundary",
        )
        attach(manager)
        j.click("link", "الاستجابة والتصعيد")

        if scenario in {"closure-required-procedure", "closure-pending-approval"}:
            if scenario == "closure-pending-approval":
                update(j, "completed", "Retained approval matches the reviewed operation", evidence=True)
                assert procedure(j)["payload"]["steps"][0]["status"] == "awaiting_approval"
            requirements(manager, True)
            before = manager.state()
            manager.decision("closed", "Close only after the mandatory response review is complete")
            expect(manager.page.get_by_role("alert")).to_contain_text(manager.text("أكمل متطلبات الإغلاق"))
            assert manager.state()["version"] == before["version"] and manager.state()["status"] != "closed"
            manager.page.once("dialog", lambda dialog: dialog.accept())
            manager.click("link", GAP, manager.page.locator(".closure-requirements"))
            expect(manager.page.locator(".procedure-step")).to_contain_text("Verify retained identity approval")
            update(manager, "completed", "Manager verified retained approval and response outcome", evidence=True)
            requirements(manager, False)
            result["outcomes"] = [
                "incomplete closure rejected without changing the case",
                "requirement link opened the assigned response",
                "evidenced completion removed the specific barrier; other closure requirements remain",
            ]

        elif scenario == "closure-optional-failure":
            update(j, "failed", "Optional supporting record is unavailable; required case review continues")
            assert procedure(j)["payload"]["steps"][0]["status"] == "failed"
            requirements(manager, False)
            result["outcomes"] = ["failed optional task retained honestly", "optional task did not become a mandatory closure barrier"]

        elif scenario == "closure-reopened-procedure":
            update(manager, "completed", "Approved identity evidence reviewed", evidence=True)
            requirements(manager, False)
            manager.click("button", "إعداد تقرير جديد")
            expect(manager.page.locator(".report-revision")).to_have_count(1)
            report_id = manager.state()["reports"][0]["id"]
            path = f"/api/cases/{manager.case_id}/reports/{report_id}"
            report = manager.page.evaluate("path => api(path)", path)
            manager.click("link", "الاستجابة والتصعيد")
            update(manager, "in_progress", "A discrepancy requires rechecking the approval scope", evidence=True)
            requirements(manager, True)
            after = manager.page.evaluate("path => api(path)", path)
            assert after["payload"] == report["payload"]
            assert after["source_version"] < manager.state()["version"]
            expect(manager.page.get_by_role("button", name=manager.text("مراجعة واعتماد النسخة"), exact=True)).to_have_count(0)
            result["outcomes"] = [
                "reopened required step restored its closure barrier",
                "previous report snapshot unchanged and outdated",
                "no native report rendering or final closure claimed",
            ]

        elif scenario == "procedure-template-republication":
            before = procedure(j)
            publish(manager, replacement=True)
            j.page.reload()
            j.settle()
            assert procedure(j) == before
            expect(j.page.locator(".procedure-step")).not_to_contain_text("Review additional identity records")
            attach(manager)
            rows = manager.page.evaluate("id => api(`/api/cases/${id}/records?kind=playbook`)", manager.case_id)["items"]
            assert len(rows) == 2 and next(row for row in rows if row["id"] == before["id"]) == before
            assert next(row for row in rows if row["id"] != before["id"])["payload"]["steps"][0]["title"] == "Review additional identity records"
            result["outcomes"] = [
                "publishing new instructions did not rewrite existing case work",
                "explicit attachment added the new checklist alongside its retained predecessor",
            ]

        elif scenario == "procedure-concurrent-correction":
            j.click("button", "تحديث الخطوة")
            draft = j.page.get_by_role("dialog")
            set_status(j, draft, "failed", "Analyst could not validate the approval during the first attempt")
            update(manager, "in_progress", "Manager obtained another record and resumed the investigation")
            j.click("button", "حفظ", draft)
            expect(draft.get_by_role("alert")).to_be_visible()
            expect(draft.locator("textarea[name=notes]")).to_have_value("Analyst could not validate the approval during the first attempt")
            assert procedure(j)["payload"]["steps"][0]["status"] == "in_progress"
            j.page.once("dialog", lambda dialog: dialog.accept())
            j.click("button", "إغلاق", draft)
            j.page.reload()
            j.settle()
            update(j, "completed", "Reviewed the newly retained record and confirmed approval", evidence=True)
            assert procedure(j)["payload"]["steps"][0]["status"] == "completed"
            result["outcomes"] = [
                "stale submission did not overwrite another reviewer",
                "draft explanation retained on conflict",
                "reviewing current work allowed a corrected evidenced completion",
            ]

        elif scenario == "procedure-role-boundary":
            expect(j.page.locator(".procedure-step").get_by_role("button", name=j.text("تحديث الخطوة"), exact=True)).to_have_count(0)
            assert procedure(j)["payload"]["steps"][0]["status"] == "pending"
            update(manager, "completed", "Authorized manager completed the assigned review", evidence=True)
            requirements(manager, False)
            result["outcomes"] = ["manager-only task did not offer an unauthorized action", "authorized manager completed it using retained evidence"]

        elif scenario == "procedure-evidence-access-recovery":
            update(j, "completed", "Retained identity approval has been checked", evidence=True)
            manager.click("link", "السجلات والأدلة")
            restrict_batch(manager, "approval.json")
            j.page.locator(".procedure-step").get_by_role("button").filter(has_text="approval.json").click()
            j.settle()
            expect(j.page.locator("#global-message")).to_be_visible()
            expect(j.page.get_by_role("dialog")).to_have_count(0)
            restrict_batch(manager, "approval.json", j.page.evaluate("state.user.name"))
            j.page.locator(".procedure-step").get_by_role("button").filter(has_text="approval.json").click()
            j.settle()
            details = j.page.get_by_role("dialog")
            expect(details).to_contain_text("approval.json")
            assert_accessible(j.page)
            j.click("button", "إغلاق", details)
            result["outcomes"] = [
                "read action from an already open page respected revoked evidence access",
                "no evidence dialog opened while unauthorized",
                "same read action succeeded after access was restored",
            ]

        elif scenario == "procedure-handoff-readable-outcome":
            note = "Approval CHG-204 matches the recorded maintenance window; no response action remains."
            update(j, "completed", note, evidence=True)
            manager.page.reload()
            manager.settle()
            row = manager.page.locator(".procedure-step")
            expect(row).to_contain_text(note)
            expect(row).to_contain_text("approval.json")
            expect(manager.page.get_by_role("dialog")).to_have_count(0)
            row.get_by_role("button").filter(has_text="approval.json").click()
            manager.settle()
            details = manager.page.get_by_role("dialog")
            expect(details).to_contain_text("approval.json")
            evidence = next(item for item in manager.state()["evidence"] if "approval.json" in item["title"])
            expect(details).to_contain_text(evidence["sha256"])
            for width in (390, 1440):
                manager.page.set_viewport_size({"width": width, "height": 1000})
                assert manager.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                assert_accessible(manager.page)
                manager.page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-evidence-{width}.png"))
            manager.click("button", "إغلاق", details)
            row.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-result.png"))
            j.page.reload()
            j.settle()
            expect(j.page.locator(".procedure-step")).to_contain_text(note)
            expect(j.page.locator(".procedure-step").get_by_role("button", name=j.text("تحديث الخطوة"), exact=True)).to_have_count(0)
            result["outcomes"] = [
                "reviewer read the recorded result and evidence without entering an edit form",
                "completed step did not offer unauthorized reopening to the analyst",
            ]

        else:
            before = procedure(manager)
            version = manager.state()["version"]
            attach(manager)
            rows = manager.page.evaluate("id => api(`/api/cases/${id}/records?kind=playbook`)", manager.case_id)["items"]
            assert rows == [before] and manager.state()["version"] == version
            expect(manager.page.locator(".procedure-step")).to_have_count(1)
            result["outcomes"] = ["reselecting the attached template created no duplicate work", "case version unchanged"]

        assert_accessible(manager.page)
        for width in (390, 1440):
            manager.page.set_viewport_size({"width": width, "height": 1000})
            assert manager.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            manager.page.evaluate("window.scrollTo({top: 0, behavior: 'instant'})")
            manager.page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-{width}.png"), full_page=True)
