"""User interruption and recovery journeys; drafts never leave the document."""

import pytest
from playwright.sync_api import Error, expect

from tests.e2e.test_review_workflow import ANSWERS, review_session


def reply_once(page, accept=False):
    seen = []

    def reply(dialog):
        seen.append(dialog.type)
        dialog.accept() if accept else dialog.dismiss()

    page.once("dialog", reply)
    return seen


def cancel_reload(page):
    seen = reply_once(page)
    try:
        page.reload(timeout=3000)
    except Error as error:
        assert "ERR_ABORTED" in str(error) or "Timeout" in str(error)
    assert seen == ["beforeunload"]


def fill_answers(journey, note):
    for key, value in ANSWERS.items():
        journey.page.locator(f"select[name={key}]").select_option(value)
    journey.page.locator("input[name=executive_note]").fill(note)


SCENARIOS = [
    "leave-assessment",
    "close-draft-dialog",
    "reload-case-context",
    "switch-language",
    "network-save-retry",
    "stale-case-context",
    "untouched-library",
    "background-report-change",
]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", SCENARIOS)
def test_user_can_recover_drafts_without_silent_loss(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        page = j.page
        note = "Correlate identity records before reaching a final assessment."
        if scenario == "untouched-library":
            manager.login("manager@socify.local")
            manager.nav("مكتبة التحليل المحلي")
            assert not manager.page.evaluate("SOCifyDrafts.hasChanges()")
            manager.nav("إدارة القضايا")
            result["outcomes"] = ["untouched source and rule forms do not interrupt navigation"]
        elif scenario == "background-report-change":
            j.assessment("Review in progress", escalate=False)
            j.click("button", "إعداد تقرير جديد")
            expect(page.locator(".report-status")).to_contain_text(j.text("بانتظار المعالجة"))
            field = page.locator("input[name=executive_note]")
            field.fill(note)
            manager.login("manager@socify.local")
            manager.page.goto(j.case_url + "?tab=reports")
            manager.settle()
            manager.click("button", "إلغاء المعالجة")
            seen = []
            page.on("dialog", lambda dialog: (seen.append(dialog.type), dialog.dismiss()))
            page.wait_for_timeout(5500)
            expect(field).to_have_value(note)
            assert seen == []
            j.click("button", "حفظ إجابات التقرير")
            expect(field).to_have_value(note)
            assert not page.get_by_role("button", name=j.text("إلغاء المعالجة"), exact=True).count()
            expect(page.locator(".report-status")).to_contain_text(j.text("أُلغيت المعالجة"))
            result["outcomes"] = [
                "teammate cancelled a queued report",
                "background refresh did not erase assessment or interrupt typing",
                "saved work reveals updated report status",
            ]
        elif scenario == "close-draft-dialog":
            j.nav("إدارة القضايا")
            j.click("button", "إنشاء قضية")
            dialog = page.get_by_role("dialog")
            dialog.locator("input[name=title]").fill("Retain this investigation draft")
            seen = reply_once(page)
            j.click("button", "إغلاق", dialog)
            assert seen == ["confirm"]
            expect(dialog.locator("input[name=title]")).to_have_value("Retain this investigation draft")
            seen = reply_once(page, accept=True)
            dialog.press("Escape")
            expect(dialog).not_to_be_visible()
            assert seen == ["confirm"]
            assert not page.get_by_role("cell", name="Retain this investigation draft", exact=True).count()
            result["outcomes"] = ["cancel close retains draft", "explicit Escape discard closes without saving"]
        elif scenario in {"reload-case-context", "stale-case-context"}:
            panel = page.locator("section.panel").filter(has=page.get_by_role("heading", name=j.text("سبب القضية وهدفها ونتيجتها"), exact=True))
            panel.locator("summary").click()
            field = panel.locator("textarea[name=objective]")
            original = field.input_value()
            field.fill(note)
            if scenario == "reload-case-context":
                cancel_reload(page)
                expect(field).to_have_value(note)
                field.fill(original)
                page.reload()
                j.settle()
                result["outcomes"] = ["cancel reload retains edited objective", "reverting to original removes unnecessary warning"]
            else:
                manager.login("manager@socify.local")
                manager.page.goto(j.case_url)
                manager.settle()
                other = manager.page.locator("section.panel").filter(
                    has=manager.page.get_by_role("heading", name=manager.text("سبب القضية وهدفها ونتيجتها"), exact=True)
                )
                other.locator("summary").click()
                other.locator("textarea[name=objective]").fill("Review the identity provider approval record.")
                manager.click("button", "حفظ", other)
                j.click("button", "حفظ", panel)
                expect(panel.get_by_role("alert")).to_be_visible()
                expect(field).to_have_value(note)
                assert j.state()["context"]["objective"] == "Review the identity provider approval record."
                cancel_reload(page)
                expect(field).to_have_value(note)
                result["outcomes"] = ["stale save cannot overwrite teammate work", "rejected draft retained", "cancel refresh preserves recovery opportunity"]
        else:
            j.click("link", "التقارير والمراجعة")
            fill_answers(j, note)
            field = page.locator("input[name=executive_note]")
            if scenario == "leave-assessment":
                seen = reply_once(page)
                j.click("link", "السجلات والأدلة")
                assert seen == ["beforeunload"]
                expect(field).to_have_value(note)
                expect(page.locator("select[name=incident_classification]")).to_have_value("benign_activity")
                j.click("button", "حفظ إجابات التقرير")
                j.click("link", "السجلات والأدلة")
                j.click("link", "التقارير والمراجعة")
                expect(field).to_have_value(note)
                result["outcomes"] = [
                    "navigation cancellation retains assessment and answers",
                    "saving permits navigation",
                    "saved assessment retained on return",
                ]
            elif scenario == "switch-language":
                before = page.locator("html").get_attribute("lang")
                seen = reply_once(page)
                page.locator("[data-language-toggle]").click()
                assert seen == ["confirm"]
                expect(field).to_have_value(note)
                assert page.locator("html").get_attribute("lang") == before
                j.click("button", "حفظ إجابات التقرير")
                page.locator("[data-language-toggle]").click()
                j.settle()
                assert page.locator("html").get_attribute("lang") != before
                expect(field).to_have_value(note)
                result["outcomes"] = ["cancel language change leaves preference and draft unchanged", "saved content survives language change"]
            elif scenario == "network-save-retry":
                route = f"**/api/cases/{j.case_id}/quick-report"

                def disconnected(request):
                    request.abort("internetdisconnected")

                page.route(route, disconnected)
                j.click("button", "حفظ إجابات التقرير")
                expect(page.get_by_role("alert")).to_have_text(j.text("تعذر الاتصال. أعد المحاولة."))
                expect(field).to_have_value(note)
                cancel_reload(page)
                page.unroute(route, disconnected)
                j.click("button", "حفظ إجابات التقرير")
                page.reload()
                j.settle()
                expect(field).to_have_value(note)
                result["outcomes"] = ["failed network save retains work", "retry after reconnection saves the same assessment"]
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
