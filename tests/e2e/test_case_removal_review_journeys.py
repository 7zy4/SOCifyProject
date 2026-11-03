"""Finish a case-local access decision after another investigator changes the case."""

import pytest
from playwright.sync_api import expect

from tests.e2e.test_case_membership_journeys import discard, grant, member_row, removal_dialog, remove, transferred
from tests.e2e.test_case_summary_recovery_journeys import context_form, review_updates
from tests.e2e.test_followup_handoff_journeys import evidence_images, manager_case
from tests.e2e.test_review_workflow import ARTIFACTS, ReviewJourney, review_session

REASON = "The handoff is complete; end access to this case and retain the investigation history."


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", ["removal-review-objective", "removal-review-independent-draft"])
def test_review_new_case_data_without_retyping_access_removal_reason(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        manager_case(j, manager)
        person = j.page.evaluate("state.user.name")
        transferred(j, manager, person)
        objective = "Retain my independent investigation objective while reviewing case access."
        if scenario.endswith("independent-draft"):
            context_form(manager, objective)
        dialog = removal_dialog(manager, person)
        dialog.locator("[name=reason]").fill(REASON)
        j.click("button", "تحديث القضية")
        section = context_form(j, "A colleague reviewed the new identity evidence during the handoff.")
        j.click("button", "حفظ", section)
        assert j.state()["context"]["objective"] == "A colleague reviewed the new identity evidence during the handoff."
        manager.click("button", "سحب الوصول", dialog)
        expect(dialog.locator("[role=alert]")).to_be_visible()
        expect(dialog.locator("[name=reason]")).to_have_value(REASON)
        expect(dialog.locator("details.case-form-review > summary")).to_be_visible()
        review_updates(manager, dialog)
        expect(dialog.locator("[name=reason]")).to_have_value(REASON)
        manager.click("button", "سحب الوصول", dialog)
        expect(dialog).not_to_be_visible()
        expect(member_row(manager, person)).to_have_count(0)
        assert j.page.request.get(j.base + f"/api/cases/{j.case_id}").status == 404
        if scenario.endswith("independent-draft"):
            section = manager.page.locator('form[data-case-form="context"]')
            expect(section.locator("[name=objective]")).to_have_value(objective)
            review_updates(manager, section)
            manager.click("button", "حفظ", section)
            assert manager.state()["context"]["objective"] == objective
        evidence_images(manager, result)
        result["outcomes"] = [
            "Reviewed a colleague's new case state without closing the access dialog",
            "Kept the reason and completed removal from the same dialog",
        ]


def another_manager(manager, j, result):
    page = manager.page.context.browser.new_page(locale="ar-SA" if result["language"] == "ar" else "en-US")
    page.on("pageerror", lambda error: result["browser_errors"].append(str(error)))
    colleague = ReviewJourney(page, manager.base, result["steps"])
    colleague.login("manager@socify.local")
    colleague.case_id, colleague.case_url = j.case_id, j.case_url
    page.goto(j.case_url)
    colleague.settle()
    return colleague


def change_objective(j, value):
    j.click("button", "تحديث القضية")
    form = context_form(j, value)
    j.click("button", "حفظ", form)
    assert j.state()["context"]["objective"] == value


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "removal-review-repeated-change",
        "removal-review-refresh-failure",
        "removal-review-lost-ack",
        "removal-review-cancel",
        "removal-review-keep-editing",
        "removal-review-owner-returned",
        "removal-review-colleague-completed",
    ],
)
def test_removal_review_survives_new_changes_interruption_and_reconsideration(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        manager_case(j, manager)
        person = j.page.evaluate("state.user.name")
        transferred(j, manager, person)
        dialog = removal_dialog(manager, person)
        dialog.locator("[name=reason]").fill(REASON)
        colleague = None
        if scenario in {"removal-review-owner-returned", "removal-review-colleague-completed"}:
            colleague = another_manager(manager, j, result)
            if scenario.endswith("owner-returned"):
                grant(colleague, person)
                section = colleague.page.locator("section.panel").filter(
                    has=colleague.page.get_by_role("heading", name=colleague.text("تحديد مسؤولية عضو"), exact=True)
                )
                section.locator("summary").click()
                from tests.e2e.test_assignment_handoff_journeys import choose

                choose(colleague, section, "user_id", person)
                section.locator("[name=responsibility]").fill(colleague.page.evaluate("caseResponsibilityLabel('owner')"))
                colleague.click("button", "حفظ", section)
            else:
                remove(colleague, person)
        else:
            change_objective(j, "A colleague added a retained investigation decision before access removal.")
        interrupted = {"done": False}
        if scenario == "removal-review-refresh-failure":

            def fail_refresh(route):
                if not interrupted["done"]:
                    interrupted["done"] = True
                    route.fulfill(status=503, content_type="application/json", body='{"error":{"code":"UNAVAILABLE","message":"Temporary failure"}}')
                else:
                    route.continue_()

            manager.page.route(f"**/api/cases/{j.case_id}", fail_refresh)
        if scenario == "removal-review-lost-ack":

            def lose_ack(route):
                if route.request.method == "DELETE" and not interrupted["done"]:
                    response = route.fetch()
                    if response.status == 200:
                        interrupted["done"] = True
                        route.abort("failed")
                    else:
                        route.fulfill(response=response)
                else:
                    route.continue_()

            manager.page.route(f"**/api/cases/{j.case_id}/members/*", lose_ack)
        manager.click("button", "سحب الوصول", dialog)
        if scenario != "removal-review-colleague-completed":
            expect(dialog.locator("[role=alert]")).to_be_visible()
            expect(dialog.locator("[name=reason]")).to_have_value(REASON)
            if scenario == "removal-review-refresh-failure":
                assert interrupted["done"]
                expect(dialog.locator("details.case-form-review")).to_have_count(0)
                manager.click("button", "سحب الوصول", dialog)
            if scenario == "removal-review-cancel":
                discard(manager, dialog)
                assert j.page.request.get(j.base + f"/api/cases/{j.case_id}").status == 200
                dialog = removal_dialog(manager, person)
                dialog.locator("[name=reason]").fill(REASON)
            else:
                if scenario == "removal-review-keep-editing":
                    manager.page.once("dialog", lambda event: event.dismiss())
                    manager.click("button", "إغلاق", dialog)
                    expect(dialog.locator("[name=reason]")).to_have_value(REASON)
                dialog.locator("details.case-form-review > summary").click()
                if scenario == "removal-review-repeated-change":
                    manager.page.set_viewport_size({"width": 390, "height": 1000})
                    dialog.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-review.png"))
                    manager.page.set_viewport_size({"width": 1440, "height": 1000})
                if scenario == "removal-review-owner-returned":
                    expect(dialog.locator("details.case-form-review")).to_contain_text(manager.text("مسؤول القضية"))
                manager.click("button", "متابعة بعد المراجعة", dialog)
                if scenario == "removal-review-repeated-change":
                    change_objective(j, "A second colleague decision arrived after the manager reviewed the first change.")
                    manager.click("button", "سحب الوصول", dialog)
                    expect(dialog.locator("[name=reason]")).to_have_value(REASON)
                    review_updates(manager, dialog)
            manager.click("button", "سحب الوصول", dialog)
            if scenario == "removal-review-lost-ack":
                assert interrupted["done"]
                expect(dialog.locator("[role=alert]")).to_be_visible()
                expect(dialog.locator("[name=reason]")).to_have_value(REASON)
                manager.click("button", "سحب الوصول", dialog)
            elif scenario == "removal-review-owner-returned":
                expect(dialog.locator("[role=alert]")).to_be_visible()
                assert j.page.request.get(j.base + f"/api/cases/{j.case_id}").status == 200
                discard(manager, dialog)
                transferred(j, manager, person)
                dialog = remove(manager, person)
        expect(dialog).not_to_be_visible()
        expect(member_row(manager, person)).to_have_count(0)
        assert j.page.request.get(j.base + f"/api/cases/{j.case_id}").status == 404
        custody = manager.page.request.get(manager.base + f"/api/cases/{j.case_id}/custody").json()
        assert len([row for row in custody["items"] if row["action"] == "member_access_revoked"]) == 1
        assert custody["integrity_valid"]
        if colleague:
            colleague.page.close()
        evidence_images(manager, result)
        result["outcomes"] = [
            scenario,
            "Completed case-local access removal without duplicate custody entries",
            "Current ownership and later colleague changes were respected",
        ]
