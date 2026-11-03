"""End a colleague's access to one case through the visible controls."""

import pytest
from playwright.sync_api import expect

from tests.e2e.test_assignment_handoff_journeys import choose, handoff_form
from tests.e2e.test_batch_boundary_journeys import restrict_batch, upload_logs
from tests.e2e.test_followup_handoff_journeys import evidence_images, manager_case
from tests.e2e.test_investigation_link_journeys import note_dialog, records
from tests.e2e.test_review_workflow import ARTIFACTS, ReviewJourney, review_session
from tests.e2e.test_task_queue_journeys import assign, assignments


def member_row(j, name):
    panel = j.page.locator("section.panel").filter(has=j.page.get_by_role("heading", name=j.text("فريق القضية"), exact=True))
    return panel.locator("tr").filter(has=j.page.get_by_role("cell", name=name, exact=True))


def removal_dialog(manager, name):
    manager.click("button", "سحب الوصول", member_row(manager, name))
    return manager.page.get_by_role("dialog")


def remove(manager, name):
    dialog = removal_dialog(manager, name)
    dialog.locator("[name=reason]").fill("The outgoing shift has completed its responsibility for this case")
    manager.click("button", "سحب الوصول", dialog)
    return dialog


def grant(manager, person):
    manager.page.goto(manager.case_url)
    manager.settle()
    panel = manager.page.locator("section.panel").filter(has=manager.page.get_by_role("heading", name=manager.text("تحديد مسؤولية عضو"), exact=True))
    panel.locator("summary").click()
    choose(manager, panel, "user_id", person)
    panel.locator("[name=responsibility]").fill(manager.page.evaluate("caseResponsibilityLabel('reviewer')"))
    manager.click("button", "حفظ", panel)


def discard(manager, dialog):
    manager.page.once("dialog", lambda event: event.accept())
    manager.click("button", "إغلاق", dialog)


def transferred(j, manager, person):
    form = handoff_form(manager, person, manager.page.evaluate("state.user.name"))
    manager.click("button", "حفظ", form)
    assert j.page.request.get(j.base + f"/api/cases/{j.case_id}").status == 200


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_handoff_then_end_only_the_outgoing_case_access(app, language):
    with review_session(app, language, "membership-handoff-revoke") as (j, manager, result):
        person = j.page.evaluate("state.user.name")
        manager_case(j, manager)
        form = handoff_form(manager, person, manager.page.evaluate("state.user.name"))
        manager.click("button", "حفظ", form)
        dialog = remove(manager, person)
        expect(dialog).not_to_be_visible()
        expect(member_row(manager, person)).to_have_count(0)
        assert j.page.request.get(j.base + f"/api/cases/{j.case_id}").status == 404
        assert j.page.request.get(j.base + "/api/auth/me").status == 200
        j.page.reload()
        j.settle()
        expect(j.page.locator("main")).not_to_contain_text("Authorized maintenance investigation")
        evidence_images(manager, result)
        result["outcomes"] = ["Responsibility transferred before access removal", "Case unavailable in the existing session; account remains active"]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "membership-owner-recovery",
        "membership-open-assignment",
        "membership-completed-history",
        "membership-stale-note",
        "membership-lost-receipt",
        "membership-network-before-commit",
        "membership-other-case",
        "membership-regrant-restricted",
        "membership-cancel",
        "membership-reason-required",
        "membership-stale-regrant",
        "membership-manager-access",
        "membership-stale-case",
    ],
)
def test_case_local_access_removal_is_safe_and_recoverable(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        person = j.page.evaluate("state.user.name")
        person_id = j.page.evaluate("state.user.id")
        original_case = (j.case_id, j.case_url)
        other_case = None
        if scenario == "membership-other-case":
            j.nav("إدارة القضايا")
            j.create_case()
            other_case = j.case_id
            j.case_id, j.case_url = original_case
            j.page.goto(j.case_url)
            j.settle()
        manager_case(j, manager)
        if scenario == "membership-owner-recovery":
            dialog = remove(manager, person)
            expect(dialog.locator("[role=alert]")).to_contain_text(manager.text("سلّم مسؤوليات العضو عبر تسليم المناوبة قبل سحب وصوله"))
            assert j.page.request.get(j.base + f"/api/cases/{j.case_id}").status == 200
            evidence_images(manager, result)
            discard(manager, dialog)
        transferred(j, manager, person)
        if scenario == "membership-manager-access":
            expect(
                member_row(manager, manager.page.evaluate("state.user.name")).get_by_role("button", name=manager.text("سحب الوصول"), exact=True)
            ).to_have_count(0)
            manager.page.set_viewport_size({"width": 390, "height": 1000})
            member_row(manager, person).screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-action.png"))
        if scenario in {"membership-open-assignment", "membership-completed-history", "membership-regrant-restricted"}:
            upload_logs(manager, "assigned-review.json", "Retained case membership evidence")
            if scenario == "membership-regrant-restricted":
                restrict_batch(manager, "assigned-review.json", person)
            else:
                assign(manager, person)
                j.nav("مهامي")
                if scenario == "membership-completed-history":
                    j.click("button", "إكمال المهمة")
                    retained = assignments(manager)[0]
            manager.page.goto(j.case_url)
            manager.settle()
        if scenario == "membership-stale-note":
            j.click("link", "التحقيق والخط الزمني")
            note = note_dialog(j)
            note.locator("textarea[name=body]").fill("Unsaved case note after the shift ended")
        if scenario == "membership-open-assignment":
            dialog = remove(manager, person)
            expect(dialog.locator("[role=alert]")).to_contain_text(manager.text("سلّم مسؤوليات العضو عبر تسليم المناوبة قبل سحب وصوله"))
            discard(manager, dialog)
            transferred(j, manager, person)
            assert assignments(manager)[0]["assignee"] == manager.page.evaluate("state.user.id")
        if scenario in {"membership-cancel", "membership-reason-required"}:
            dialog = removal_dialog(manager, person)
            if scenario == "membership-cancel":
                dialog.locator("[name=reason]").fill("Cancelled access change")
                discard(manager, dialog)
                assert j.page.request.get(j.base + f"/api/cases/{j.case_id}").status == 200
                dialog = removal_dialog(manager, person)
            else:
                manager.click("button", "سحب الوصول", dialog)
                assert not dialog.locator("form").evaluate("form=>form.checkValidity()")
                assert j.page.request.get(j.base + f"/api/cases/{j.case_id}").status == 200
            dialog.locator("[name=reason]").fill("Access no longer needed after completed handoff")
            manager.click("button", "سحب الوصول", dialog)
        else:
            lost = {"done": False}
            if scenario in {"membership-lost-receipt", "membership-network-before-commit", "membership-stale-regrant"}:

                def interrupt(route):
                    if route.request.method == "DELETE" and not lost["done"]:
                        lost["done"] = True
                        if scenario != "membership-network-before-commit":
                            response = route.fetch()
                            assert response.status == 200
                        route.abort("failed")
                    else:
                        route.continue_()

                manager.page.route(f"**/api/cases/{j.case_id}/members/{person_id}", interrupt)
            dialog = removal_dialog(manager, person)
            dialog.locator("[name=reason]").fill("End this case access after the shift completed")
            colleague = None
            if scenario == "membership-stale-case":
                j.click("link", "التحقيق والخط الزمني")
                note = note_dialog(j)
                j.click("button", "حفظ", note)
            manager.click("button", "سحب الوصول", dialog)
            if lost["done"] or scenario == "membership-stale-case":
                expect(dialog.locator("[role=alert]")).to_be_visible()
                expect(dialog.locator("[name=reason]")).to_have_value("End this case access after the shift completed")
                if scenario == "membership-stale-regrant":
                    page = manager.page.context.browser.new_page(locale="ar-SA" if language == "ar" else "en-US")
                    page.on("pageerror", lambda error: result["browser_errors"].append(str(error)))
                    colleague = ReviewJourney(page, manager.base, result["steps"])
                    colleague.login("manager@socify.local")
                    colleague.case_id, colleague.case_url = j.case_id, j.case_url
                    grant(colleague, person)
                    manager.click("button", "سحب الوصول", dialog)
                    expect(dialog.locator("[role=alert]")).to_contain_text(
                        manager.text("تغيرت القضية؛ حدّث قبل الحفظ") if language == "ar" else "The case changed"
                    )
                    assert j.page.request.get(j.base + f"/api/cases/{j.case_id}").status == 200
                if scenario in {"membership-stale-regrant", "membership-stale-case"}:
                    discard(manager, dialog)
                    manager.page.reload()
                    manager.settle()
                    dialog = remove(manager, person)
                else:
                    manager.click("button", "سحب الوصول", dialog)
                if colleague:
                    colleague.page.close()
        expect(dialog).not_to_be_visible()
        expect(member_row(manager, person)).to_have_count(0)
        assert j.page.request.get(j.base + f"/api/cases/{j.case_id}").status == 404
        assert j.page.request.get(j.base + "/api/auth/me").status == 200
        if scenario == "membership-stale-note":
            j.click("button", "حفظ", note)
            expect(note.locator("form > [role=alert]")).to_be_visible()
            assert records(manager, "war_room") == []
        if scenario == "membership-completed-history":
            assert assignments(manager)[0] == retained
        if other_case:
            assert j.page.request.get(j.base + f"/api/cases/{other_case}").status == 200
            j.page.goto(j.base + f"/cases/{other_case}")
            j.settle()
            expect(j.page.locator("#workspace")).to_contain_text("Authorized maintenance investigation")
        if scenario == "membership-regrant-restricted":
            grant(manager, person)
            j.page.goto(j.case_url + "?tab=logs")
            j.settle()
            expect(j.page.locator("main")).not_to_contain_text("Retained case membership evidence")
            manager.page.goto(j.case_url + "?tab=logs")
            manager.settle()
            restrict_batch(manager, "assigned-review.json", person)
            j.page.reload()
            j.settle()
            expect(j.page.get_by_role("cell", name="Retained case membership evidence", exact=True)).to_be_visible()
        evidence_images(manager, result)
        result["outcomes"] = [
            scenario,
            "Case-specific access change through visible controls",
            "Access denial verified in the existing analyst session without disabling the account",
        ]
