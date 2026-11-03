"""Finish one case action while keeping another investigation draft usable."""

import pytest
from playwright.sync_api import expect

from tests.e2e.test_assignment_handoff_journeys import choose, role_permission
from tests.e2e.test_case_membership_journeys import member_row, remove, transferred
from tests.e2e.test_followup_handoff_journeys import evidence_images, manager_case
from tests.e2e.test_review_workflow import review_session

DRAFT = "Verify the retained identity approval before deciding the investigation outcome."


def panel(j, title):
    return j.page.locator("section.panel").filter(has=j.page.get_by_role("heading", name=j.text(title), exact=True))


def context_form(j, value=DRAFT):
    section = panel(j, "سبب القضية وهدفها ونتيجتها")
    if section.locator("details").get_attribute("open") != "":
        section.locator("summary").click()
    section.locator("[name=objective]").fill(value)
    return section


def handoff(j, source, target):
    section = panel(j, "تسليم المناوبة")
    section.locator("summary").click()
    choose(j, section, "from_user", source)
    choose(j, section, "to_user", target)
    section.locator("[name=reason]").fill("Transfer the ongoing case while retaining the investigation draft")
    return section


def member_form(j, person):
    section = panel(j, "تحديد مسؤولية عضو")
    section.locator("summary").click()
    choose(j, section, "user_id", person)
    section.locator("[name=responsibility]").fill(j.page.evaluate("caseResponsibilityLabel('reviewer')"))
    return section


def status_form(j):
    section = panel(j, "حالة القضية")
    section.locator("[name=status]").fill(j.page.evaluate("autopsyLabel('investigating')"))
    section.locator("[name=reason]").fill("Start the retained evidence investigation")
    return section


def review_updates(j, section):
    section.locator("details.case-form-review > summary").click()
    j.click("button", "متابعة بعد المراجعة", section)


def retain_prompts(j, result):
    seen = []
    j.page.on("dialog", lambda event: (seen.append(event.message), event.dismiss()))
    result["unexpected_prompts"] = seen
    return seen


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", ["summary-member-draft", "summary-handoff-draft"])
def test_action_updates_the_case_without_discarding_another_draft(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        manager_case(j, manager)
        person = j.page.evaluate("state.user.name")
        if scenario == "summary-member-draft":
            transferred(j, manager, person)
        section = context_form(manager)
        seen = []
        manager.page.on("dialog", lambda event: (seen.append(event.message), event.dismiss()))
        if scenario == "summary-member-draft":
            dialog = remove(manager, person)
            expect(dialog).not_to_be_visible()
            assert j.page.request.get(j.base + f"/api/cases/{j.case_id}").status == 404
            expect(member_row(manager, person)).to_have_count(0)
        else:
            form = handoff(manager, person, manager.page.evaluate("state.user.name"))
            manager.click("button", "حفظ", form)
            expect(member_row(manager, person)).to_contain_text(manager.text("المناوبة السابقة"))
        expect(section.locator("[name=objective]")).to_have_value(DRAFT)
        assert not seen, "Saving an independent action must not ask to discard the other draft"
        manager.click("button", "حفظ", section)
        assert manager.state()["context"]["objective"] == DRAFT
        assert not manager.page.evaluate("SOCifyDrafts.hasChanges()")
        evidence_images(manager, result)
        result["outcomes"] = [
            scenario,
            "The successful action is visible immediately",
            "The independent draft remains and can be saved without overwriting a colleague",
        ]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "summary-grant-draft",
        "summary-status-draft",
        "summary-context-handoff",
        "summary-context-status",
        "summary-context-member",
        "summary-revoke-refresh-failure",
        "summary-handoff-refresh-failure",
        "summary-context-refresh-failure",
        "summary-concurrent-context",
        "summary-pending-independent-draft",
        "summary-save-network-retry",
        "summary-permission-restored",
    ],
)
def test_independent_case_work_survives_refresh_review_and_recovery(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        manager_case(j, manager)
        person, manager_name = j.page.evaluate("state.user.name"), manager.page.evaluate("state.user.name")
        if scenario == "summary-permission-restored":
            context_form(j)
            seen = retain_prompts(j, result)
            role_permission(manager, "cases.update", False)
            j.click("button", "تحديث القضية")
            form = j.page.locator('form[data-case-form="context"]')
            expect(form.locator("[name=objective]")).to_have_value(DRAFT)
            expect(form.get_by_role("button", name=j.text("حفظ"), exact=True)).to_be_disabled()
            role_permission(manager, "cases.update", True)
            j.click("button", "تحديث القضية")
            section = panel(j, "سبب القضية وهدفها ونتيجتها")
            expect(section.locator("[name=objective]")).to_have_value(DRAFT)
            j.click("button", "حفظ", section)
            assert j.state()["context"]["objective"] == DRAFT and not seen
            evidence_images(j, result)
            result["outcomes"] = [scenario, "Draft retained while editing permission was unavailable, then saved after restoration"]
            return
        if scenario == "summary-revoke-refresh-failure":
            transferred(j, manager, person)
        section = context_form(manager)
        seen = retain_prompts(manager, result)
        if scenario == "summary-concurrent-context":
            other_value = "Independent colleague review of the newest retained identity evidence"
            other = context_form(j, other_value)
            j.click("button", "حفظ", other)
            manager.click("button", "حفظ", section)
            assert manager.state()["context"]["objective"] == other_value
            expect(section.locator("[name=objective]")).to_have_value(DRAFT)
            section.locator("details.case-form-review > summary").click()
            expect(section.locator("details.case-form-review")).to_contain_text(other_value)
            manager.click("button", "متابعة بعد المراجعة", section)
            expect(section.locator("[name=objective]")).to_have_value(DRAFT)
            manager.click("button", "حفظ", section)
        elif scenario in {"summary-grant-draft", "summary-status-draft"}:
            action = member_form(manager, person) if scenario == "summary-grant-draft" else status_form(manager)
            manager.click("button", "حفظ", action)
            if scenario == "summary-grant-draft":
                expect(member_row(manager, person)).to_contain_text(manager.page.evaluate("caseResponsibilityLabel('reviewer')"))
            else:
                assert manager.state()["status"] == "investigating"
            expect(section.locator("[name=objective]")).to_have_value(DRAFT)
            manager.click("button", "حفظ", section)
        elif scenario in {"summary-context-handoff", "summary-context-status", "summary-context-member"}:
            action = (
                handoff(manager, person, manager_name)
                if scenario.endswith("handoff")
                else status_form(manager)
                if scenario.endswith("status")
                else member_form(manager, person)
            )
            manager.click("button", "حفظ", section)
            review_updates(manager, action)
            manager.click("button", "حفظ", action)
            if scenario.endswith("handoff"):
                expect(member_row(manager, person)).to_contain_text(manager.text("المناوبة السابقة"))
            elif scenario.endswith("status"):
                assert manager.state()["status"] == "investigating"
            else:
                expect(member_row(manager, person)).to_contain_text(manager.page.evaluate("caseResponsibilityLabel('reviewer')"))
        elif scenario == "summary-pending-independent-draft":
            held = {}

            def hold(route):
                if route.request.method == "PATCH":
                    held.update(route=route, response=route.fetch())
                else:
                    route.continue_()

            manager.page.route(f"**/api/cases/{j.case_id}/context", hold)
            section.get_by_role("button", name=manager.text("حفظ"), exact=True).click()
            expect(section.locator("[name=objective]")).to_be_disabled()
            action = member_form(manager, person)
            assert held["response"].status == 200
            held["route"].fulfill(response=held["response"])
            manager.settle()
            manager.page.unroute(f"**/api/cases/{j.case_id}/context", hold)
            review_updates(manager, action)
            manager.click("button", "حفظ", action)
        elif scenario == "summary-save-network-retry":
            action = handoff(manager, person, manager_name)
            failed = {"done": False}

            def interrupt(route):
                if route.request.method == "POST" and not failed["done"]:
                    failed["done"] = True
                    route.abort("failed")
                else:
                    route.continue_()

            manager.page.route(f"**/api/cases/{j.case_id}/handoff", interrupt)
            manager.click("button", "حفظ", action)
            expect(action.locator("[role=alert]")).to_be_visible()
            expect(section.locator("[name=objective]")).to_have_value(DRAFT)
            manager.click("button", "حفظ", action)
            expect(member_row(manager, person)).to_contain_text(manager.text("المناوبة السابقة"))
            manager.click("button", "حفظ", section)
        else:
            failure = {"done": False}
            calls = []
            route = "members/" + str(j.page.evaluate("state.user.id")) if "revoke" in scenario else "handoff" if "handoff" in scenario else "context"
            method = "DELETE" if "revoke" in scenario else "POST" if "handoff" in scenario else "PATCH"
            manager.page.on("request", lambda request: calls.append(request.url) if request.method == method and request.url.endswith("/" + route) else None)

            def fail_refresh(intercept):
                if intercept.request.method == "GET" and not failure["done"]:
                    failure["done"] = True
                    intercept.fulfill(
                        status=503, content_type="application/json", body='{"error":{"code":"TEMPORARY_UNAVAILABLE","message":"Temporary failure"}}'
                    )
                else:
                    intercept.continue_()

            manager.page.route(f"**/api/cases/{j.case_id}", fail_refresh)
            if "revoke" in scenario:
                action = remove(manager, person)
            elif "handoff" in scenario:
                action = handoff(manager, person, manager_name)
                manager.click("button", "حفظ", action)
            else:
                other = status_form(manager)
                action = section
                manager.click("button", "حفظ", action)
            expect(action.locator("[role=alert]")).to_contain_text(manager.text("حُفظ الإجراء. تعذر تحديث القضية؛ أعد المحاولة."))
            assert len(calls) == 1
            manager.click("button", "تحديث القضية", action)
            assert len(calls) == 1, "Refreshing a known saved action must not repeat its mutation"
            if route == "context":
                review_updates(manager, other)
                manager.click("button", "حفظ", other)
            else:
                expect(section.locator("[name=objective]")).to_have_value(DRAFT)
                manager.click("button", "حفظ", section)
        assert manager.state()["context"]["objective"] == DRAFT
        assert not seen
        assert not manager.page.evaluate("SOCifyDrafts.hasChanges()")
        evidence_images(manager, result)
        result["outcomes"] = [
            scenario,
            "Independent drafts retained and completed through visible controls",
            "Updated case data is visible; concurrent changes require review",
        ]
