"""Keep a late case response separate from the next investigation."""

import re
import time

import pytest
from playwright.sync_api import expect

from tests.e2e.test_case_summary_recovery_journeys import context_form
from tests.e2e.test_followup_handoff_journeys import evidence_images, manager_case
from tests.e2e.test_review_workflow import review_session


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "pending-refresh-leave",
        "pending-refresh-discard",
        "pending-refresh-stay",
        "pending-save-ack-stay",
        "pending-save-refresh-leave",
        "pending-save-ack-leave",
    ],
)
def test_late_response_stays_with_its_case_and_respects_navigation_intent(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        manager_case(j, manager)
        original_id, original_url = j.case_id, j.case_url
        original_objective = j.state()["context"]["objective"]
        manager.click("link", "جميع القضايا")
        manager.click("button", "إنشاء قضية")
        dialog = manager.page.get_by_role("dialog")
        title = "Separate investigation with its own evidence and decision"
        dialog.locator("input[name=title]").fill(title)
        manager.click("button", "حفظ", dialog)
        other_id = int(re.search(r"/cases/(\d+)", manager.page.url)[1])
        manager.page.goto(original_url)
        manager.settle()
        value = "Retain this original-case objective without applying it to the next investigation."
        save_pending = scenario.startswith("pending-save")
        dirty = scenario != "pending-refresh-leave"
        section = context_form(manager, value) if dirty else None
        hold_method = "PATCH" if "save-ack" in scenario else "GET"
        path = f"**/api/cases/{original_id}" + ("/context" if hold_method == "PATCH" else "")
        held = {}

        def delay(route):
            if route.request.method == hold_method and not held:
                held.update(route=route, response=route.fetch())
            else:
                route.continue_()

        manager.page.route(path, delay)
        if save_pending:
            section.get_by_role("button", name=manager.text("حفظ"), exact=True).click()
        else:
            manager.page.get_by_role("button", name=manager.text("تحديث القضية"), exact=True).click()
        deadline = time.monotonic() + 5
        while not held and time.monotonic() < deadline:
            manager.page.wait_for_timeout(25)
        assert held and held["response"].status == 200
        stay = scenario.endswith("stay")
        prompts = []

        def navigation_choice(event):
            prompts.append(event.type)
            event.dismiss() if stay else event.accept()

        manager.page.on("dialog", navigation_choice)
        manager.page.get_by_role("link", name=manager.text("جميع القضايا"), exact=True).click()
        if stay:
            assert manager.page.url == original_url
            held["route"].fulfill(response=held["response"])
            manager.settle()
            if not save_pending:
                expect(section.locator("[name=objective]")).to_have_value(value)
                manager.click("button", "حفظ", section)
            assert manager.state()["context"]["objective"] == value
        else:
            manager.page.wait_for_url(re.compile(r"/cases(?:\?.*)?$"))
            manager.settle()
            # A browser-aborted response belongs to the retired document. Do not
            # turn cleanup into an artificial new request in the destination.
            if held["route"].request.failure:
                result["retired_response"] = held["route"].request.failure
            else:
                held["route"].fulfill(response=held["response"])
            manager.page.unroute(path, delay)
            manager.page.locator("a.case-link").filter(has_text=title).click()
            manager.settle()
            expect(manager.page.locator(".workspace-head h2")).to_have_text(title)
            assert manager.page.evaluate("autopsy.current.id") == other_id
            other_value = "Save the separate investigation objective only to its own case."
            form = context_form(manager, other_value)
            manager.click("button", "حفظ", form)
            assert manager.page.request.get(manager.base + f"/api/cases/{other_id}").json()["context"]["objective"] == other_value
            original = manager.page.request.get(manager.base + f"/api/cases/{original_id}").json()
            assert original["context"]["objective"] == (value if save_pending else original_objective)
        expected_prompt = dirty and scenario != "pending-save-refresh-leave"
        assert len(prompts) == int(expected_prompt), prompts
        evidence_images(manager, result)
        result["outcomes"] = [
            scenario,
            "The user's leave or stay choice was respected",
            "A late response did not replace the next case or move a draft across cases",
        ]
