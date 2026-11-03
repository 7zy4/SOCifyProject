"""A completed shift can hand off work assigned after its earlier handoff."""

import pytest

from tests.e2e.test_assignment_handoff_journeys import handoff_form
from tests.e2e.test_batch_boundary_journeys import upload_logs
from tests.e2e.test_case_membership_journeys import remove, transferred
from tests.e2e.test_followup_handoff_journeys import evidence_images, manager_case
from tests.e2e.test_review_workflow import review_session
from tests.e2e.test_task_queue_journeys import assign, assignments


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_later_assigned_work_can_be_transferred_before_access_removal(app, language):
    with review_session(app, language, "membership-returning-work") as (j, manager, result):
        person = j.page.evaluate("state.user.name")
        manager_case(j, manager)
        transferred(j, manager, person)
        upload_logs(manager, "assigned-review.json", "Follow-up evidence assigned after the earlier shift")
        assign(manager, person)
        form = handoff_form(manager, person, manager.page.evaluate("state.user.name"))
        manager.click("button", "حفظ", form)
        assert assignments(manager)[0]["assignee"] == manager.page.evaluate("state.user.id"), "New work must be transferable after a prior shift handoff"
        remove(manager, person)
        manager.nav("مهامي")
        manager.click("button", "بدء التحليل")
        manager.click("button", "إكمال المهمة")
        assert assignments(manager)[0]["state"] == "completed"
        assert j.page.request.get(j.base + f"/api/cases/{j.case_id}").status == 404
        evidence_images(manager, result)
        result["outcomes"] = [
            "New work after a previous handoff transferred and completed by the incoming owner",
            "Outgoing case access revoked without rewriting prior work",
        ]
