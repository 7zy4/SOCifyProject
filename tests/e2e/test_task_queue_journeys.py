"""Follow a real assigned batch from a manager's selection to an analyst's outcome."""

import pytest
from playwright.sync_api import expect

from tests.e2e.test_batch_boundary_journeys import restrict_batch, upload_logs
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_review_workflow import ARTIFACTS, review_session


def assignments(journey):
    return journey.page.evaluate("() => api('/api/team')")["assignments"]


def assign(journey, person, *, typed_case=False, instructions="Review the retained identity batch", filename="assigned-review.json", expected=1):
    journey.nav("الفريق")
    form = journey.page.locator("form").filter(has=journey.page.locator("[name=instructions]"))
    case = form.locator("input[name=case_id]")
    if typed_case:
        case.fill(journey.state()["reference"] + " · " + journey.state()["title"])
        case.press("Tab")
    else:
        case.press("ArrowDown")
        form.get_by_role("option").filter(has_text="Authorized maintenance investigation").first.click()
    expect(form.locator("input[name=job_id]")).to_be_visible()
    form.locator("input[name=job_id]").press("ArrowDown")
    form.get_by_role("option").filter(has_text=filename).first.click()
    form.locator("input[name=assignee]").press("ArrowDown")
    form.get_by_role("option").filter(has_text=person).first.click()
    form.locator("[name=instructions]").fill(instructions)
    journey.click("button", "حفظ", form)
    assert len(assignments(journey)) == expected


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "task-assignment-choice",
        "task-start-complete",
        "task-complete-from-case",
        "task-open-assigned-batch",
        "task-reopen-completed",
        "task-duplicate-assignment",
        "task-filter-status",
        "task-search-recovery",
        "task-manager-personal-scope",
        "task-batch-revoked",
        "task-batch-restored",
        "task-role-revoked",
        "task-concurrent-state",
        "task-queue-pagination",
    ],
)
def test_assigned_work_has_an_actionable_and_consistent_state(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        manager.login("manager@socify.local")
        manager.case_url = j.case_url
        manager.page.goto(j.case_url)
        manager.settle()
        upload_logs(manager, "assigned-review.json", "Assigned identity review event")
        person = j.page.evaluate("state.user.name")
        assign(manager, person)
        before = assignments(manager)[0]
        if scenario in {"task-start-complete", "task-reopen-completed"}:
            j.page.set_viewport_size({"width": 390, "height": 1000})
        j.nav("مهامي")
        expect(j.page.get_by_role("cell", name="Review the retained identity batch", exact=True)).to_be_visible()
        if scenario in {"task-start-complete", "task-reopen-completed"}:
            assert j.page.locator(".assignment-table").evaluate("el => el.scrollWidth <= el.clientWidth")
            result["interaction_viewport"] = 390
        if scenario == "task-start-complete":
            j.click("button", "بدء التحليل")
            assert assignments(j)[0]["task_status"] == "in_progress"
            j.click("button", "إكمال المهمة")
            after = assignments(j)[0]
            assert after["task_status"] == after["state"] == "completed"
            expect(j.page.locator("main")).not_to_contain_text("in_progress")
            expect(j.page.locator("main")).not_to_contain_text("completed")
        elif scenario == "task-complete-from-case":
            j.page.goto(j.case_url)
            j.settle()
            row = j.page.locator("tr").filter(has=j.page.get_by_role("cell", name="Review the retained identity batch", exact=True))
            j.click("button", "إكمال المهمة", row)
            after = assignments(j)[0]
            assert after["task_status"] == after["state"] == "completed"
            assert after["completed_at"] is not None
            j.nav("مهامي")
        elif scenario == "task-open-assigned-batch":
            manager.page.goto(j.case_url)
            manager.settle()
            upload_logs(manager, "separate-review.json", "Separate unassigned review event")
            j.click("link", "فتح الدفعة")
            expect(j.page.get_by_role("cell", name="Assigned identity review event", exact=True)).to_be_visible()
            expect(j.page.get_by_role("cell", name="Separate unassigned review event", exact=True)).to_have_count(0)
            assert f"job_id={before['job_id']}" in j.page.url
        elif scenario == "task-reopen-completed":
            j.click("button", "إكمال المهمة")
            assert assignments(j)[0]["completed_at"]
            j.click("button", "إعادة فتح المهمة")
            after = assignments(j)[0]
            assert after["task_status"] == after["state"] == "in_progress" and after["completed_at"] is None
            task = next(t for t in j.state()["tasks"] if t["id"] == before["task_id"])
            assert task["status"] == "in_progress" and task["completed_by"] is None
        elif scenario == "task-duplicate-assignment":
            version = manager.state()["version"]
            assign(manager, person)
            assert manager.state()["version"] == version
            assert assignments(manager)[0] == before
        elif scenario in {"task-filter-status", "task-search-recovery"}:
            form = j.page.locator(".assignment-queue form")
            if scenario == "task-filter-status":
                j.click("button", "إكمال المهمة")
                form.locator("select[name=task_status]").select_option("pending")
            else:
                form.locator("input[name=task_q]").fill("nothing matches this review")
            j.click("button", "بحث", form)
            expect(j.page.locator(".assignment-results")).to_contain_text(j.text("لا مهام مطابقة"))
            if scenario == "task-filter-status":
                form.locator("select[name=task_status]").select_option("completed")
            else:
                form.locator("input[name=task_q]").fill("assigned-review.json")
            j.click("button", "بحث", form)
            expect(j.page.get_by_role("cell", name="Review the retained identity batch", exact=True)).to_be_visible()
            j.page.reload()
            j.settle()
            expect(j.page.get_by_role("cell", name="Review the retained identity batch", exact=True)).to_be_visible()
            expect(j.page.locator("[name=task_status]" if scenario == "task-filter-status" else "[name=task_q]")).to_have_value(
                "completed" if scenario == "task-filter-status" else "assigned-review.json"
            )
        elif scenario == "task-manager-personal-scope":
            manager.nav("مهامي")
            expect(manager.page.get_by_role("cell", name="Review the retained identity batch", exact=True)).to_have_count(0)
            expect(manager.page.locator(".assignment-results")).to_contain_text(manager.text("لا مهام مطابقة"))
            manager.nav("الفريق")
            expect(manager.page.get_by_role("cell", name="Review the retained identity batch", exact=True)).to_be_visible()
        elif scenario in {"task-batch-revoked", "task-batch-restored"}:
            manager.page.goto(j.case_url + "?tab=logs")
            manager.settle()
            restrict_batch(manager, "assigned-review.json")
            j.click("button", "بدء التحليل")
            expect(j.page.locator(".assignment-queue [role=alert]")).to_be_visible()
            assert assignments(manager)[0]["task_status"] == "pending"
            j.click("button", "تحديث القائمة")
            expect(j.page.get_by_role("cell", name="Review the retained identity batch", exact=True)).to_have_count(0)
            if scenario == "task-batch-restored":
                restrict_batch(manager, "assigned-review.json", person)
                j.click("button", "تحديث القائمة")
                j.click("button", "بدء التحليل")
                assert assignments(j)[0]["state"] == "in_progress"
        elif scenario == "task-role-revoked":
            manager.nav("الفريق")
            policy = manager.page.locator('.team-role-policy[data-role="analyst"]')
            policy.locator("summary").click()
            policy.locator('input[value="cases.update"]').uncheck()
            manager.click("button", "حفظ حدود الدور", policy)
            j.click("button", "بدء التحليل")
            expect(j.page.locator(".assignment-queue [role=alert]")).to_be_visible()
            assert assignments(manager)[0]["task_status"] == "pending"
            j.click("button", "تحديث القائمة")
            expect(j.page.get_by_role("button", name=j.text("بدء التحليل"), exact=True)).to_have_count(0)
            expect(j.page.get_by_role("link", name=j.text("فتح الدفعة"), exact=True)).to_be_visible()
        elif scenario == "task-concurrent-state":
            manager.click("button", "إكمال المهمة", manager.page.locator(".assignment-queue"))
            j.click("button", "بدء التحليل")
            expect(j.page.locator(".assignment-queue [role=alert]")).to_contain_text(j.text("تغيرت المهمة. حدّث القائمة قبل المتابعة"))
            assert assignments(j)[0]["task_status"] == "completed"
            j.click("button", "تحديث القائمة")
            expect(j.page.get_by_role("button", name=j.text("إعادة فتح المهمة"), exact=True)).to_be_visible()
        elif scenario == "task-queue-pagination":
            for index in range(1, 26):
                manager.page.goto(j.case_url)
                manager.settle()
                filename = f"queue-{index:02d}.json"
                upload_logs(manager, filename, f"Queue review event {index}")
                assign(manager, person, instructions=f"Review retained queue batch {index}", filename=filename, expected=index + 1)
            j.page.reload()
            j.settle()
            expect(j.page.get_by_role("cell", name="Review the retained identity batch", exact=True)).to_have_count(0)
            j.page.locator("select[name=task_status]").select_option("pending")
            j.click("button", "بحث", j.page.locator(".assignment-queue form"))
            j.click("button", "التالي", j.page.locator(".assignment-queue"))
            expect(j.page.get_by_role("cell", name="Review the retained identity batch", exact=True)).to_be_visible()
            j.page.reload()
            j.settle()
            expect(j.page.get_by_role("cell", name="Review the retained identity batch", exact=True)).to_be_visible()
            j.click("button", "إكمال المهمة")
            assert next(row for row in assignments(manager) if row["id"] == before["id"])["state"] == "completed"
            expect(j.page.get_by_role("cell", name="Review the retained identity batch", exact=True)).to_have_count(0)
            expect(j.page.get_by_role("cell", name="Review retained queue batch 25", exact=True)).to_be_visible()
            assert "task_page=" not in j.page.url
            result["setup_only_assignments"] = 25
        assert len(assignments(manager)) == (26 if scenario == "task-queue-pagination" else 1)
        assert next(row for row in assignments(manager) if row["id"] == before["id"])["task_id"] == before["task_id"]
        assert_accessible(j.page)
        for width in (390, 1440):
            j.page.set_viewport_size({"width": width, "height": 1000})
            assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            j.page.evaluate("window.scrollTo({top: 0, behavior: 'instant'})")
            j.page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-{width}.png"), full_page=True)
        result["outcomes"] = [scenario, "assignment and linked case task inspected independently", "all business changes through visible interface"]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_case_reader_sees_ownership_without_an_unavailable_completion_action(app, language):
    scenario = "task-other-assignee-case"
    with review_session(app, language, scenario) as (j, manager, result):
        manager.login("manager@socify.local")
        manager.case_url = j.case_url
        manager.page.goto(j.case_url)
        manager.settle()
        upload_logs(manager, "assigned-review.json", "Manager assigned identity review")
        assign(manager, manager.page.evaluate("state.user.name"))
        j.page.goto(j.case_url)
        j.settle()
        row = j.page.locator("tr").filter(has=j.page.get_by_role("cell", name="Review the retained identity batch", exact=True))
        expect(row).to_be_visible()
        expect(row.get_by_role("button", name=j.text("إكمال المهمة"), exact=True)).to_have_count(0)
        manager.click("button", "إكمال المهمة", manager.page.locator(".assignment-queue"))
        j.page.reload()
        j.settle()
        expect(row).to_contain_text(j.text("مكتمل"))
        assert assignments(manager)[0]["state"] == "completed"
        assert_accessible(j.page)
        result["outcomes"] = ["case reader sees task without another assignee's action", "authorized owner completed it", "case and assignment agree"]
