"""Find and execute retained work beyond the first case-task page."""

import pytest
from playwright.sync_api import expect

from tests.e2e.test_assignment_handoff_journeys import handoff_form, role_permission
from tests.e2e.test_batch_boundary_journeys import restrict_batch, upload_logs
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_review_workflow import ARTIFACTS, review_session
from tests.e2e.test_task_queue_journeys import assign, assignments


def task_row(j, title):
    return j.page.locator(".case-task-queue tr").filter(has=j.page.get_by_role("cell", name=j.system_task_title(title), exact=True))


def search_tasks(j, value, status=None):
    form = j.page.locator(".case-task-queue form")
    form.locator("input[name=case_task_q]").fill(value)
    if status is not None:
        form.locator("select[name=case_task_status]").select_option(status)
    j.click("button", "بحث", form)


def capture(j, result):
    assert_accessible(j.page)
    for width in (390, 1440):
        j.page.set_viewport_size({"width": width, "height": 1000})
        assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        j.page.evaluate("window.scrollTo({top:0,behavior:'instant'})")
        j.page.screenshot(path=str(ARTIFACTS / f"{result['scenario']}-{result['language']}-{width}.png"), full_page=True)


def historical_backlog(manager, result, count=103):
    # Pre-existing work is prepared through the ordinary authenticated API.
    # These records are fixtures, not additional users or completed UI journeys.
    task_ids = manager.page.evaluate(
        """async ({caseId,count}) => {
          const ids=[];
          for(let i=0;i<count;i++) {
            const task=await api(`/api/incidents/${caseId}/tasks`, {method:'POST',body:{title:`Retained review item ${String(i+1).padStart(3,'0')}`,assignee:state.user.id}});
            ids.push(task.id);
          }
          return ids;
        }""",
        {"caseId": manager.case_id, "count": count},
    )
    result["setup_only_tasks"] = len(task_ids)
    result["setup_method"] = "Authenticated task-creation API; pre-existing backlog, excluded from journey counts"
    return task_ids


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_old_case_task_remains_actionable_from_performance(app, language):
    with review_session(app, language, "case-backlog-old-task") as (j, manager, result):
        manager.login("manager@socify.local")
        manager.case_url = j.case_url
        manager.page.goto(j.case_url)
        manager.settle()
        upload_logs(manager, "assigned-review.json", "Retained sign-in event requiring review")
        assign(manager, j.page.evaluate("state.user.name"))
        historical_backlog(manager, result)
        j.page.set_viewport_size({"width": 390, "height": 1000})
        result["interaction_viewport"] = 390
        j.nav("الأداء")
        j.page.get_by_role("link", name="Review the retained identity batch", exact=True).click()
        j.settle()
        row = j.page.locator("tr").filter(has=j.page.get_by_role("cell", name="Review the retained identity batch", exact=True))
        expect(row.get_by_role("button", name=j.text("إكمال المهمة"), exact=True)).to_be_visible()
        assert j.page.evaluate("document.activeElement.closest('tr')?.textContent.includes('Review the retained identity batch')")
        j.page.screenshot(path=str(ARTIFACTS / f"case-backlog-old-task-{language}-target.png"))
        j.click("button", "إكمال المهمة", row)
        expect(row.get_by_role("cell", name=j.page.evaluate("autopsyLabel('completed')"), exact=True)).to_be_visible()
        result["outcomes"] = ["old retained task reached and completed through the visible interface", "setup records excluded from user counts"]
        capture(j, result)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_repeated_case_task_completion_keeps_the_original_contributor(app, language):
    with review_session(app, language, "case-task-concurrent-completion") as (j, manager, result):
        manager.login("manager@socify.local")
        manager.case_url = j.case_url
        manager.page.goto(j.case_url)
        manager.settle()
        title = "Validate primary evidence"
        manager.click("button", "إكمال المهمة", task_row(manager, title))
        before = next(task for task in manager.state()["tasks"] if task["title"] == title)
        j.click("button", "إكمال المهمة", task_row(j, title))
        after = next(task for task in manager.state()["tasks"] if task["id"] == before["id"])
        result["original_completion"] = {key: before[key] for key in ("id", "completed_by", "completed_at")}
        result["repeated_completion"] = {key: after[key] for key in ("id", "completed_by", "completed_at")}
        assert result["repeated_completion"] == result["original_completion"]
        expect(task_row(j, title).get_by_role("button", name=j.text("إكمال المهمة"), exact=True)).to_have_count(0)
        result["outcomes"] = ["repeated completion did not change the first contributor or completion time"]
        capture(j, result)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("assigned", [False, True], ids=["ordinary", "assigned"])
def test_completing_work_preserves_the_open_case_draft(app, language, assigned):
    scenario = "case-task-draft-assigned" if assigned else "case-task-draft-ordinary"
    with review_session(app, language, scenario) as (j, manager, result):
        title = "Validate primary evidence"
        if assigned:
            manager.login("manager@socify.local")
            manager.case_url = j.case_url
            manager.page.goto(j.case_url)
            manager.settle()
            upload_logs(manager, "assigned-review.json", "Retained sign-in event requiring review")
            assign(manager, j.page.evaluate("state.user.name"))
            j.page.reload()
            j.settle()
            title = "Review the retained identity batch"
        section = j.page.locator("section.panel").filter(has=j.page.get_by_role("heading", name=j.text("سبب القضية وهدفها ونتيجتها"), exact=True))
        section.locator("summary").click()
        section.locator("input[name=reason]").fill("Authorized maintenance verification")
        section.locator("[name=objective]").fill("Confirm the retained identity evidence before closure")
        j.click("button", "إكمال المهمة", task_row(j, title))
        expect(section.locator("[name=objective]")).to_have_value("Confirm the retained identity evidence before closure")
        with j.page.expect_response(lambda response: response.url.endswith(f"/api/cases/{j.case_id}/context") and response.request.method == "PATCH") as saved:
            j.click("button", "حفظ", section)
        assert saved.value.status == 200
        assert j.state()["context"]["objective"] == "Confirm the retained identity evidence before closure"
        result["outcomes"] = ["open case draft preserved and saved after completing a task without reloading"]
        capture(j, result)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_task_completion_does_not_hide_another_edit_to_the_case(app, language):
    with review_session(app, language, "case-task-concurrent-draft") as (j, manager, result):
        manager.login("manager@socify.local")
        manager.case_url = j.case_url
        manager.page.goto(j.case_url)
        manager.settle()
        for actor, objective in [(j, "Analyst draft awaiting evidence review"), (manager, "Manager retained scope decision")]:
            section = actor.page.locator("section.panel").filter(
                has=actor.page.get_by_role("heading", name=actor.text("سبب القضية وهدفها ونتيجتها"), exact=True)
            )
            section.locator("summary").click()
            section.locator("[name=objective]").fill(objective)
            if actor is manager:
                manager.click("button", "حفظ", section)
        j.click("button", "إكمال المهمة", task_row(j, "Validate primary evidence"))
        section = j.page.locator("section.panel").filter(has=j.page.get_by_role("heading", name=j.text("سبب القضية وهدفها ونتيجتها"), exact=True))
        j.click("button", "حفظ", section)
        expect(section.get_by_role("alert")).to_be_visible()
        expect(section.locator("[name=objective]")).to_have_value("Analyst draft awaiting evidence review")
        assert j.state()["context"]["objective"] == "Manager retained scope decision"
        result["outcomes"] = ["task completion did not silently overwrite another contributor's case edit", "rejected draft retained for review"]
        capture(j, result)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "case-backlog-search",
        "case-backlog-empty-search",
        "case-backlog-status-filter",
        "case-backlog-pagination",
        "case-backlog-same-title",
        "case-backlog-foreign-focus",
        "case-backlog-missing-focus",
        "case-backlog-restricted-scope",
        "case-backlog-permission-change",
        "case-backlog-handoff",
        "case-backlog-network-retry",
    ],
)
def test_case_task_backlog_can_be_found_reviewed_and_recovered(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        manager.login("manager@socify.local")
        manager.case_url = j.case_url
        manager.page.goto(j.case_url)
        manager.settle()
        upload_logs(manager, "assigned-review.json", "Retained sign-in event requiring review")
        person = j.page.evaluate("state.user.name")
        assign(manager, person)
        assigned = assignments(manager)[0]
        historical_backlog(manager, result)
        title = "Review the retained identity batch"
        j.nav("الأداء")
        link = j.page.get_by_role("link", name=title, exact=True).get_attribute("href")
        target_url = j.base + link
        if scenario == "case-backlog-same-title":
            duplicate = manager.page.evaluate(
                "id => api(`/api/incidents/${id}/tasks`,{method:'POST',body:{title:'Review the retained identity batch',assignee:state.user.id}})", j.case_id
            )
            result["setup_only_tasks"] += 1
            j.page.goto(target_url)
            j.settle()
            row = task_row(j, title)
            expect(row).to_have_attribute("id", f"case-task-{assigned['task_id']}")
            j.click("button", "إكمال المهمة", row)
            assert assignments(manager)[0]["task_status"] == "completed"
            untouched = j.page.evaluate("({id,focus}) => api(`/api/cases/${id}/tasks?focus=${focus}`)", {"id": j.case_id, "focus": duplicate["id"]})
            assert next(task for task in untouched["items"] if task["id"] == duplicate["id"])["status"] == "pending"
        elif scenario == "case-backlog-foreign-focus":
            manager.nav("إدارة القضايا")
            manager.create_case()
            foreign = manager.page.evaluate(
                "id => api(`/api/incidents/${id}/tasks`,{method:'POST',body:{title:'Private finance containment decision',assignee:state.user.id}})",
                manager.case_id,
            )
            result["setup_only_tasks"] += 1
            j.page.goto(j.case_url + f"?tab=summary#case-task-{foreign['id']}")
            j.settle()
            expect(j.page.locator(".case-task-queue [role=alert]")).to_contain_text(j.text("المهمة غير متاحة"))
            expect(j.page.locator("main")).not_to_contain_text("Private finance containment decision")
            assert j.page.request.get(j.base + f"/api/cases/{j.case_id}/tasks?focus={foreign['id']}").status == 404
            j.click("button", "عرض مهام القضية", j.page.locator(".case-task-queue"))
            expect(task_row(j, "Retained review item 103")).to_be_visible()
        elif scenario == "case-backlog-missing-focus":
            for identifier in ("9223372036854775807", "9" * 30):
                j.page.goto(j.case_url + f"?tab=summary#case-task-{identifier}")
                j.settle()
                expect(j.page.locator(".case-task-queue [role=alert]")).to_be_visible()
                j.click("button", "عرض مهام القضية", j.page.locator(".case-task-queue"))
                expect(task_row(j, "Retained review item 103")).to_be_visible()
                assert "case-task-" not in j.page.url
            result["input_conditions"] = ["unknown valid task identifier", "identifier longer than the storage range"]
        elif scenario == "case-backlog-restricted-scope":
            manager.page.goto(j.case_url + "?tab=logs")
            manager.settle()
            restrict_batch(manager, "assigned-review.json")
            j.page.goto(target_url)
            j.settle()
            expect(j.page.locator(".case-task-queue")).to_have_count(0)
            expect(j.page.locator("main")).not_to_contain_text(title)
            assert j.page.request.get(j.base + f"/api/cases/{j.case_id}/tasks?focus={assigned['task_id']}").status == 403
            restrict_batch(manager, "assigned-review.json", person)
            j.page.reload()
            j.settle()
            expect(task_row(j, title)).to_be_visible()
        elif scenario == "case-backlog-permission-change":
            j.page.goto(target_url)
            j.settle()
            role_permission(manager, "cases.update", False)
            j.click("button", "إكمال المهمة", task_row(j, title))
            expect(j.page.locator(".case-task-queue [role=alert]")).to_be_visible()
            assert assignments(manager)[0]["task_status"] == "pending"
            j.click("button", "تحديث القائمة", j.page.locator(".case-task-queue"))
            expect(task_row(j, title).get_by_role("button")).to_have_count(0)
            role_permission(manager, "cases.update", True)
            j.click("button", "تحديث القائمة", j.page.locator(".case-task-queue"))
            j.click("button", "إكمال المهمة", task_row(j, title))
            assert assignments(manager)[0]["task_status"] == "completed"
        elif scenario == "case-backlog-handoff":
            manager_name = manager.page.evaluate("state.user.name")
            form = handoff_form(manager, person, manager_name)
            manager.click("button", "حفظ", form)
            j.page.goto(target_url)
            j.settle()
            expect(task_row(j, title).get_by_role("button")).to_have_count(0)
            expect(task_row(j, title).get_by_role("cell", name=manager_name, exact=True)).to_be_visible()
            manager.page.goto(target_url)
            manager.settle()
            manager.click("button", "إكمال المهمة", task_row(manager, title))
            assert assignments(manager)[0]["task_status"] == "completed"
            j.page.reload()
            j.settle()
        elif scenario == "case-backlog-network-retry":
            j.page.route("**/api/cases/*/tasks?*", lambda route: route.abort(), times=1)
            j.page.goto(target_url)
            j.settle()
            expect(j.page.locator(".case-task-queue [role=alert]")).to_be_visible()
            j.click("button", "إعادة المحاولة", j.page.locator(".case-task-queue"))
            expect(task_row(j, title)).to_be_visible()
            assert j.page.evaluate("document.activeElement.closest('tr')?.textContent.includes('Review the retained identity batch')")
        else:
            j.page.goto(j.case_url)
            j.settle()
            if scenario == "case-backlog-pagination":
                for _ in range(4):
                    j.click("button", "التالي", j.page.locator(".case-task-queue"))
                expect(task_row(j, title)).to_be_visible()
                assert "case_task_page=5" in j.page.url
                j.page.reload()
                j.settle()
                expect(task_row(j, title)).to_be_visible()
                j.page.locator("[data-language-toggle]").click()
                j.settle()
                expect(task_row(j, title)).to_be_visible()
                j.page.locator("[data-language-toggle]").click()
                j.settle()
                j.click("button", "السابق", j.page.locator(".case-task-queue"))
                assert "case_task_page=4" in j.page.url
                expect(task_row(j, title)).to_have_count(0)
            else:
                if scenario == "case-backlog-empty-search":
                    search_tasks(j, "no such retained work")
                    expect(j.page.locator(".case-task-queue")).to_contain_text(j.text("لا مهام مطابقة"))
                search_tasks(j, "Retained review item 001")
                expect(task_row(j, "Retained review item 001")).to_be_visible()
                if scenario == "case-backlog-status-filter":
                    j.click("button", "إكمال المهمة", task_row(j, "Retained review item 001"))
                    search_tasks(j, "Retained review item 001", "pending")
                    expect(j.page.locator(".case-task-queue")).to_contain_text(j.text("لا مهام مطابقة"))
                    search_tasks(j, "Retained review item 001", "completed")
                    expect(task_row(j, "Retained review item 001")).to_be_visible()
                j.page.reload()
                j.settle()
                expect(j.page.get_by_label(j.text("بحث مهام القضية"), exact=True)).to_have_value("Retained review item 001")
        capture(j, result)
        result["outcomes"] = [
            scenario,
            "retained task identity and authorized actions verified",
            "task actions through visible controls; backlog setup excluded",
        ]
