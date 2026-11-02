"""Transfer actual work between shifts without inventing access or changing its history."""

import pytest
from playwright.sync_api import expect

from tests.e2e.test_batch_boundary_journeys import restrict_batch, upload_logs
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_review_workflow import ARTIFACTS, review_session
from tests.e2e.test_task_queue_journeys import assign, assignments


def choose(j, form, field, person, capture=None):
    form.locator(f"input[name={field}]").press("ArrowDown")
    if capture:
        j.page.screenshot(path=str(ARTIFACTS / capture))
    form.get_by_role("option").filter(has_text=person).first.click()


def assignment_form(manager, person):
    manager.nav("الفريق")
    form = manager.page.locator("form").filter(has=manager.page.locator("[name=instructions]"))
    choose(manager, form, "case_id", "Authorized maintenance investigation")
    choose(manager, form, "job_id", "assigned-review.json")
    choose(manager, form, "assignee", person)
    form.locator("[name=instructions]").fill("Review the retained identity batch")
    return form


def handoff_form(manager, source, target):
    manager.page.goto(manager.case_url)
    manager.settle()
    panel = manager.page.locator("section.panel").filter(has=manager.page.get_by_role("heading", name=manager.text("تسليم المناوبة"), exact=True))
    panel.locator("summary").click()
    choose(manager, panel, "from_user", source)
    choose(manager, panel, "to_user", target)
    panel.locator("[name=reason]").fill("Transfer unfinished evidence review to the incoming shift")
    return panel


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", ["assignment-restricted-recovery", "assignment-eligible-recipient"])
def test_assignment_is_executable_before_it_is_created(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        manager.login("manager@socify.local")
        manager.case_url = j.case_url
        manager.page.goto(j.case_url)
        manager.settle()
        upload_logs(manager, "assigned-review.json", "Shift identity review event")
        person = j.page.evaluate("state.user.name")
        if scenario == "assignment-restricted-recovery":
            restrict_batch(manager, "assigned-review.json")
            form = assignment_form(manager, person)
            manager.click("button", "حفظ", form)
            assert assignments(manager) == [], "A task must not be created for an inaccessible batch"
            expect(form.locator("[role=alert]")).to_be_visible()
            manager.page.goto(j.case_url + "?tab=logs")
            manager.settle()
            restrict_batch(manager, "assigned-review.json", person)
            assign(manager, person)
            j.nav("مهامي")
            j.click("link", "فتح الدفعة")
            expect(j.page.get_by_role("cell", name="Shift identity review event", exact=True)).to_be_visible()
        else:
            manager.nav("الفريق")
            form = manager.page.locator("form").filter(has=manager.page.locator("[name=instructions]"))
            choose(manager, form, "case_id", "Authorized maintenance investigation")
            choose(manager, form, "job_id", "assigned-review.json")
            form.locator("input[name=assignee]").press("ArrowDown")
            members = manager.page.evaluate("() => api('/api/team')")["members"]
            for member in members:
                if member["role"] in {"auditor", "reviewer", "instructor"}:
                    expect(form.get_by_role("option").filter(has_text=member["name"])).to_have_count(0)
            choose(manager, form, "assignee", person)
            form.locator("[name=instructions]").fill("Review the retained identity batch")
            manager.click("button", "حفظ", form)
            j.nav("مهامي")
            j.click("button", "بدء التحليل")
            assert assignments(j)[0]["state"] == "in_progress"
        assert_accessible(manager.page)
        result["outcomes"] = [scenario, "assignment requires actual access and an operational recipient", "changes through visible controls"]


def role_permission(manager, permission, enabled):
    manager.nav("الفريق")
    panel = manager.page.locator('.team-role-policy[data-role="analyst"]')
    panel.locator("summary").click()
    panel.locator(f'input[value="{permission}"]').set_checked(enabled)
    manager.click("button", "حفظ حدود الدور", panel)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "handoff-open-assignment",
        "handoff-completed-history",
        "handoff-mixed-work",
        "handoff-restricted-recipient",
        "handoff-duplicate-open",
        "handoff-duplicate-completed",
        "handoff-concurrent-completion",
        "handoff-returning-shift",
        "deactivate-open-assignment",
        "deactivate-completed-history",
        "assignment-permission-restored",
        "assignment-stale-permission",
    ],
)
def test_shift_work_retains_ownership_access_and_completion_history(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        manager.login("manager@socify.local")
        manager.case_url = j.case_url
        manager.page.goto(j.case_url)
        manager.settle()
        upload_logs(manager, "assigned-review.json", "Shift identity review event")
        person = j.page.evaluate("state.user.name")
        manager_name = manager.page.evaluate("state.user.name")
        analyst_id = j.page.evaluate("state.user.id")
        manager_id = manager.page.evaluate("state.user.id")
        if scenario.startswith("assignment-"):
            if scenario == "assignment-stale-permission":
                # Prepare the form in one real manager tab, then change policy in another.
                form = assignment_form(manager, person)
                from tests.e2e.test_review_workflow import ReviewJourney

                other_page = manager.page.context.browser.new_page(locale="ar-SA" if language == "ar" else "en-US")
                other_page.on("pageerror", lambda error: result["browser_errors"].append(str(error)))
                other = ReviewJourney(other_page, manager.base, result["steps"])
                other.login("manager@socify.local")
                role_permission(other, "events.read", False)
                manager.click("button", "حفظ", form)
                assert assignments(manager) == []
                expect(form.locator("[role=alert]")).to_contain_text(manager.text("العضو لا يملك صلاحية تنفيذ مهام التحقيق"))
                other.page.close()
            else:
                role_permission(manager, "cases.read", False)
                form = manager.page.locator("form").filter(has=manager.page.locator("[name=instructions]"))
                form.locator("input[name=assignee]").press("ArrowDown")
                expect(form.get_by_role("option").filter(has_text=person)).to_have_count(0)
            role_permission(manager, "events.read" if scenario == "assignment-stale-permission" else "cases.read", True)
            assign(manager, person)
            j.nav("مهامي")
            j.click("button", "بدء التحليل")
            assert assignments(j)[0]["state"] == "in_progress"
        else:
            restricted = scenario == "handoff-restricted-recipient"
            if restricted:
                restrict_batch(manager, "assigned-review.json")
            assign(manager, manager_name if restricted else person)
            original = assignments(manager)[0]
            j.nav("مهامي")
            if scenario in {"handoff-completed-history", "handoff-mixed-work", "deactivate-completed-history"}:
                j.click("button", "إكمال المهمة")
                original = assignments(manager)[0]
                assert original["completed_at"]
            if scenario == "handoff-mixed-work":
                manager.page.goto(j.case_url)
                manager.settle()
                upload_logs(manager, "unfinished.json", "Unfinished identity correlation")
                assign(manager, person, filename="unfinished.json", instructions="Correlate unfinished identity events", expected=2)
            if scenario.startswith("handoff-duplicate-"):
                assign(manager, manager_name, expected=2)
                if scenario == "handoff-duplicate-completed":
                    manager.nav("مهامي")
                    manager.click("button", "إكمال المهمة")
            if scenario.startswith("deactivate-"):
                if scenario == "deactivate-open-assignment":
                    manager.page.set_viewport_size({"width": 390, "height": 1000})
                    result["interaction_viewport"] = 390
                manager.nav("الفريق")
                row = manager.page.locator("tr").filter(has=manager.page.get_by_role("cell", name=person, exact=True))
                manager.click("button", "إدارة العضو", row)
                dialog = manager.page.get_by_role("dialog")
                form = dialog.locator("form").filter(has=manager.page.locator("[name=handoff_to]"))
                choose(manager, form, "handoff_to", manager_name, f"{scenario}-{language}-choices.png")
                form.locator("[name=reason]").fill("End account access and preserve the completed analyst work")
                manager.click("button", "حفظ", form)
                expect(dialog).not_to_be_visible()
                j.page.reload()
                expect(j.page.locator("input[name=password]")).to_be_visible()
                assert j.page.request.get(j.base + "/api/auth/me").status == 401
            else:
                form = handoff_form(manager, manager_name if restricted else person, person if restricted else manager_name)
                if scenario == "handoff-concurrent-completion":
                    j.click("button", "إكمال المهمة")
                    original = assignments(manager)[0]
                before = assignments(manager)
                manager.click("button", "حفظ", form)
                if scenario.startswith("handoff-duplicate-") or scenario == "handoff-concurrent-completion":
                    expect(form.locator("[role=alert]")).to_be_visible()
                    assert assignments(manager) == before
                    if scenario == "handoff-concurrent-completion":
                        manager.page.once("dialog", lambda dialog: dialog.accept())
                        form = handoff_form(manager, person, manager_name)
                        manager.click("button", "حفظ", form)
                else:
                    expect(manager.page.get_by_role("cell", name=manager.text("المناوبة السابقة"), exact=True)).to_be_visible()
            after = assignments(manager)
            same = next(row for row in after if row["id"] == original["id"])
            assert same["task_id"] == original["task_id"]
            if scenario.startswith("handoff-duplicate-"):
                assert len(after) == 2
            elif original["task_status"] in {"completed", "reviewed"}:
                assert same["assignee"] == analyst_id and same["completed_at"] == original["completed_at"]
                task = next(task for task in manager.state()["tasks"] if task["id"] == original["task_id"])
                assert task["assignee"] == task["completed_by"] == analyst_id
                if scenario == "handoff-mixed-work":
                    unfinished = next(row for row in after if row["id"] != original["id"])
                    assert unfinished["assignee"] == manager_id and unfinished["state"] == "assigned"
                    manager.nav("مهامي")
                    expect(manager.page.get_by_role("cell", name="Review the retained identity batch", exact=True)).to_have_count(0)
                    manager.click("button", "إكمال المهمة")
            elif restricted:
                assert same["assignee"] == analyst_id
                j.click("button", "تحديث القائمة")
                j.click("link", "فتح الدفعة")
                expect(j.page.get_by_role("cell", name="Shift identity review event", exact=True)).to_be_visible()
                j.nav("مهامي")
                j.click("button", "إكمال المهمة")
            elif scenario == "handoff-returning-shift":
                assert same["assignee"] == manager_id
                form = handoff_form(manager, manager_name, person)
                manager.click("button", "حفظ", form)
                assert assignments(manager)[0]["assignee"] == analyst_id
                j.click("button", "تحديث القائمة")
                j.click("button", "بدء التحليل")
            else:
                assert same["assignee"] == manager_id
                if scenario == "handoff-open-assignment":
                    j.click("button", "بدء التحليل")
                    expect(j.page.locator(".assignment-queue [role=alert]")).to_be_visible()
                    assert assignments(manager)[0]["state"] == "assigned"
                    j.click("button", "تحديث القائمة")
                    expect(j.page.get_by_role("cell", name="Review the retained identity batch", exact=True)).to_have_count(0)
                manager.nav("مهامي")
                manager.click("button", "إكمال المهمة")
                assert assignments(manager)[0]["state"] == "completed"
        assert_accessible(manager.page)
        for width in (390, 1440):
            manager.page.set_viewport_size({"width": width, "height": 1000})
            assert manager.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            manager.page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-{width}.png"), full_page=True)
        result["outcomes"] = [scenario, "assignment and linked task independently verified", "no writes through API or database"]
