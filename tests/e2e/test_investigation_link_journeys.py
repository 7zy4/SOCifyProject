"""Keep investigation decisions linked to the retained work they describe."""

import json

import pytest
from playwright.sync_api import expect

from tests.e2e.test_assignment_handoff_journeys import role_permission
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_case_continuity_journeys import record_dialog
from tests.e2e.test_case_task_backlog_journeys import historical_backlog
from tests.e2e.test_review_workflow import ARTIFACTS, review_session


def records(j, kind):
    return j.page.evaluate("({id,kind})=>api(`/api/cases/${id}/records?kind=${kind}&limit=100`)", {"id": j.case_id, "kind": kind})["items"]


def note_dialog(j):
    dialog = record_dialog(j, "war_room")
    dialog.locator("input[name=title]").fill("Identity evidence review decision")
    dialog.locator("textarea[name=body]").fill("Retain the original review task and its evidence assessment for the next shift.")
    return dialog


def choose(j, dialog, name, text):
    control = dialog.locator(f"input[name={name}]")
    control.fill(text)
    control.press("ArrowDown")
    dialog.get_by_role("option").filter(has_text=text).first.click()


def capture(j, result):
    assert_accessible(j.page)
    for width in (390, 1440):
        j.page.set_viewport_size({"width": width, "height": 1000})
        assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        j.page.mouse.move(0, 0)
        j.page.evaluate("scrollTo(0,0)")
        j.page.screenshot(path=str(ARTIFACTS / f"{result['scenario']}-{result['language']}-{width}.png"), full_page=True)
    corrective = j.page.locator(".record-card").filter(has=j.page.get_by_role("heading", name="Review the identity approval procedure", exact=True))
    if corrective.count():
        expect(corrective).to_contain_text(j.page.evaluate("state.user.name"))
        corrective.screenshot(path=str(ARTIFACTS / f"{result['scenario']}-{result['language']}-target.png"))


def edit_note(j):
    card = j.page.locator(".record-card").filter(has=j.page.get_by_role("heading", name="Identity evidence review decision", exact=True))
    j.click("button", "تعديل", card)
    return j.page.get_by_role("dialog")


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "investigation-reference-empty-recovery",
        "investigation-reference-invalid-value",
        "investigation-reference-network-retry",
        "investigation-reference-edit-retry",
        "investigation-reference-pagination",
        "investigation-reference-duplicate-title",
        "investigation-reference-foreign-case",
        "investigation-reference-unlink",
        "investigation-reference-permission-change",
        "investigation-reference-keyboard",
        "investigation-reference-late-response",
    ],
)
def test_investigator_can_recover_and_keep_the_intended_reference(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        old_task = next(task for task in j.state()["tasks"] if task["title"] == "Validate primary evidence")
        if scenario == "investigation-reference-pagination":
            historical_backlog(j, result, count=28)
        if scenario in {"investigation-reference-foreign-case", "investigation-reference-permission-change"}:
            manager.login("manager@socify.local")
            manager.case_url = j.case_url
        if scenario == "investigation-reference-foreign-case":
            manager.create_case()
            manager.page.evaluate("id=>api(`/api/incidents/${id}/tasks`,{method:'POST',body:{title:'Private finance reference'}})", manager.case_id)
            result["setup_only_tasks"] = 1
        duplicates = None
        if scenario == "investigation-reference-duplicate-title":
            duplicates = j.page.evaluate(
                "async id=>[await api(`/api/incidents/${id}/tasks`,{method:'POST',body:{title:'Repeated review title'}}),await api(`/api/incidents/${id}/tasks`,{method:'POST',body:{title:'Repeated review title'}})]",
                j.case_id,
            )
            result["setup_only_tasks"] = 2
        j.click("link", "التحقيق والخط الزمني")
        dialog = note_dialog(j)
        if scenario in {"investigation-reference-edit-retry", "investigation-reference-unlink"}:
            choose(j, dialog, "task_id", "Validate primary evidence")
            j.click("button", "حفظ", dialog)
            if scenario.endswith("edit-retry"):
                j.page.route("**/api/cases/*/tasks?focus=*", lambda route: route.abort(), times=1)
            dialog = edit_note(j)
            if scenario.endswith("edit-retry"):
                expect(dialog.get_by_role("alert")).to_be_visible()
                assert records(j, "war_room")[0]["payload"]["task_id"] == old_task["id"]
                j.click("button", "إعادة المحاولة", dialog)
                dialog = j.page.get_by_role("dialog")
                assert "Validate primary evidence" in dialog.locator("input[name=task_id]").input_value()
            else:
                dialog.locator("input[name=task_id]").fill("")
            dialog.locator("textarea[name=body]").fill("Updated review decision retained for the next shift.")
        elif scenario.endswith("pagination"):
            field = dialog.locator("input[name=task_id]").locator("..")
            field.get_by_role("button", name=j.text("عرض الخيارات"), exact=True).click()
            j.click("button", "عرض المزيد", field)
            field.get_by_role("option").filter(has_text="Validate primary evidence").click()
        elif scenario.endswith("duplicate-title"):
            control = dialog.locator("input[name=task_id]")
            control.fill("Repeated review title")
            control.press("ArrowDown")
            dialog.get_by_role("option", name=f"Repeated review title · {duplicates[0]['id']}", exact=True).click()
        elif scenario.endswith("keyboard"):
            control = dialog.locator("input[name=task_id]")
            control.fill("Validate")
            control.press("Tab")
            j.page.keyboard.press("Tab")
            j.page.wait_for_timeout(350)
            expect(control).to_have_attribute("aria-expanded", "false")
            control.fill("Validate primary evidence")
            control.press("ArrowDown")
            option = dialog.get_by_role("option").filter(has_text="Validate primary evidence")
            expect(option).to_be_focused()
            j.page.keyboard.press("Enter")
            control.press("ArrowDown")
            expect(dialog.get_by_role("option").first).to_be_focused()
            j.page.keyboard.press("Escape")
            expect(control).to_be_focused()
            expect(control).to_have_attribute("aria-expanded", "false")
        elif scenario.endswith("late-response"):
            held = []

            def delay_first(route):
                if "Validate" in route.request.url and not held:
                    held.append((route, route.fetch()))
                else:
                    route.continue_()

            j.page.route("**/api/cases/*/tasks?*", delay_first)
            control = dialog.locator("input[name=task_id]")
            control.fill("Validate primary evidence")
            with j.page.expect_request(lambda request: "/tasks?" in request.url and "Validate" in request.url):
                control.press("ArrowDown")
            control.fill("Document response decision")
            control.press("ArrowDown")
            expect(dialog.get_by_role("option").filter(has_text="Document response decision")).to_be_visible()
            held[0][0].fulfill(response=held[0][1])
            j.settle()
            expect(dialog.get_by_role("option").filter(has_text="Validate primary evidence")).to_have_count(0)
            dialog.get_by_role("option").filter(has_text="Document response decision").click()
        else:
            if scenario.endswith("network-retry"):
                j.page.route("**/api/cases/*/tasks?*", lambda route: route.abort(), times=1)
                control = dialog.locator("input[name=task_id]")
                control.fill("Validate primary evidence")
                control.press("ArrowDown")
                field = control.locator("..")
                expect(field.get_by_role("alert")).to_be_visible()
                j.click("button", "إعادة المحاولة", field)
                dialog.get_by_role("option").filter(has_text="Validate primary evidence").click()
            else:
                if scenario.endswith("empty-recovery") or scenario.endswith("foreign-case"):
                    control = dialog.locator("input[name=task_id]")
                    control.fill("Private finance reference" if scenario.endswith("foreign-case") else "No retained task with this title")
                    control.press("ArrowDown")
                    expect(control.locator("..").get_by_role("status")).to_have_text(j.text("لا نتائج مطابقة"))
                    expect(dialog.get_by_role("option")).to_have_count(0)
                elif scenario.endswith("invalid-value"):
                    dialog.locator("input[name=task_id]").fill("Unrecognized task reference")
                    j.click("button", "حفظ", dialog)
                    expect(dialog.locator("form > [role=alert]")).to_be_visible()
                    expect(dialog.locator("textarea[name=body]")).to_have_value(
                        "Retain the original review task and its evidence assessment for the next shift."
                    )
                    assert records(j, "war_room") == []
                choose(j, dialog, "task_id", "Validate primary evidence")
            if scenario.endswith("permission-change"):
                role_permission(manager, "cases.update", False)
                j.click("button", "حفظ", dialog)
                expect(dialog.locator("form > [role=alert]")).to_be_visible()
                assert records(j, "war_room") == []
                role_permission(manager, "cases.update", True)
        j.click("button", "حفظ", dialog)
        expect(dialog).not_to_be_visible()
        saved = records(j, "war_room")[0]["payload"]
        expected = None if scenario.endswith("unlink") else duplicates[0]["id"] if duplicates else old_task["id"]
        if scenario.endswith("late-response"):
            expected = next(task for task in j.state()["tasks"] if task["title"] == "Document response decision")["id"]
        assert saved.get("task_id") == expected
        result["outcomes"] = [scenario, "decision and intended reference saved through the interface", "setup and verification calls excluded"]
        capture(j, result)


def root_cause(j, conclusion="Retained identity policy gap", question="Why was the identity scope missed?"):
    j.click("link", "التحقيق والخط الزمني")
    dialog = record_dialog(j, "root_cause")
    dialog.locator("input[name=category]").fill(j.text("غير معروف"))
    dialog.locator("textarea[name=conclusion]").fill(conclusion)
    j.click("button", "إضافة سؤال لماذا", dialog)
    row = dialog.locator("fieldset.why-step")
    row.get_by_label(j.text("السؤال"), exact=True).fill(question)
    row.get_by_label(j.text("الإجابة"), exact=True).fill("The retained evidence requires further review before this cause is confirmed.")
    j.click("button", "حفظ", dialog)
    return records(j, "root_cause")[0]


def corrective_dialog(j):
    j.click("link", "الاستجابة والتصعيد")
    dialog = record_dialog(j, "corrective")
    dialog.locator("input[name=title]").fill("Review the identity approval procedure")
    choose(j, dialog, "owner_id", j.page.evaluate("state.user.name"))
    dialog.locator("input[name=due_at]").fill("2026-11-04T09:00")
    status = dialog.locator("input[name=status]")
    status.press("ArrowDown")
    status.locator("..").get_by_role("option").first.click()
    return dialog


def root_backlog(j, result):
    result["setup_only_records"] = j.page.evaluate(
        """async id => {
            for(let n=0;n<103;n++) await api(`/api/cases/${id}/records/root_cause`,{method:'POST',body:{category:'unknown',conclusion:`Retained unrelated review ${n+1}`}});
            return 103;
        }""",
        j.case_id,
    )


def edit_corrective(j):
    card = j.page.locator(".record-card").filter(has=j.page.get_by_role("heading", name="Review the identity approval procedure", exact=True))
    j.click("button", "تعديل", card)
    return j.page.get_by_role("dialog")


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", ["corrective-invalid-branch-recovery", "corrective-legacy-missing-branch"])
def test_corrective_reference_can_recover_from_an_invalid_branch(app, database, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        cause = root_cause(j)
        second = root_cause(j, "Separate endpoint policy question", "Why was endpoint approval missing?")
        dialog = corrective_dialog(j)
        choose(j, dialog, "root_cause_id", "Retained identity policy gap")
        choose(j, dialog, "why_id", "Why was the identity scope missed?")
        j.click("button", "حفظ", dialog)
        if scenario.endswith("missing-branch"):
            # Old records may predate branch deletion protection. This is a
            # historical starting state, not a UI action performed by the user.
            database.execute("UPDATE autopsy_records SET payload=? WHERE id=?", (json.dumps({**cause["payload"], "whys": []}), cause["id"]))
            result["setup_only_state"] = "Historical missing branch; direct setup is excluded from journey counts"
            j.page.reload()
            j.settle()
        dialog = edit_corrective(j)
        if scenario.endswith("missing-branch"):
            expect(dialog.locator("input[name=why_id]")).to_have_value(j.text("فرع السبب المرتبط غير متاح"))
            j.click("button", "حفظ", dialog)
            expect(dialog.locator("form > [role=alert]")).to_be_visible()
            assert records(j, "corrective")[0]["payload"]["why_id"] == cause["payload"]["whys"][0]["id"]
            dialog.locator("input[name=why_id]").fill("")
        else:
            dialog.locator("input[name=why_id]").fill("Unrecognized approval branch")
            choose(j, dialog, "root_cause_id", "Separate endpoint policy question")
            expect(dialog.locator("input[name=why_id]")).to_have_value("")
            choose(j, dialog, "why_id", "Why was endpoint approval missing?")
        j.click("button", "حفظ", dialog)
        saved = records(j, "corrective")[0]["payload"]
        if scenario.endswith("missing-branch"):
            assert saved["root_cause_id"] == cause["id"] and "why_id" not in saved
        else:
            assert saved["root_cause_id"] == second["id"] and saved["why_id"] == second["payload"]["whys"][0]["id"]
        result["outcomes"] = ["invalid branch recovered explicitly without a silent relationship change"]
        capture(j, result)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "corrective-retained-cause-edit",
        "corrective-reselect-same-cause",
        "corrective-change-cause",
        "corrective-validation-required",
        "corrective-closed-case-followup",
        "corrective-linked-branch-removal",
    ],
)
def test_corrective_followup_preserves_the_investigation_relationship(app, database, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        cause = root_cause(j)
        second = root_cause(j, "Separate endpoint policy question", "Why was endpoint approval missing?") if scenario.endswith("change-cause") else None
        dialog = corrective_dialog(j)
        choose(j, dialog, "root_cause_id", "Retained identity policy gap")
        choose(j, dialog, "why_id", "Why was the identity scope missed?")
        j.click("button", "حفظ", dialog)
        if scenario.endswith("retained-cause-edit"):
            root_backlog(j, result)
        elif scenario.endswith("closed-case-followup"):
            # A previously closed investigation is the initial state, not a claim
            # of completing the native report and closure workflow in this test.
            database.execute("UPDATE incident_cases SET status='closed', version=version+1 WHERE id=?", (j.case_id,))
            result["setup_only_state"] = "Previously closed case; closure itself is excluded from this journey"
        j.page.reload()
        j.settle()
        if scenario.endswith("linked-branch-removal"):
            j.click("link", "التحقيق والخط الزمني")
            card = j.page.locator(".record-card").filter(has_text="Retained identity policy gap")
            j.click("button", "تعديل", card)
            dialog = j.page.get_by_role("dialog")
            j.click("button", "حذف الخطوة", dialog)
            j.click("button", "حفظ", dialog)
            expect(dialog.locator("form > [role=alert]")).to_be_visible()
            assert len(records(j, "root_cause")[0]["payload"]["whys"]) == 1
            j.page.once("dialog", lambda confirm: confirm.accept())
            j.click("button", "إغلاق", dialog)
            j.click("link", "الاستجابة والتصعيد")
            dialog = edit_corrective(j)
            dialog.locator("input[name=why_id]").fill("")
            j.click("button", "حفظ", dialog)
            j.click("link", "التحقيق والخط الزمني")
            j.click("button", "تعديل", j.page.locator(".record-card").filter(has_text="Retained identity policy gap"))
            dialog = j.page.get_by_role("dialog")
            j.click("button", "حذف الخطوة", dialog)
            j.click("button", "حفظ", dialog)
            assert records(j, "root_cause")[0]["payload"]["whys"] == []
            assert "why_id" not in records(j, "corrective")[0]["payload"]
        else:
            dialog = edit_corrective(j)
            if scenario.endswith("reselect-same-cause"):
                choose(j, dialog, "root_cause_id", "Retained identity policy gap")
            elif scenario.endswith("change-cause"):
                choose(j, dialog, "root_cause_id", "Separate endpoint policy question")
                expect(dialog.locator("input[name=why_id]")).to_have_value("")
                choose(j, dialog, "why_id", "Why was endpoint approval missing?")
            elif scenario.endswith("validation-required") or scenario.endswith("closed-case-followup"):
                dialog.locator("input[name=status]").fill(j.page.evaluate("autopsyLabel('validated')"))
                j.click("button", "حفظ", dialog)
                expect(dialog.locator("form > [role=alert]")).to_be_visible()
                assert records(j, "corrective")[0]["payload"]["status"] == "open"
            dialog.locator("textarea[name=validation]").fill("The retained approval record and reviewed access decision confirm the follow-up was performed.")
            j.click("button", "حفظ", dialog)
            expect(dialog).not_to_be_visible()
            saved = records(j, "corrective")[0]["payload"]
            selected = second or cause
            assert saved["root_cause_id"] == selected["id"] and saved["why_id"] == selected["payload"]["whys"][0]["id"]
            if scenario.endswith("closed-case-followup"):
                assert j.state()["status"] == "closed" and saved["status"] == "validated"
                j.click("link", "التحقيق والخط الزمني")
                expect(j.page.locator(".record-card").get_by_role("button", name=j.text("تعديل"), exact=True)).to_have_count(0)
                j.click("link", "الاستجابة والتصعيد")
        result["outcomes"] = [scenario, "retained relationships and case scope verified after the visible follow-up"]
        capture(j, result)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", ["corrective-old-cause-selection", "corrective-cause-branch-scope"])
def test_corrective_action_selects_the_intended_retained_cause(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        cause = root_cause(j)
        if scenario == "corrective-old-cause-selection":
            root_backlog(j, result)
        else:
            root_cause(j, "Separate endpoint policy question", "Why was endpoint approval missing?")
        dialog = corrective_dialog(j)
        choose(j, dialog, "root_cause_id", "Retained identity policy gap")
        branch = dialog.locator("input[name=why_id]")
        branch.press("ArrowDown")
        expect(dialog.get_by_role("option").filter(has_text="Why was endpoint approval missing?")).to_have_count(0)
        dialog.get_by_role("option").filter(has_text="Why was the identity scope missed?").click()
        j.click("button", "حفظ", dialog)
        saved = records(j, "corrective")[0]["payload"]
        assert saved["root_cause_id"] == cause["id"] and saved["why_id"] == cause["payload"]["whys"][0]["id"]
        j.click("button", "عرض السبب الجذري")
        expect(j.page.get_by_role("dialog")).to_contain_text("Retained identity policy gap")
        j.click("button", "إغلاق", j.page.get_by_role("dialog"))
        j.click("button", "عرض فرع السبب")
        expect(j.page.get_by_role("dialog")).to_contain_text("Why was the identity scope missed?")
        expect(j.page.get_by_role("dialog")).to_contain_text("The retained evidence requires further review")
        j.page.get_by_role("dialog").screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-branch.png"))
        j.click("button", "إغلاق", j.page.get_by_role("dialog"))
        result["outcomes"] = ["corrective action linked to the chosen retained cause and its own branch"]
        capture(j, result)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", ["investigation-old-task-selection", "investigation-old-task-edit"])
def test_investigation_note_retains_an_old_task_link(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        old_task = next(task for task in j.state()["tasks"] if task["title"] == "Validate primary evidence")
        if scenario.endswith("edit"):
            j.click("link", "التحقيق والخط الزمني")
            dialog = note_dialog(j)
            choose(j, dialog, "task_id", "Validate primary evidence")
            j.click("button", "حفظ", dialog)
        historical_backlog(j, result)
        j.page.reload()
        j.settle()
        if scenario.endswith("edit"):
            card = j.page.locator(".record-card").filter(has=j.page.get_by_role("heading", name="Identity evidence review decision", exact=True))
            j.click("button", "تعديل", card)
            dialog = j.page.get_by_role("dialog")
            dialog.locator("textarea[name=body]").fill("Original review remains assigned; retain this decision for the next shift.")
            j.click("button", "حفظ", dialog)
        else:
            j.click("link", "التحقيق والخط الزمني")
            dialog = note_dialog(j)
            choose(j, dialog, "task_id", "Validate primary evidence")
            j.click("button", "حفظ", dialog)
        saved = records(j, "war_room")[0]
        result["expected_task_id"] = old_task["id"]
        result["saved_task_id"] = saved["payload"].get("task_id")
        assert result["saved_task_id"] == result["expected_task_id"]
        j.click("link", "فتح المهمة")
        expect(j.page.locator(f"#case-task-{old_task['id']}")).to_contain_text("Validate primary evidence")
        j.click("link", "التحقيق والخط الزمني")
        capture(j, result)
        result["outcomes"] = ["old retained task selected or preserved through visible note controls", "setup records excluded from user counts"]
