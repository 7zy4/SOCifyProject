"""Find and finish system work in the selected interface language."""

import pytest
from playwright.sync_api import expect

from tests.e2e.test_case_task_backlog_journeys import search_tasks
from tests.e2e.test_followup_handoff_journeys import evidence_images
from tests.e2e.test_investigation_link_journeys import note_dialog, records
from tests.e2e.test_review_workflow import review_session


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "task-language-search",
        "task-language-switch-complete",
        "task-language-reference",
        "task-language-performance",
        "task-language-authored-title",
        "task-language-reload-search",
    ],
)
def test_new_analyst_finds_and_finishes_localized_task(app, language, scenario):
    with review_session(app, language, scenario) as (j, _, result):
        active = language
        if scenario == "task-language-switch-complete":
            j.page.locator("[data-language-toggle]").click()
            j.settle()
            active = "en" if language == "ar" else "ar"
        title = "التحقق من الدليل الأساسي" if active == "ar" else "Validate primary evidence"
        if scenario == "task-language-authored-title":
            authored = j.page.evaluate("id=>api(`/api/incidents/${id}/tasks`,{method:'POST',body:{title:'Validate primary evidence'}})", j.case_id)
            result["setup_only_tasks"] = 1
            result["setup_method"] = "Existing analyst-authored task prepared through the authenticated API; not an extra journey"
            j.page.reload()
            j.settle()
            authored_row = j.page.locator(f"#case-task-{authored['id']}")
            expect(authored_row).to_contain_text("Validate primary evidence")
            j.page.locator("[data-language-toggle]").click()
            j.settle()
            expect(authored_row).to_contain_text("Validate primary evidence")
            j.click("button", "إكمال المهمة", authored_row)
            result["outcomes"] = ["Analyst-authored title unchanged after language switch; the intended task completed"]
            evidence_images(j, result)
            return
        if scenario == "task-language-performance":
            j.nav("الأداء")
            j.page.get_by_role("link", name=title, exact=True).click()
            j.settle()
        if scenario == "task-language-reference":
            j.click("link", "التحقيق والخط الزمني")
            dialog = note_dialog(j)
            control = dialog.locator("input[name=task_id]")
            control.fill(title)
            control.press("ArrowDown")
            dialog.get_by_role("option").filter(has_text=title).first.click()
            j.click("button", "حفظ", dialog)
            linked = records(j, "war_room")[0]["payload"]["task_id"]
            task = next(task for task in j.state()["tasks"] if task["system_key"] == "validate_evidence")
            assert linked == task["id"]
            j.click("link", "فتح المهمة", j.page.locator(".record-card"))
        row = j.page.locator(".case-task-queue tr").filter(has=j.page.get_by_role("cell", name=title, exact=True))
        expect(row).to_be_visible()
        search_tasks(j, title)
        if scenario == "task-language-reload-search":
            j.page.reload()
            j.settle()
            expect(j.page.locator("input[name=case_task_q]")).to_have_value(title)
        expect(row).to_be_visible()
        j.click("button", "إكمال المهمة", row)
        expect(row.get_by_role("cell", name=j.page.evaluate("autopsyLabel('completed')"), exact=True)).to_be_visible()
        result["outcomes"] = ["Located the system task in the selected language and completed it through the interface"]
        result["final_language"] = active
        evidence_images(j, result)
