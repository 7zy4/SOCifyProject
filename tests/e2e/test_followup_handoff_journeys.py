"""Keep corrective work and private investigation decisions usable across shifts."""

import pytest
from playwright.sync_api import expect

from tests.e2e.test_assignment_handoff_journeys import choose as choose_person
from tests.e2e.test_assignment_handoff_journeys import handoff_form, role_permission
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_investigation_link_journeys import choose, corrective_dialog, note_dialog, records, root_cause
from tests.e2e.test_review_workflow import ARTIFACTS, review_session


def manager_case(j, manager):
    manager.login("manager@socify.local")
    manager.case_url = j.case_url
    manager.page.goto(j.case_url)
    manager.settle()


def card(j, title):
    return j.page.locator(".record-card").filter(has=j.page.get_by_role("heading", name=title, exact=True))


def edit(j, title):
    j.click("button", "تعديل", card(j, title))
    return j.page.get_by_role("dialog")


def set_status(j, dialog, status, validation=""):
    dialog.locator("input[name=status]").fill(j.page.evaluate("value=>autopsyLabel(value)", status))
    dialog.locator("textarea[name=validation]").fill(validation)


def evidence_images(j, result):
    assert_accessible(j.page)
    for width in (390, 1440):
        j.page.set_viewport_size({"width": width, "height": 1000})
        assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        j.page.evaluate("scrollTo({top:0,behavior:'instant'})")
        j.page.screenshot(path=str(ARTIFACTS / f"{result['scenario']}-{result['language']}-{width}.png"), full_page=True)
    if j.page.locator(".record-card").count():
        j.page.locator(".record-card").first.screenshot(path=str(ARTIFACTS / f"{result['scenario']}-{result['language']}-target.png"))


def deactivate(manager, name, target):
    manager.nav("الفريق")
    row = manager.page.locator("tr").filter(has=manager.page.get_by_role("cell", name=name, exact=True))
    manager.click("button", "إدارة العضو", row)
    dialog = manager.page.get_by_role("dialog")
    form = dialog.locator("form").filter(has=manager.page.locator("[name=handoff_to]"))
    choose_person(manager, form, "handoff_to", target)
    form.locator("[name=reason]").fill("End outgoing access and retain the completed corrective review history")
    manager.click("button", "حفظ", form)
    expect(dialog).not_to_be_visible()


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "corrective-handoff-open",
        "corrective-handoff-completed-review",
        "corrective-handoff-validated-history",
        "corrective-deactivate-open",
        "corrective-deactivate-validated-history",
        "corrective-stale-handoff-edit",
        "corrective-validation-required",
        "corrective-permission-recovery",
        "corrective-concurrent-review",
    ],
)
def test_corrective_owner_can_finish_the_work_without_rewriting_history(app, language, scenario):
    title = "Review the identity approval procedure"
    with review_session(app, language, scenario) as (j, manager, result):
        root_cause(j)
        dialog = corrective_dialog(j)
        choose(j, dialog, "root_cause_id", "Retained identity policy gap")
        choose(j, dialog, "why_id", "Why was the identity scope missed?")
        status = "validated" if scenario.endswith("validated-history") else "completed" if scenario.endswith("completed-review") else "open"
        if status != "open":
            set_status(j, dialog, status, "Independent review retained before the shift ended")
        j.click("button", "حفظ", dialog)
        original = records(j, "corrective")[0]
        person = j.page.evaluate("state.user.name")
        manager_case(j, manager)
        manager_name = manager.page.evaluate("state.user.name")
        manager_id = manager.page.evaluate("state.user.id")
        owner_id = j.page.evaluate("state.user.id")

        if scenario == "corrective-validation-required":
            dialog = edit(j, title)
            set_status(j, dialog, "validated")
            j.click("button", "حفظ", dialog)
            expect(dialog.locator("form > [role=alert]")).to_be_visible()
            assert records(j, "corrective")[0]["payload"]["status"] == "open"
            dialog.locator("textarea[name=validation]").fill("Retained approval independently checked against the completed remediation")
            j.click("button", "حفظ", dialog)
            assert records(j, "corrective")[0]["payload"]["status"] == "validated"
            subject = j
        elif scenario == "corrective-permission-recovery":
            dialog = edit(j, title)
            set_status(j, dialog, "in_progress", "Draft verification retained during access restoration")
            role_permission(manager, "cases.update", False)
            j.click("button", "حفظ", dialog)
            expect(dialog.locator("form > [role=alert]")).to_be_visible()
            expect(dialog.locator("textarea[name=validation]")).to_have_value("Draft verification retained during access restoration")
            assert records(j, "corrective")[0]["payload"]["status"] == "open"
            role_permission(manager, "cases.update", True)
            j.click("button", "حفظ", dialog)
            assert records(j, "corrective")[0]["payload"]["status"] == "in_progress"
            subject = j
        elif scenario == "corrective-concurrent-review":
            dialog = edit(j, title)
            set_status(j, dialog, "in_progress", "Outgoing verification must not replace the independent finding")
            manager.click("link", "الاستجابة والتصعيد")
            other = edit(manager, title)
            set_status(manager, other, "completed", "Independent reviewer retained the corrected remediation")
            manager.click("button", "حفظ", other)
            j.click("button", "حفظ", dialog)
            expect(dialog.locator("form > [role=alert]")).to_be_visible()
            expect(dialog.locator("textarea[name=validation]")).to_have_value("Outgoing verification must not replace the independent finding")
            assert records(manager, "corrective")[0]["payload"]["status"] == "completed"
            j.page.once("dialog", lambda prompt: prompt.accept())
            j.page.reload()
            j.settle()
            dialog = edit(j, title)
            expect(dialog.locator("textarea[name=validation]")).to_have_value("Independent reviewer retained the corrected remediation")
            set_status(j, dialog, "validated", "Reconciled the independent finding and verified the corrective result")
            j.click("button", "حفظ", dialog)
            subject = j
        else:
            stale = scenario == "corrective-stale-handoff-edit"
            if stale:
                dialog = edit(j, title)
                set_status(j, dialog, "in_progress", "Unsubmitted outgoing verification")
            if scenario.startswith("corrective-deactivate-"):
                deactivate(manager, person, manager_name)
                j.page.reload()
                expect(j.page.locator("input[name=password]")).to_be_visible()
                assert j.page.request.get(j.base + "/api/auth/me").status == 401
                manager.page.goto(j.case_url)
                manager.settle()
            else:
                form = handoff_form(manager, person, manager_name)
                manager.click("button", "حفظ", form)
            transferred = records(manager, "corrective")[0]
            expected_owner = owner_id if status == "validated" else manager_id
            assert transferred["payload"]["owner_id"] == expected_owner
            assert transferred["payload"]["root_cause_id"] == original["payload"]["root_cause_id"]
            assert transferred["payload"]["why_id"] == original["payload"]["why_id"]
            if status == "validated":
                assert transferred == original
            if stale:
                j.click("button", "حفظ", dialog)
                expect(dialog.locator("form > [role=alert]")).to_be_visible()
                expect(dialog.locator("textarea[name=validation]")).to_have_value("Unsubmitted outgoing verification")
                assert records(manager, "corrective")[0] == transferred
            manager.click("link", "الاستجابة والتصعيد")
            expect(card(manager, title)).to_contain_text(person if status == "validated" else manager_name)
            manager.click("button", "عرض فرع السبب", card(manager, title))
            expect(manager.page.get_by_role("dialog")).to_contain_text("Why was the identity scope missed?")
            manager.page.keyboard.press("Escape")
            if status != "validated":
                dialog = edit(manager, title)
                set_status(manager, dialog, "validated", "Incoming shift independently verified the retained corrective work")
                manager.click("button", "حفظ", dialog)
                assert records(manager, "corrective")[0]["payload"]["status"] == "validated"
            subject = manager
        result["outcomes"] = [
            scenario,
            "ownership, retained references and history verified after actual UI actions",
            "no setup writes through API or database",
        ]
        evidence_images(subject, result)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", ["private-decision-published", "shared-decision-withdrawn-during-edit", "shared-decision-restored-after-withdrawal"])
def test_incoming_reader_respects_private_decisions_and_can_recover_after_publication(app, language, scenario):
    title = "Identity evidence review decision"
    with review_session(app, language, scenario) as (j, manager, result):
        manager_case(j, manager)
        manager.click("link", "التحقيق والخط الزمني")
        dialog = note_dialog(manager)
        choose(manager, dialog, "task_id", "Validate primary evidence")
        visibility = "private" if scenario == "private-decision-published" else "team"
        dialog.locator("input[name=visibility]").fill(manager.page.evaluate("v=>autopsyLabel(v)", visibility))
        manager.click("button", "حفظ", dialog)
        j.click("link", "التحقيق والخط الزمني")
        if visibility == "private":
            expect(card(j, title)).to_have_count(0)
            assert records(j, "war_room") == []
        else:
            dialog = edit(j, title)
            dialog.locator("textarea[name=body]").fill("Incoming analyst review awaiting authorized publication")
        other = edit(manager, title)
        other.locator("input[name=visibility]").fill(manager.page.evaluate("v=>autopsyLabel(v)", "team" if visibility == "private" else "private"))
        manager.click("button", "حفظ", other)
        if visibility == "team":
            j.click("button", "حفظ", dialog)
            expect(dialog.locator("form > [role=alert]")).to_be_visible()
            assert records(j, "war_room") == []
            assert records(manager, "war_room")[0]["payload"]["body"] != "Incoming analyst review awaiting authorized publication"
            if scenario.endswith("restored-after-withdrawal"):
                other = edit(manager, title)
                other.locator("input[name=visibility]").fill(manager.page.evaluate("autopsyLabel('team')"))
                manager.click("button", "حفظ", other)
            j.page.once("dialog", lambda prompt: prompt.accept())
        j.page.reload()
        j.settle()
        if scenario == "shared-decision-withdrawn-during-edit":
            expect(card(j, title)).to_have_count(0)
        else:
            expect(card(j, title)).to_be_visible()
            if scenario.endswith("restored-after-withdrawal"):
                dialog = edit(j, title)
                dialog.locator("textarea[name=body]").fill("Incoming analyst reconciled the newly shared decision")
                j.click("button", "حفظ", dialog)
            destination = card(j, title).get_by_role("link", name=j.text("فتح المهمة"), exact=True).get_attribute("href").split("#", 1)[1]
            j.click("link", "فتح المهمة", card(j, title))
            expect(j.page.locator(f"#{destination}")).to_contain_text(j.system_task_title("Validate primary evidence"))
            expect(j.page.locator(f"#{destination}")).to_be_focused()
        result["outcomes"] = [scenario, "private decision excluded from unauthorized results and stale edits rejected", "reference usable after publication"]
        evidence_images(j, result)
