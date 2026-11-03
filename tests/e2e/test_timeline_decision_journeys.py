"""Find retained events, share investigation context, and report evidenced decisions."""

import json

import pytest
from playwright.sync_api import expect

from tests.e2e.test_assignment_handoff_journeys import role_permission
from tests.e2e.test_batch_boundary_journeys import restrict_batch
from tests.e2e.test_case_continuity_journeys import panel
from tests.e2e.test_followup_handoff_journeys import evidence_images, manager_case
from tests.e2e.test_investigation_link_journeys import choose
from tests.e2e.test_report_recovery_journeys import report, report_path
from tests.e2e.test_review_workflow import ARTIFACTS, review_session


def upload_events(j, count=2):
    events = [
        {"title": f"Retained gateway event {index + 1:02d}", "timestamp": f"2026-11-02T09:{index:02d}:00Z", "hostname": "RETAINED-GW", "severity": "medium"}
        for index in range(count)
    ]
    j.click("link", "السجلات والأدلة")
    j.page.locator("input[name=file]").set_input_files({"name": "retained-gateway.json", "mimeType": "application/json", "buffer": json.dumps(events).encode()})
    j.click("button", "استيراد وفحص فوري")
    expect(j.page.get_by_role("cell", name="Retained gateway event 01", exact=True)).to_be_visible()


def timeline(j):
    return panel(j, "الخط الزمني الموحد للسجلات")


def open_timeline(j):
    j.click("link", "التحقيق والخط الزمني")
    timeline(j).locator("select[name=timeline_scope]").select_option("logs")
    j.click("button", "تطبيق الفلاتر", timeline(j))


def search_events(j, query):
    timeline(j).locator("input[name=timeline_q]").fill(query)
    j.click("button", "تطبيق الفلاتر", timeline(j))


def event_row(j, title="Retained gateway event 01"):
    return timeline(j).locator("li").filter(has=j.page.get_by_role("heading", name=title, exact=True))


def bookmark(j, title="Retained gateway event 01", visibility="team"):
    j.click("button", "تمييز السجل وإضافة ملاحظة", event_row(j, title))
    dialog = j.page.get_by_role("dialog")
    dialog.locator("input[name=title]").fill("Gateway evidence review marker")
    dialog.locator("textarea[name=notes]").fill("Preserve the original gateway event for the incoming reviewer")
    dialog.locator("input[name=visibility]").fill(j.page.evaluate("v=>autopsyLabel(v)", visibility))
    return dialog


def local_input(j, value):
    return j.page.evaluate("value=>{const d=new Date(value);return new Date(d-d.getTimezoneOffset()*60000).toISOString().slice(0,16)}", value)


def attack_form(j, query="T1059"):
    area = panel(j, "توثيق MITRE ATT&CK بالأدلة")
    area.locator("input[name=attack_search]").fill(query)
    j.click("button", "بحث التقنيات", area)
    return area.locator("form").filter(has=j.page.locator("input[name=assessment]"))


def technique(j, form, assessment="verified", event="Retained gateway event 01"):
    choose(j, form, "technique_id", "T1059 · Command and Scripting Interpreter")
    form.locator("input[name=assessment]").fill(j.page.evaluate("v=>autopsyLabel(v)", assessment))
    form.locator("textarea[name=reason]").fill("The retained gateway record supports this scoped investigation decision")
    if event:
        choose(j, form, "event_id", event)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "timeline-time-window-correction",
        "timeline-page-bookmark-refind",
        "timeline-shared-window-recall",
        "timeline-filter-network-retry",
        "bookmark-private-report-exclusion",
        "bookmark-shared-reviewer",
        "bookmark-permission-recovery",
        "technique-verified-evidence-recovery",
        "technique-empty-search-recovery",
        "technique-filter-evidence-refresh",
        "technique-live-scope-restoration",
        "technique-report-freshness",
    ],
)
def test_investigator_can_reach_the_retained_event_and_publish_the_right_decision(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        manager_case(j, manager)
        source = manager if scenario == "technique-live-scope-restoration" else j
        upload_events(source, 51 if scenario == "timeline-page-bookmark-refind" else 2)
        result["uploaded_records"] = 51 if scenario == "timeline-page-bookmark-refind" else 2
        open_timeline(j)
        subject = j
        if scenario == "timeline-time-window-correction":
            start = timeline(j).locator("input[name=timeline_start]")
            end = timeline(j).locator("input[name=timeline_end]")
            start.fill(local_input(j, "2026-11-02T09:01:00Z"))
            end.fill(local_input(j, "2026-11-02T09:00:00Z"))
            j.click("button", "تطبيق الفلاتر", timeline(j))
            expect(j.page.locator("#global-message")).to_be_visible()
            end.fill(local_input(j, "2026-11-02T09:02:00Z"))
            j.click("button", "تطبيق الفلاتر", timeline(j))
            expect(event_row(j)).to_have_count(0)
            expect(event_row(j, "Retained gateway event 02")).to_be_visible()
            j.page.reload()
            j.settle()
            expect(event_row(j, "Retained gateway event 02")).to_be_visible()
        elif scenario == "timeline-page-bookmark-refind":
            expect(timeline(j).locator(".autopsy-timeline > li")).to_have_count(50)
            j.click("button", "التالي", timeline(j))
            expect(timeline(j).locator(".autopsy-timeline > li")).to_have_count(1)
            j.page.reload()
            j.settle()
            dialog = bookmark(j, "Retained gateway event 51")
            j.click("button", "حفظ", dialog)
            j.click("button", "السابق", timeline(j))
            search_events(j, "Retained gateway event 51")
            expect(event_row(j, "Retained gateway event 51")).to_contain_text("Gateway evidence review marker")
        elif scenario == "timeline-shared-window-recall":
            timeline(j).locator("input[name=timeline_start]").fill(local_input(j, "2026-11-02T09:01:00Z"))
            timeline(j).locator("input[name=timeline_end]").fill(local_input(j, "2026-11-02T09:02:00Z"))
            j.click("button", "تطبيق الفلاتر", timeline(j))
            j.click("button", "حفظ منظر البحث", timeline(j))
            dialog = j.page.get_by_role("dialog")
            dialog.locator("input[name=title]").fill("Incoming gateway review window")
            j.click("button", "حفظ", dialog)
            manager.page.goto(j.case_url + "?tab=investigation")
            manager.settle()
            manager.click("button", "Incoming gateway review window", timeline(manager))
            expect(event_row(manager)).to_have_count(0)
            expect(event_row(manager, "Retained gateway event 02")).to_be_visible()
            expect(timeline(manager).locator("select[name=timeline_scope]")).to_have_value("logs")
            manager.page.reload()
            manager.settle()
            expect(event_row(manager, "Retained gateway event 02")).to_be_visible()
            subject = manager
        elif scenario == "timeline-filter-network-retry":
            j.page.route("**/api/cases/*/timeline?*", lambda route: route.abort(), times=1)
            search_events(j, "event 02")
            expect(j.page.locator("#global-message")).to_be_visible()
            expect(timeline(j).locator("input[name=timeline_q]")).to_have_value("event 02")
            j.click("button", "تطبيق الفلاتر", timeline(j))
            expect(event_row(j)).to_have_count(0)
            expect(event_row(j, "Retained gateway event 02")).to_be_visible()
        elif scenario.startswith("bookmark-"):
            if scenario == "bookmark-private-report-exclusion":
                open_timeline(manager)
                dialog = bookmark(manager, visibility="private")
                manager.click("button", "حفظ", dialog)
                j.page.reload()
                j.settle()
                expect(timeline(j)).not_to_contain_text("Gateway evidence review marker")
                expect(timeline(manager)).to_contain_text("Gateway evidence review marker")
                manager.click("link", "التقارير والمراجعة")
                manager.click("button", "إعداد تقرير جديد")
                snapshot = report(manager, report_path(manager))
                assert "Gateway evidence review marker" not in json.dumps(snapshot["payload"])
                result["report_state"] = snapshot["job"]["state"]
                subject = manager
            else:
                dialog = bookmark(j)
                if scenario == "bookmark-permission-recovery":
                    role_permission(manager, "cases.update", False)
                    j.click("button", "حفظ", dialog)
                    expect(dialog.locator("form > [role=alert]")).to_be_visible()
                    expect(dialog.locator("textarea[name=notes]")).to_have_value("Preserve the original gateway event for the incoming reviewer")
                    role_permission(manager, "cases.update", True)
                j.click("button", "حفظ", dialog)
                manager.page.goto(j.case_url + "?tab=investigation")
                manager.settle()
                expect(event_row(manager)).to_contain_text("Gateway evidence review marker")
                manager.click("button", "تفاصيل السجل", event_row(manager))
                expect(manager.page.get_by_role("dialog")).to_contain_text("RETAINED-GW")
                manager.page.keyboard.press("Escape")
                subject = manager
        else:
            if scenario == "technique-report-freshness":
                j.click("link", "التقارير والمراجعة")
                j.click("button", "إعداد تقرير جديد")
                original_path = report_path(j)
                original = report(j, original_path)
                expect(j.page.locator(".report-revision").first).to_contain_text(j.text("يتضمن أحدث بيانات القضية"))
                open_timeline(j)
            form = attack_form(j, "No such retained technique" if scenario == "technique-empty-search-recovery" else "T1059")
            if scenario == "technique-empty-search-recovery":
                form.locator("input[name=technique_id]").press("ArrowDown")
                expect(form.get_by_role("option")).to_have_count(0)
                form = attack_form(j)
            if scenario == "technique-filter-evidence-refresh":
                technique(j, form)
                search_events(j, "event 02")
                expect(form.locator("input[name=event_id]")).to_have_value("")
                expect(form.locator("input[name=technique_id]")).to_have_value("T1059 · Command and Scripting Interpreter")
                expect(form.locator("input[name=assessment]")).to_have_value(j.page.evaluate("autopsyLabel('verified')"))
                expect(form.locator("textarea[name=reason]")).to_have_value("The retained gateway record supports this scoped investigation decision")
                form.locator("input[name=event_id]").press("ArrowDown")
                expect(form.get_by_role("option").filter(has_text="Retained gateway event 01")).to_have_count(0)
                choose(j, form, "event_id", "Retained gateway event 02")
                selected = form.locator("input[name=event_id]").input_value()
                search_events(j, "Retained gateway event 02")
                expect(form.locator("input[name=event_id]")).to_have_value(selected)
                form.locator("input[name=event_id]").press("ArrowDown")
                panel(j, "توثيق MITRE ATT&CK بالأدلة").screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-choice.png"))
                j.page.keyboard.press("Escape")
            technique(
                j,
                form,
                event=None
                if scenario == "technique-verified-evidence-recovery"
                else "Retained gateway event 02"
                if scenario == "technique-filter-evidence-refresh"
                else "Retained gateway event 01",
            )
            if scenario == "technique-verified-evidence-recovery":
                j.click("button", "حفظ", form)
                expect(form.locator("[role=alert]")).to_be_visible()
                choose(j, form, "event_id", "Retained gateway event 01")
            if scenario == "technique-live-scope-restoration":
                manager.page.goto(j.case_url + "?tab=logs")
                manager.settle()
                restrict_batch(manager, "retained-gateway.json")
                j.click("button", "حفظ", form)
                expect(form.locator("[role=alert]")).to_be_visible()
                assert manager.page.evaluate("id=>api(`/api/cases/${id}/attack`)", j.case_id)["annotations"] == []
                restrict_batch(manager, "retained-gateway.json", j.page.evaluate("state.user.name"))
            j.click("button", "حفظ", form)
            annotations = j.page.evaluate("id=>api(`/api/cases/${id}/attack`)", j.case_id)["annotations"]
            assert len(annotations) == 1 and annotations[0]["assessment"] == "verified" and annotations[0]["event_id"]
            if scenario == "technique-report-freshness":
                j.click("link", "التقارير والمراجعة")
                expect(j.page.locator(".report-revision").first).to_contain_text(j.text("تغيرت القضية بعد إعداد هذا التقرير"))
                retained = report(j, original_path)
                assert retained["payload"] == original["payload"] and retained["sha256"] == original["sha256"]
                j.click("button", "إعداد تقرير جديد")
                latest = report(j, report_path(j))
                assert latest["payload"]["techniques"][0]["event_id"] == annotations[0]["event_id"]
                assert original["payload"]["techniques"] == []
                result["report_state"] = latest["job"]["state"]
        result["outcomes"] = [
            scenario,
            "visible user actions and retained evidence verified",
            "uploaded records and verification calls are not additional users",
        ]
        evidence_images(subject, result)
        if scenario.startswith("technique-") and scenario != "technique-report-freshness":
            panel(subject, "توثيق MITRE ATT&CK بالأدلة").screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-target.png"))
        elif scenario.startswith("timeline-"):
            timeline(subject).screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-target.png"))
