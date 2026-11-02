"""User goals around case handover, working hours, and retained investigation records."""

import io
import zipfile
from pathlib import Path

import pytest
from playwright.sync_api import expect

from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_review_workflow import ARTIFACTS, review_session

SCENARIOS = [
    "sla-pause-resume",
    "sla-business-calendar",
    "sla-calendar-recovery",
    "sla-analyst-permissions",
    "collection-approved",
    "collection-rejected",
    "postmortem-independent-review",
    "capsule-private-exclusion",
    "capsule-restore-archive",
    "capsule-corrupt-recovery",
    "timeline-saved-search",
    "response-unproven-success",
]


def panel(journey, heading):
    return journey.page.locator("section.panel").filter(has=journey.page.get_by_role("heading", name=journey.text(heading), exact=True))


def choose(journey, scope, key, value):
    scope.locator(f"input[name={key}]").fill(journey.page.evaluate("v => autopsyLabel(v)", value))


def record_dialog(journey, kind):
    label = journey.page.evaluate("k => SOCifyLocale.template`إضافة ${autopsyLabel(k)}`", kind)
    journey.page.get_by_role("button", name=label, exact=True).click()
    return journey.page.get_by_role("dialog")


def workflow(journey):
    return journey.page.evaluate("id => api(`/api/cases/${id}/workflow`)", journey.case_id)


def download_capsule(journey):
    journey.click("link", "التقارير والمراجعة")
    with journey.page.expect_download() as pending:
        journey.page.get_by_role("link", name=journey.text("تصدير حزمة الفريق"), exact=True).click()
    return Path(pending.value.path()).read_bytes()


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", SCENARIOS)
def test_case_continuity_from_the_user_interface(app, language, scenario):
    with review_session(app, language, scenario) as (analyst, manager, result):
        manager.login("manager@socify.local")
        manager.page.goto(analyst.case_url)
        manager.settle()
        manager.case_url = analyst.case_url
        j = manager
        page = j.page
        result["goal"] = scenario
        if scenario.startswith("sla-"):
            j.click("link", "الاستجابة والتصعيد")
            form = panel(j, "SLA وجمع الأدلة ومراجعة ما بعد الحادثة").locator("form").filter(has=page.locator("input[name=minutes]"))
            form.locator("input[name=minutes]").fill("120")
            form.locator("input[name=reason]").fill("Agreed response target for the investigation")
            if scenario in {"sla-business-calendar", "sla-calendar-recovery"}:
                choose(j, form, "mode", "business")
                choose(j, form, "weekdays", "sun_thu")
                if scenario == "sla-calendar-recovery":
                    form.locator("input[name=start_hour]").fill("18")
                    form.locator("input[name=end_hour]").fill("9")
                    j.click("button", "حفظ", form)
                    expect(form.get_by_role("alert")).to_be_visible()
                    expect(form.locator("input[name=minutes]")).to_have_value("120")
                    assert not workflow(j)["sla"]["configured"]
                    form.locator("input[name=start_hour]").fill("9")
                    form.locator("input[name=end_hour]").fill("17")
            j.click("button", "حفظ", form)
            data = workflow(j)["sla"]
            assert data["configured"] and data["policy"]["minutes"] == 120
            summary = page.locator(".sla-summary")
            expect(summary).to_contain_text(j.text("الوقت المتبقي"))
            expect(summary).to_contain_text(j.text("الموعد المتوقع"))
            expect(summary).to_contain_text(j.text("المهلة جارية"))
            page.locator(".sla-settings summary").click()
            expect(form.locator("input[name=minutes]")).to_have_value("120")
            page.locator(".sla-settings summary").click()
            if scenario in {"sla-business-calendar", "sla-calendar-recovery"}:
                assert data["policy"]["calendar"] == {
                    "mode": "business",
                    "timezone": "Asia/Riyadh",
                    "weekdays": [0, 1, 2, 3, 6],
                    "start_hour": 9,
                    "end_hour": 17,
                    "holidays": [],
                }
            if scenario == "sla-pause-resume":
                for button, state in [("إيقاف SLA مؤقتًا", "paused"), ("استئناف SLA", "running")]:
                    j.click("button", button)
                    dialog = page.get_by_role("dialog")
                    dialog.locator("input[name=reason]").fill("Waiting for retained evidence" if state == "paused" else "Evidence is available for review")
                    j.click("button", "حفظ", dialog)
                    assert workflow(j)["sla"]["status"] == state
                    expect(page.locator(".sla-summary")).to_contain_text(j.text("المهلة معلقة" if state == "paused" else "المهلة جارية"))
                    if state == "paused":
                        first = workflow(j)["sla"]["elapsed_work_seconds"]
                        page.wait_for_timeout(1100)
                        assert abs(workflow(j)["sla"]["elapsed_work_seconds"] - first) < 0.01
            if scenario == "sla-analyst-permissions":
                analyst.click("link", "الاستجابة والتصعيد")
                expect(analyst.page.locator("input[name=minutes]")).to_have_count(0)
                expect(analyst.page.get_by_role("button", name=analyst.text("إيقاف SLA مؤقتًا"), exact=True)).to_have_count(0)
                assert workflow(analyst)["sla"]["configured"]
            result["outcomes"] = ["response policy persisted", scenario, "result inspected through the interface and read-only stored state"]
        elif scenario.startswith("collection-"):
            analyst.click("link", "الاستجابة والتصعيد")
            form = analyst.page.locator("form").filter(has=analyst.page.locator("input[name=recipe_id]"))
            form.locator("input[name=recipe_id]").press("ArrowDown")
            form.get_by_role("option").first.click()
            form.locator("input[name=collector_id]").press("ArrowDown")
            form.get_by_role("option").filter(has_text=analyst.page.evaluate("state.user.name")).first.click()
            form.locator("textarea[name=reason]").fill("Collect identity records for the documented incident window")
            analyst.click("button", "حفظ", form)
            assert workflow(analyst)["collections"][0]["payload"]["state"] == "pending_approval"
            j.click("link", "الاستجابة والتصعيد")
            j.click("button", "اعتماد نطاق الجمع" if scenario == "collection-approved" else "رفض نطاق الجمع")
            dialog = page.get_by_role("dialog")
            dialog.locator("input[name=reason]").fill(
                "Approved incident window" if scenario == "collection-approved" else "Requested sources are outside the case scope"
            )
            j.click("button", "حفظ", dialog)
            expected = "approved" if scenario == "collection-approved" else "rejected"
            analyst.page.reload()
            analyst.settle()
            assert workflow(analyst)["collections"][0]["payload"]["state"] == expected
            expect(analyst.page.locator("main")).not_to_contain_text("pending_approval")
            if language == "en":
                expect(analyst.page.locator("main")).not_to_contain_text("مصادر مصادقة")
            control = analyst.page.get_by_role("button", name=analyst.text("توثيق الجمع المنفذ محليًا"), exact=True)
            if expected == "approved":
                expect(control).to_be_visible()
            else:
                expect(control).to_have_count(0)
            result["outcomes"] = ["collection requested by analyst", "manager decision retained", "only approved collection can be documented"]
        elif scenario == "postmortem-independent-review":
            j.transition("investigating")
            j.transition("awaiting_review")
            j.click("link", "الاستجابة والتصعيد")
            j.click("button", "إنشاء مسودة مراجعة ما بعد الحادثة")
            j.click("button", "مراجعة المسودة")
            dialog = page.get_by_role("dialog")
            dialog.locator("textarea[name=executive_summary]").fill("Retained evidence has not established a compromise.")
            dialog.locator("textarea[name=lessons]").fill("Retain the missing identity records before concluding scope.")
            dialog.locator("textarea[name=limitations]").fill("Identity records remain incomplete.")
            j.click("button", "حفظ", dialog)
            expect(dialog.get_by_role("alert")).to_be_visible()
            assert workflow(j)["postmortems"][0]["payload"]["state"] == "draft"
            dialog.locator("input[name=override_reason]").fill("Duty manager exception recorded because no separate reviewer is available.")
            j.click("button", "حفظ", dialog)
            assert workflow(j)["postmortems"][0]["payload"]["state"] == "reviewed"
            result["outcomes"] = ["unexplained self-review blocked", "draft retained after rejection", "manager exception explicitly documented"]
        elif scenario.startswith("capsule-"):
            analyst.click("link", "التحقيق والخط الزمني")
            for visibility, title in [("private", "Confidential author assessment"), ("team", "Shared investigation assessment")]:
                dialog = record_dialog(analyst, "war_room")
                dialog.locator("input[name=title]").fill(title)
                dialog.locator("textarea[name=body]").fill(title + ": review before drawing conclusions.")
                choose(analyst, dialog, "visibility", visibility)
                analyst.click("button", "حفظ", dialog)
            capsule = download_capsule(analyst)
            with zipfile.ZipFile(io.BytesIO(capsule)) as archive:
                snapshot = archive.read("data.json").decode()
                assert "Confidential author assessment" not in snapshot
                assert "Shared investigation assessment" in snapshot
            if scenario != "capsule-private-exclusion":
                analyst.click("link", "استعادة حزمة كقضية جديدة")
                file = analyst.page.get_by_label(analyst.text("حزمة قضية محلية"), exact=True)
                if scenario == "capsule-corrupt-recovery":
                    buffer = io.BytesIO()
                    with zipfile.ZipFile(io.BytesIO(capsule)) as source, zipfile.ZipFile(buffer, "w") as target:
                        for name in source.namelist():
                            content = source.read(name)
                            target.writestr(name, content + b" " if name == "data.json" else content)
                    file.set_input_files({"name": "damaged.zip", "mimeType": "application/zip", "buffer": buffer.getvalue()})
                    analyst.click("button", "استعادة كقضية جديدة")
                    expect(analyst.page.get_by_role("alert")).to_be_visible()
                    analyst.page.wait_for_timeout(6000)
                    expect(analyst.page.get_by_role("alert")).to_be_visible()
                    assert "/analysis-library" in analyst.page.url
                file.set_input_files({"name": "retained-case.zip", "mimeType": "application/zip", "buffer": capsule})
                analyst.click("button", "استعادة كقضية جديدة")
                analyst.page.wait_for_url("**/cases/*?tab=reports")
                assert f"/cases/{analyst.case_id}?" not in analyst.page.url
                analyst.click("button", "فحص الأرشيف")
                dialog = analyst.page.get_by_role("dialog")
                expect(dialog.locator("pre")).to_contain_text("Authorized maintenance investigation")
                dialog.locator("select[name=section]").select_option("autopsy_records")
                expect(dialog.locator("pre")).to_contain_text("Shared investigation assessment")
                expect(dialog.locator("pre")).not_to_contain_text("Confidential author assessment")
                analyst.click("button", "إغلاق", dialog)
            result["outcomes"] = ["private content absent from team download", scenario, "source case preserved"]
        elif scenario == "timeline-saved-search":
            analyst.click("link", "التحقيق والخط الزمني")
            expect(analyst.page.locator(".graph-canvas")).to_have_count(0)
            query = analyst.page.get_by_label(analyst.text("بحث الخط الزمني"), exact=True)
            query.fill("identity approval")
            analyst.click("button", "تطبيق الفلاتر")
            analyst.click("button", "حفظ منظر البحث")
            dialog = analyst.page.get_by_role("dialog")
            dialog.locator("input[name=title]").fill("Identity approval review")
            choose(analyst, dialog, "visibility", "private")
            analyst.click("button", "حفظ", dialog)
            query.fill("unrelated")
            analyst.click("button", "تطبيق الفلاتر")
            analyst.click("button", "Identity approval review")
            expect(query).to_have_value("identity approval")
            analyst.page.reload()
            analyst.settle()
            expect(analyst.page.get_by_label(analyst.text("بحث الخط الزمني"), exact=True)).to_have_value("identity approval")
            result["outcomes"] = ["named private search recalled", "filter retained after reload", "no result fabricated for empty matching set"]
        elif scenario == "response-unproven-success":
            analyst.click("link", "الاستجابة والتصعيد")
            dialog = record_dialog(analyst, "response")
            dialog.locator("input[name=title]").fill("Account session containment")
            choose(analyst, dialog, "phase", "containment")
            choose(analyst, dialog, "status", "succeeded")
            dialog.locator("textarea[name=details]").fill("Awaiting confirmation from the identity platform owner")
            analyst.click("button", "حفظ", dialog)
            expect(dialog.get_by_role("alert")).to_be_visible()
            expect(dialog.locator("input[name=title]")).to_have_value("Account session containment")
            choose(analyst, dialog, "status", "planned")
            analyst.click("button", "حفظ", dialog)
            records = analyst.page.evaluate("id => api(`/api/cases/${id}/records?kind=response`)", analyst.case_id)
            assert len(records["items"]) == 1 and records["items"][0]["payload"]["status"] == "planned"
            result["outcomes"] = ["unsupported success rejected", "planned action saved without inventing execution", "rejected form inputs retained"]
        for journey in [analyst, manager]:
            assert not journey.page.evaluate("SOCifyDrafts.hasChanges()")
            for width in [390, 1440]:
                journey.page.set_viewport_size({"width": width, "height": 1000})
                assert journey.page.evaluate("document.documentElement.scrollWidth <= innerWidth"), width
        if scenario == "sla-pause-resume":
            assert_accessible(page)
            panel(j, "SLA وجمع الأدلة ومراجعة ما بعد الحادثة").evaluate("el => el.scrollIntoView({block: 'start'})")
            page.evaluate("window.scrollBy(0, -90)")
            page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-summary.png"))
