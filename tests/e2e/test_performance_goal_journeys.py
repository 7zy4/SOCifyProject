"""Follow team workload and delivery through the visible interface."""

from datetime import timedelta

import pytest
from playwright.sync_api import expect

from socify.timeutils import parse_timestamp
from tests.e2e.test_assignment_handoff_journeys import handoff_form
from tests.e2e.test_batch_boundary_journeys import restrict_batch, upload_logs
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_review_workflow import ARTIFACTS, review_session
from tests.e2e.test_task_queue_journeys import assign, assignments


def number(text):
    return int(text.translate(str.maketrans("٠١٢٣٤٥٦٧٨٩", "0123456789")).replace(",", "").replace("٬", ""))


def counter(j, name):
    return number(j.page.locator(".insight-counter").filter(has=j.page.get_by_text(j.text(name), exact=True)).locator("strong").inner_text())


def completed(j, person):
    row = delivery(j).locator("tr").filter(has=j.page.get_by_text(person, exact=True))
    return number(row.get_by_role("cell").last.inner_text())


def period(j, days):
    j.page.get_by_label(j.text("فترة الإنجاز"), exact=True).select_option(days)
    j.click("button", "تطبيق", j.page.locator(".filter-row"))


def reload(j):
    j.page.reload()
    j.settle()


def delivery(j):
    return j.page.locator("section.panel").filter(has=j.page.get_by_role("heading", name=j.text("الفريق والإنجاز"), exact=True))


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "performance-task-destination",
        "performance-completed-credit",
        "performance-reopened-credit",
        "performance-handoff-credit",
        "performance-handoff-workload",
        "performance-member-period",
        "performance-empty-personal",
        "performance-personal-assignment",
        "performance-review-waiting",
        "performance-review-cleared",
        "performance-access-denied",
        "performance-network-recovery",
        "performance-invalid-filter-recovery",
        "performance-restricted-batch",
        "performance-period-boundary",
        "performance-deadline-crossing",
    ],
)
def test_performance_supports_the_next_user_decision(app, monkeypatch, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        manager.login("manager@socify.local")
        manager.case_url = j.case_url
        manager.page.goto(j.case_url)
        manager.settle()
        person = j.page.evaluate("state.user.name")
        manager_name = manager.page.evaluate("state.user.name")
        if scenario in {
            "performance-task-destination",
            "performance-completed-credit",
            "performance-reopened-credit",
            "performance-handoff-credit",
            "performance-handoff-workload",
            "performance-personal-assignment",
            "performance-restricted-batch",
            "performance-period-boundary",
        }:
            upload_logs(manager, "assigned-review.json", "Review retained sign-in evidence")
            assign(manager, manager_name if scenario == "performance-personal-assignment" else person)
        if scenario in {"performance-completed-credit", "performance-reopened-credit", "performance-handoff-credit", "performance-period-boundary"}:
            j.nav("مهامي")
            j.click("button", "إكمال المهمة")
            result["original_completion"] = assignments(manager)[0]["completed_at"]
        if scenario.startswith("performance-review-"):
            j.assessment("Retained sign-in evidence reviewed; awaiting independent decision")
            if scenario == "performance-review-cleared":
                manager.page.goto(j.case_url + "?tab=reports")
                manager.settle()
                manager.decision("approved", "Reviewed the sign-in investigation and accepted the documented decision")
        if scenario == "performance-task-destination":
            j.page.set_viewport_size({"width": 390, "height": 1000})
            result["interaction_viewport"] = 390
        j.nav("الأداء")
        manager.nav("الأداء")
        subject = j
        if scenario == "performance-task-destination":
            j.page.get_by_role("link", name="Review the retained identity batch", exact=True).click()
            j.settle()
            row = j.page.locator("tr").filter(has=j.page.get_by_role("cell", name="Review the retained identity batch", exact=True))
            expect(row.get_by_role("button", name=j.text("إكمال المهمة"), exact=True)).to_be_visible()
            assert j.page.evaluate("document.activeElement.closest('tr')?.textContent.includes('Review the retained identity batch')")
            assert j.page.locator(".assignment-table").evaluate_all("tables => tables.length > 0 && tables.every(el => el.scrollWidth <= el.clientWidth)")
            assert row.get_by_role("button").evaluate("el => {const r=el.getBoundingClientRect(); return r.left>=0 && r.right<=innerWidth;}")
            j.page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-task.png"))
            j.click("button", "إكمال المهمة", row)
            j.nav("الأداء")
            expect(j.page.get_by_role("link", name="Review the retained identity batch", exact=True)).to_have_count(0)
            assert completed(j, person) == 1
        elif scenario == "performance-completed-credit":
            assert completed(j, person) == completed(manager, person) == 1
            assert completed(manager, manager_name) == 0
            assert counter(j, "مهام معلقة") == 2
            reload(j)
            assert completed(j, person) == 1
        elif scenario == "performance-reopened-credit":
            assert completed(j, person) == 1
            j.nav("مهامي")
            j.click("button", "إعادة فتح المهمة")
            j.nav("الأداء")
            assert completed(j, person) == 0
            assert counter(j, "مهام معلقة") == 3
            expect(j.page.get_by_role("link", name="Review the retained identity batch", exact=True)).to_be_visible()
        elif scenario.startswith("performance-handoff-"):
            form = handoff_form(manager, person, manager_name)
            manager.click("button", "حفظ", form)
            manager.nav("الأداء")
            reload(j)
            if scenario == "performance-handoff-credit":
                assert completed(j, person) == completed(manager, person) == 1
                assert completed(manager, manager_name) == 0
                assert assignments(manager)[0]["completed_at"] == result["original_completion"]
            else:
                assert counter(j, "مهام معلقة") == 0
                manager.click("link", "أدائي", manager.page.locator(".channel-tabs"))
                assert counter(manager, "مهام معلقة") == 3
                expect(manager.page.get_by_role("link", name="Review the retained identity batch", exact=True)).to_be_visible()
                subject = manager
        elif scenario == "performance-member-period":
            period(manager, "7")
            manager.click("link", person, delivery(manager))
            assert "days=7" in manager.page.url and "member=" in manager.page.url
            expect(manager.page.get_by_label(manager.text("فترة الإنجاز"), exact=True)).to_have_value("7")
            assert delivery(manager).get_by_role("row").count() == 2
            manager.page.locator("[data-language-toggle]").click()
            manager.settle()
            expect(manager.page.get_by_label(manager.text("فترة الإنجاز"), exact=True)).to_have_value("7")
            manager.page.locator("[data-language-toggle]").click()
            manager.settle()
            manager.click("link", "الفريق", manager.page.locator(".channel-tabs"))
            assert "days=7" in manager.page.url
            subject = manager
        elif scenario == "performance-empty-personal":
            manager.click("link", "أدائي", manager.page.locator(".channel-tabs"))
            assert counter(manager, "قضايا نشطة") == counter(manager, "أغلقت خلال الفترة") == counter(manager, "مهام معلقة") == 0
            expect(manager.page.get_by_text(manager.text("لا قضايا نشطة"), exact=True)).to_be_visible()
            assert manager.page.locator(".insight-columns table tbody tr").count() == 5
            stages = (
                ["الرصد", "إقرار الاستلام", "الاحتواء", "التعافي", "الإغلاق"]
                if language == "ar"
                else ["Detection", "Acknowledgement", "Containment", "Recovery", "Closure"]
            )
            assert manager.page.locator(".insight-columns table tbody tr td:first-child").all_inner_texts() == stages
            for row in manager.page.locator(".insight-columns table tbody tr").all():
                assert row.get_by_role("cell").nth(1).inner_text() == "—"
            subject = manager
        elif scenario == "performance-personal-assignment":
            assert counter(j, "مهام معلقة") == 2
            manager.click("link", "أدائي", manager.page.locator(".channel-tabs"))
            assert counter(manager, "مهام معلقة") == 1
            expect(manager.page.get_by_role("link", name="Review the retained identity batch", exact=True)).to_be_visible()
            expect(j.page.get_by_role("link", name="Review the retained identity batch", exact=True)).to_have_count(0)
            subject = manager
        elif scenario.startswith("performance-review-"):
            assert counter(manager, "بانتظار المراجعة") == (1 if scenario == "performance-review-waiting" else 0)
            subject = manager
        elif scenario == "performance-access-denied":
            j.page.goto(j.base + "/performance?member=team")
            j.settle()
            expect(j.page.get_by_text(j.text("تعذر تحميل الأداء"), exact=True)).to_be_visible()
            expect(j.page.get_by_role("link", name=manager_name, exact=True)).to_have_count(0)
            assert j.page.request.get(j.base + "/api/soc/performance?member=team").status == 403
            j.nav("الأداء")
            assert counter(j, "قضايا نشطة") == 1
        elif scenario == "performance-network-recovery":
            j.page.route("**/api/soc/performance?*", lambda route: route.abort(), times=1)
            reload(j)
            expect(j.page.get_by_text(j.text("تعذر تحميل الأداء"), exact=True)).to_be_visible()
            j.click("button", "إعادة المحاولة")
            assert counter(j, "قضايا نشطة") == 1
        elif scenario == "performance-invalid-filter-recovery":
            j.page.goto(j.base + "/performance?days=invalid&member=me")
            j.settle()
            expect(j.page.get_by_text(j.text("تعذر تحميل الأداء"), exact=True)).to_be_visible()
            j.nav("الأداء")
            period(j, "90")
            assert counter(j, "قضايا نشطة") == 1
        elif scenario == "performance-restricted-batch":
            manager.page.goto(j.case_url + "?tab=logs")
            manager.settle()
            restrict_batch(manager, "assigned-review.json")
            reload(j)
            expect(j.page.get_by_role("link", name="Review the retained identity batch", exact=True)).to_have_count(0)
            restrict_batch(manager, "assigned-review.json", person)
            reload(j)
            expect(j.page.get_by_role("link", name="Review the retained identity batch", exact=True)).to_be_visible()
        elif scenario == "performance-period-boundary":
            stamp = parse_timestamp(result["original_completion"])
            monkeypatch.setattr("socify.soc_insights.utc_now", lambda: stamp + timedelta(days=7) - timedelta(seconds=1))
            period(j, "7")
            assert completed(j, person) == 1
            monkeypatch.setattr("socify.soc_insights.utc_now", lambda: stamp + timedelta(days=7, seconds=1))
            reload(j)
            assert completed(j, person) == 0
            assert counter(j, "قضايا نشطة") == 1
            period(j, "all")
            assert completed(j, person) == 1
            result["environment_condition"] = "Controlled server clock across the seven-day completion boundary; case backlog stays current"
        elif scenario == "performance-deadline-crossing":
            due = parse_timestamp(j.state()["sla_due_at"])
            monkeypatch.setattr("socify.soc_insights.utc_now", lambda: due - timedelta(seconds=1))
            reload(j)
            datum = j.page.get_by_text(j.text("تجاوزت موعد القضية"), exact=True).locator("+ dd")
            assert number(datum.inner_text()) == 0
            monkeypatch.setattr("socify.soc_insights.utc_now", lambda: due + timedelta(seconds=1))
            reload(j)
            assert number(datum.inner_text()) == 1
            result["environment_condition"] = "Controlled server clock before and after the case deadline; no invented closed case"
        assert_accessible(subject.page)
        for width in (390, 1440):
            subject.page.set_viewport_size({"width": width, "height": 1000})
            assert subject.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            subject.page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-{width}.png"), full_page=True)
        result["outcomes"] = [scenario, "visible counters and task destinations verified", "business state changes through the interface"]
