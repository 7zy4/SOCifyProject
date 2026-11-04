"""Follow completed investigations from the performance page into retained work."""

from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from playwright.sync_api import expect

from socify.timeutils import iso_now, utc_now
from tests.e2e.test_batch_boundary_journeys import restrict_batch, upload_logs
from tests.e2e.test_investigation_link_journeys import capture, choose, corrective_dialog, records, root_cause
from tests.e2e.test_performance_goal_journeys import counter, delivery, period
from tests.e2e.test_review_workflow import review_session


def close_existing_case(database, j, result):
    database.execute("UPDATE incident_cases SET status='closed', closed_at=?, version=version+1 WHERE id=?", (iso_now(), j.case_id))
    result["setup_only_state"] = "Previously closed investigation; native approval and closure are separate journeys"


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", ["performance-closed-case-destination", "performance-closed-corrective-followup"])
def test_analyst_can_follow_closed_work_from_performance(app, database, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        if scenario.endswith("corrective-followup"):
            root_cause(j)
            dialog = corrective_dialog(j)
            choose(j, dialog, "root_cause_id", "Retained identity policy gap")
            choose(j, dialog, "why_id", "Why was the identity scope missed?")
            j.click("button", "حفظ", dialog)
        close_existing_case(database, j, result)
        j.nav("الأداء")
        assert counter(j, "أغلقت خلال الفترة") == 1
        j.page.get_by_role("link").filter(has_text=j.text("أغلقت خلال الفترة")).click()
        j.settle()
        j.page.get_by_role("link").filter(has_text="Authorized maintenance investigation").click()
        j.settle()
        assert j.state()["status"] == "closed"
        if scenario.endswith("corrective-followup"):
            j.click("link", "الاستجابة والتصعيد")
            card = j.page.locator(".record-card").filter(has_text="Review the identity approval procedure")
            j.click("button", "تعديل", card)
            dialog = j.page.get_by_role("dialog")
            dialog.locator("input[name=status]").fill(j.page.evaluate("autopsyLabel('validated')"))
            dialog.locator("textarea[name=validation]").fill("The retained approval was independently reviewed and the corrective action verified.")
            j.click("button", "حفظ", dialog)
            assert records(j, "corrective")[0]["payload"]["status"] == "validated"
        else:
            expect(j.page.get_by_role("button", name=j.text("إكمال المهمة"), exact=True)).to_have_count(0)
        result["outcomes"] = ["closed work reached from its performance count and retained follow-up completed"]
        capture(j, result)


def select_queue(j, title):
    j.page.locator(".insight-counter").filter(has_text=j.text(title)).click()
    j.settle()


def completed_backlog(j, database, result):
    ids = j.page.evaluate(
        """async () => {
            const ids=[];
            for(let n=0;n<54;n++) ids.push((await api('/api/cases',{method:'POST',body:{title:`Retained completed review ${n+1}`}})).id);
            return ids;
        }"""
    )
    stamp = iso_now()
    database.executemany("UPDATE incident_cases SET status='closed',closed_at=? WHERE id=?", [(stamp, case_id) for case_id in [j.case_id, *ids]])
    result["setup_only_records"] = {"closed_cases": 55, "note": "Authenticated API preparation, not 55 users or UI completions"}


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "performance-closed-period-filter",
        "performance-closed-member-filter",
        "performance-closed-pagination",
        "performance-closed-empty",
        "performance-closed-scope-revocation",
        "performance-closed-reopen",
        "performance-closed-review-queue",
        "performance-closed-filter-recovery",
        "performance-closed-network-retry",
        "performance-closed-language-reload",
    ],
)
def test_completed_work_keeps_its_scope_and_recovery_path(app, database, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        if scenario.endswith("scope-revocation"):
            manager.login("manager@socify.local")
            manager.case_url = j.case_url
            manager.page.goto(j.case_url)
            manager.settle()
            upload_logs(manager, "closed-evidence.json", "Closed investigation retained evidence")
        if scenario.endswith("review-queue"):
            j.assessment("Evidence review ready for the independent decision")
        elif not scenario.endswith("closed-empty"):
            close_existing_case(database, j, result)
        if scenario.endswith("period-filter"):
            database.execute("UPDATE incident_cases SET closed_at=? WHERE id=?", ((utc_now() - timedelta(days=8)).isoformat(), j.case_id))
        if scenario.endswith("pagination") or scenario.endswith("language-reload"):
            completed_backlog(j, database, result)
        subject = j
        if scenario.endswith("member-filter"):
            manager.login("manager@socify.local")
            manager.nav("إدارة القضايا")
            manager.create_case()
            close_existing_case(database, manager, result)
            subject = manager
        subject.nav("الأداء")
        select_queue(subject, "بانتظار المراجعة" if scenario.endswith("review-queue") else "أغلقت خلال الفترة")
        queue = subject.page.locator("#performance-cases")
        if scenario.endswith("closed-empty"):
            assert counter(j, "أغلقت خلال الفترة") == 0
            expect(queue.locator("a[href^='/cases/']")).to_have_count(0)
            select_queue(j, "قضايا نشطة")
            expect(queue.locator(f"a[href='/cases/{j.case_id}']")).to_be_visible()
        elif scenario.endswith("period-filter"):
            period(j, "7")
            assert counter(j, "أغلقت خلال الفترة") == 0
            expect(queue.locator("a[href^='/cases/']")).to_have_count(0)
            period(j, "30")
            assert counter(j, "أغلقت خلال الفترة") == 1
            expect(queue.locator(f"a[href='/cases/{j.case_id}']")).to_be_visible()
            assert parse_qs(urlsplit(j.page.url).query)["queue"] == ["closed"]
            metrics = j.page.locator(".performance-durations")
            measured = metrics.locator(".performance-duration-row").first.locator(".performance-sample")
            assert measured.inner_text().translate(str.maketrans("٠١٢٣٤٥٦٧٨٩", "0123456789")) == (
                "حالات قابلة للحساب 0 من 1" if language == "ar" else "Cases measured 0 of 1"
            )
        elif scenario.endswith("member-filter"):
            assert counter(manager, "أغلقت خلال الفترة") == 2
            analyst_name = j.page.evaluate("state.user.name")
            delivery(manager).get_by_role("link", name=analyst_name, exact=True).click()
            manager.settle()
            assert counter(manager, "أغلقت خلال الفترة") == 1
            expect(queue.locator(f"a[href='/cases/{j.case_id}']")).to_be_visible()
            expect(queue.locator(f"a[href='/cases/{manager.case_id}']")).to_have_count(0)
            manager.click("link", "الفريق", manager.page.locator(".channel-tabs"))
            assert counter(manager, "أغلقت خلال الفترة") == 2
        elif scenario.endswith("pagination") or scenario.endswith("language-reload"):
            assert counter(j, "أغلقت خلال الفترة") == 55
            expect(queue.locator("tbody tr")).to_have_count(50)
            expect(queue.locator(f"a[href='/cases/{j.case_id}']")).to_have_count(0)
            j.click("link", "التالي", queue)
            expect(queue.locator("tbody tr")).to_have_count(5)
            expect(queue.locator(f"a[href='/cases/{j.case_id}']")).to_be_visible()
            if scenario.endswith("language-reload"):
                j.page.locator("[data-language-toggle]").click()
                j.settle()
                j.page.reload()
                j.settle()
                parameters = parse_qs(urlsplit(j.page.url).query)
                assert parameters["queue"] == ["closed"] and parameters["page"] == ["2"]
                expect(queue.locator(f"a[href='/cases/{j.case_id}']")).to_be_visible()
                result["ending_language"] = j.page.locator("html").get_attribute("lang")
            else:
                j.click("link", "السابق", queue)
                expect(queue.locator("tbody tr")).to_have_count(50)
        elif scenario.endswith("scope-revocation"):
            manager.page.goto(j.case_url + "?tab=logs")
            manager.settle()
            restrict_batch(manager, "closed-evidence.json")
            j.page.reload()
            j.settle()
            assert counter(j, "أغلقت خلال الفترة") == 0
            expect(queue.locator(f"a[href='/cases/{j.case_id}']")).to_have_count(0)
            restrict_batch(manager, "closed-evidence.json", j.page.evaluate("state.user.name"))
            j.page.reload()
            j.settle()
            assert counter(j, "أغلقت خلال الفترة") == 1
            expect(queue.locator(f"a[href='/cases/{j.case_id}']")).to_be_visible()
        elif scenario.endswith("closed-reopen"):
            queue.locator(f"a[href='/cases/{j.case_id}']").click()
            j.settle()
            j.transition("reopened")
            j.nav("الأداء")
            select_queue(j, "أغلقت خلال الفترة")
            assert counter(j, "أغلقت خلال الفترة") == 0
            expect(queue.locator(f"a[href='/cases/{j.case_id}']")).to_have_count(0)
            select_queue(j, "قضايا نشطة")
            expect(queue.locator(f"a[href='/cases/{j.case_id}']")).to_be_visible()
        elif scenario.endswith("review-queue"):
            queue.locator(f"a[href='/cases/{j.case_id}?tab=reports']").click()
            j.settle()
            expect(j.page.locator("[aria-current=page]").filter(has_text=j.text("التقارير والمراجعة"))).to_be_visible()
        elif scenario.endswith("filter-recovery"):
            j.page.goto(j.base + "/performance?queue=closed&page=0")
            j.settle()
            expect(j.page.get_by_text(j.text("تعذر تحميل الأداء"), exact=True)).to_be_visible()
            j.click("link", "مسح المرشحات")
            select_queue(j, "أغلقت خلال الفترة")
            expect(queue.locator(f"a[href='/cases/{j.case_id}']")).to_be_visible()
        else:
            j.page.route("**/api/soc/performance?*", lambda route: route.abort(), times=1)
            j.page.reload()
            j.settle()
            expect(j.page.get_by_text(j.text("تعذر تحميل الأداء"), exact=True)).to_be_visible()
            j.click("button", "إعادة المحاولة")
            expect(queue.locator(f"a[href='/cases/{j.case_id}']")).to_be_visible()
        result["outcomes"] = [scenario, "completed-work scope and the next visible action independently checked"]
        capture(subject, result)
