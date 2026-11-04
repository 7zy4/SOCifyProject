"""An analyst acts on permitted work without inferring restricted response times."""

from datetime import timedelta
from pathlib import Path

import pytest
from playwright.sync_api import expect

from socify.timeutils import utc_now
from tests.e2e.test_batch_boundary_journeys import restrict_batch, upload_logs
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_investigation_link_journeys import note_dialog, records
from tests.e2e.test_performance_goal_journeys import counter
from tests.e2e.test_review_workflow import review_session

ARTIFACTS = Path("artifacts/usability_campaign/performance-access-review")


def stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def retained_response_history(manager, database, case_id):
    """Historical setup only; no historical case is counted as a user journey."""
    start = utc_now() - timedelta(days=2)
    database.execute("UPDATE incident_cases SET created_at=? WHERE id=?", (stamp(start), case_id))
    manager.page.evaluate(
        """async ({id,start}) => {
            await api(`/api/cases/${id}/imports`, {method:'POST',body:{
                filename:'restricted-response.json',content:JSON.stringify([
                    {title:'Sensitive containment chronology',timestamp:start,hostname:'SENSITIVE-HOST'}
                ])}});
            const detail=await api(`/api/cases/${id}`);
            await api(`/api/cases/${id}/sla`, {method:'POST',body:{version:detail.version,
                minutes:60,calendar:{mode:'24x7',timezone:'UTC'},reason:'Documented case response target'}});
            for (const [phase,minutes] of [['detection',0],['containment',43]]) {
                await api(`/api/cases/${id}/records/response`, {method:'POST',body:{
                    title:'Sensitive '+phase,phase,status:'succeeded',performed_by:state.user.id,
                    performed_at:new Date(Date.parse(start)+minutes*60000).toISOString(),
                    evidence_id:detail.evidence[0].id,details:'Retained sensitive response record'}});
            }
        }""",
        {"id": case_id, "start": stamp(start)},
    )
    database.execute("UPDATE incident_cases SET status='closed',closed_at=? WHERE id=?", (stamp(start + timedelta(hours=2)), case_id))


def performance_data(j):
    return j.page.evaluate("() => api('/api/soc/performance?member=me')")


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_restricted_response_cannot_be_inferred_from_performance_charts(app, database, monkeypatch, language):
    monkeypatch.setattr("tests.e2e.test_review_workflow.ARTIFACTS", ARTIFACTS)
    with review_session(app, language, "performance-restricted-derived-metrics") as (j, manager, result):
        result["plan_id"] = "NEXT-10-restricted-derived-metrics"
        result["kind"] = "simulated end-user decision with prepared historical records"
        result["human_participants"] = 0
        result["novelty"] = (
            "Earlier performance-restricted-batch and closed-scope-revocation checks covered tasks/queues/counters; "
            "this journey checks the new completion, SLA and response-duration graphics and their API payload, "
            "then completes permitted work before an explicit grant changes the measurement population."
        )
        restricted_id, restricted_url = j.case_id, j.case_url
        person = j.page.evaluate("state.user.name")
        manager.login("manager@socify.local")
        manager.case_url = restricted_url
        retained_response_history(manager, database, restricted_id)
        manager.page.goto(restricted_url + "?tab=logs")
        manager.settle()
        restrict_batch(manager, "restricted-response.json")

        j.nav("إدارة القضايا")
        j.create_case()
        permitted_id = j.case_id
        upload_logs(j, "permitted-response.json", "Permitted response review record")
        j.nav("الأداء")
        expect(j.page.locator("[data-completion-count]")).to_have_text("0 من 1" if language == "ar" else "0 of 1")
        expect(j.page.locator("[data-speed-value]")).to_have_text("—")
        expect(j.page.locator(".performance-duration-track span")).to_have_count(0)
        assert counter(j, "قضايا نشطة") == 1 and counter(j, "أغلقت خلال الفترة") == 0
        expect(j.page.locator("main")).not_to_contain_text("Sensitive containment chronology")
        expect(j.page.locator("main")).not_to_contain_text("SENSITIVE-HOST")
        hidden = performance_data(j)
        assert hidden["completion"]["total"] == 1 and hidden["completion"]["completed"] == 0
        assert hidden["speed"]["included"] == hidden["speed"]["unmeasured"] == 0
        assert all(metric["median_seconds"] is None and metric["included"] == 0 for metric in hidden["metrics"].values())
        assert restricted_id not in [case["id"] for case in hidden["queue"]]
        result["initial_interpretation"] = (
            "The visible scope has one active investigation and no measured closed response. "
            "An unavailable response time is not evidence of an immediate or successful response. "
            "Continue the permitted review instead of drawing conclusions about inaccessible work."
        )
        result["restricted_measurements"] = {key: hidden[key] for key in ("completion", "speed", "metrics")}
        assert_accessible(j.page)
        for width in (390, 1440):
            j.page.set_viewport_size({"width": width, "height": 1000})
            assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            j.page.screenshot(path=str(ARTIFACTS / f"restricted-derived-{language}-{width}.png"), full_page=True)

        # The user follows a visible permitted case and records the actual next action.
        j.page.locator(f"#performance-cases a[href='/cases/{permitted_id}']").click()
        j.settle()
        j.click("link", "السجلات والأدلة")
        expect(j.page.get_by_role("cell", name="Permitted response review record", exact=True)).to_be_visible()
        j.click("link", "التحقيق والخط الزمني")
        dialog = note_dialog(j)
        note = "Reviewed the permitted record. Request a documented response milestone before assessing response time."
        dialog.locator("textarea[name=body]").fill(note)
        j.click("button", "حفظ", dialog)
        assert records(j, "war_room")[0]["payload"]["body"] == note

        # A manager grants access explicitly; only then may the hidden population contribute.
        restrict_batch(manager, "restricted-response.json", person)
        j.nav("الأداء")
        granted = performance_data(j)
        expect(j.page.locator("[data-completion-count]")).to_have_text("1 من 2" if language == "ar" else "1 of 2")
        assert granted["completion"]["completed"] == 1 and granted["completion"]["total"] == 2
        assert granted["speed"]["late"] == granted["speed"]["included"] == 1
        assert granted["metrics"]["containment_delay_seconds"]["median_seconds"] == 43 * 60
        assert granted["metrics"]["containment_delay_seconds"]["included"] == 1
        assert j.page.locator(".performance-duration-track span").count() == 2
        result["granted_measurements"] = {key: granted[key] for key in ("completion", "speed", "metrics")}
        result["outcomes"] = [
            "restricted response evidence contributed no timing, completion or SLA measurement",
            "missing response measurement was rendered as unavailable, not zero or success",
            "analyst opened the permitted case and saved a scoped evidence-review note through visible controls",
            "an explicit manager grant admitted the retained case and its 43-minute containment measurement",
        ]
        result["limits"] = "One semantic access condition, two language variants; isolated historical setup; no human participants."
