"""Calendar-aware operational decisions, not simulated human research.

Historical timestamps and records are explicit setup. Decisions, corrections,
follow-ups and report approvals use the interface; setup never counts as closure.
"""

import hashlib
import json
import sys
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from playwright.sync_api import expect

from scripts.local_services import local_worker_services
from socify.timeutils import utc_now
from tests.e2e import test_review_workflow as review_module
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_case_continuity_journeys import workflow
from tests.e2e.test_closed_performance_journeys import select_queue
from tests.e2e.test_followup_handoff_journeys import edit
from tests.e2e.test_investigation_link_journeys import choose, corrective_dialog, records
from tests.e2e.test_native_corrective_followup import approve, prepare
from tests.e2e.test_performance_decision_journeys import open_case, plain, save_note
from tests.e2e.test_performance_goal_journeys import counter, period
from tests.e2e.test_report_recovery_journeys import report, report_path
from tests.e2e.test_review_workflow import review_session
from tests.e2e.test_timeline_decision_journeys import local_input

ARTIFACTS = Path("artifacts/usability_campaign/calendar-decisions")
SCENARIOS = {
    "NEXT-13-cancelled-not-delivered": {
        "goal": "Assess delivery after a withdrawn request and advance the remaining active case.",
        "interpretation": "Cancellation is not successful delivery; one closed and one active operational case mean half complete.",
        "nearest": "test_performance_goal_journeys.py:performance-completed-credit; test_closed_performance_journeys.py:performance-closed-empty",
        "novelty": "Prior bodies count assignment completion or an empty closure queue, not cancelled-case exclusion from the creation cohort.",
    },
    "NEXT-14-calendar-aware-speed-choice": {
        "goal": "Choose the truly late case before assigning corrective work.",
        "interpretation": "A long weekend interval can meet business-hours SLA while a shorter continuous interval misses its target.",
        "nearest": "test_case_continuity_journeys.py:sla-business-calendar; test_investigation_link_journeys.py:corrective-closed-case-followup",
        "novelty": "Prior bodies save a calendar or edit an already chosen follow-up; this compares two calendars before choosing the appropriate case.",
    },
    "NEXT-15-closure-during-pause": {
        "goal": "Compare paused and unpaused closures and follow up only on the actual breach.",
        "interpretation": "A documented pause without resume ends at closure; later wall time cannot make that closed case late.",
        "nearest": "test_case_continuity_journeys.py:sla-pause-resume; test_performance_goal_journeys.py:performance-deadline-crossing",
        "novelty": "Prior pause is resumed on an active case; this has no resume before closure and checks a real retrospective decision.",
    },
    "NEXT-16-dst-repeated-hour": {
        "goal": "Review a response spanning a repeated local hour without losing the distinct instants.",
        "interpretation": "01:15 at -04:00 to 01:45 at -05:00 is ninety minutes, not thirty or zero.",
        "nearest": "test_case_continuity_journeys.py:sla-business-calendar; source_clock_offsets ingestion campaign",
        "novelty": "Calendar configuration and fixed-offset parsing do not exercise a user comparing repeated-hour evidence with measured SLA.",
    },
    "NEXT-33-impossible-response-chronology": {
        "goal": "Return an impossible response chronology for correction, then approve only the supported report.",
        "interpretation": "Containment before detection is unmeasured, not zero-speed success; inspect the retained evidence before correction.",
        "nearest": "test_report_review_journeys.py:test_report_review_has_meaningful_sections_and_identifiable_evidence; test_performance_decision_journeys.py:NEXT-12",
        "novelty": "Prior bodies inspect readable report sections or a missing closure timestamp, not negative cross-milestone chronology and independent corrective review.",
    },
}


def stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def context(j, case_id):
    j.case_id, j.case_url = case_id, f"{j.base}/cases/{case_id}"


def setup_case(j, database, title, created, *, existing=None, closed=None, calendar=None, budget=60, paused=None, cause=None, events=None):
    identifier = existing or j.page.evaluate("title => api('/api/cases',{method:'POST',body:{title}})", title)["id"]
    database.execute("UPDATE incident_cases SET title=?,created_at=? WHERE id=?", (title, stamp(created), identifier))
    if calendar:
        j.page.evaluate(
            """async ({id,calendar,budget}) => {
                const c=await api(`/api/cases/${id}`);
                await api(`/api/cases/${id}/sla`,{method:'POST',body:{version:c.version,minutes:budget,calendar,reason:'Documented investigation response agreement'}});
            }""",
            {"id": identifier, "calendar": calendar, "budget": budget},
        )
        database.execute(
            "UPDATE autopsy_records SET payload=json_set(payload,'$.configured_at',?),created_at=? WHERE case_id=? AND kind='workflow_sla'",
            (stamp(created), stamp(created), identifier),
        )
    if paused:
        action = j.page.evaluate(
            """async id => {const c=await api(`/api/cases/${id}`);return api(`/api/cases/${id}/sla/pause`,{method:'POST',body:{version:c.version,reason:'Vendor access unavailable; waiting period approved'}})}""",
            identifier,
        )
        database.execute("UPDATE autopsy_records SET payload=json_set(payload,'$.at',?),created_at=? WHERE id=?", (stamp(paused), stamp(paused), action["id"]))
    if cause:
        j.page.evaluate(
            "({id,cause}) => api(`/api/cases/${id}/records/root_cause`,{method:'POST',body:{category:'unknown',conclusion:cause}})",
            {"id": identifier, "cause": cause},
        )
    if events:
        j.page.evaluate(
            "({id,events}) => api(`/api/cases/${id}/imports`,{method:'POST',body:{filename:'response-clock-evidence.json',content:JSON.stringify(events)}})",
            {"id": identifier, "events": events},
        )
    if closed:
        database.execute("UPDATE incident_cases SET status='closed',closed_at=? WHERE id=?", (stamp(closed), identifier))
    return identifier


def dashboard(j, result, *, expected_speed=None):
    j.nav("الأداء")
    period(j, "all")
    if expected_speed is not None:
        assert plain(j.page.locator("[data-speed-value]").inner_text()) == expected_speed
    result["dashboard_before"] = j.page.locator("main").inner_text()
    shot(j, result, "decision")


def shot(j, result, name):
    path = ARTIFACTS / f"{result['scenario']}-{result['language']}-{name}.png"
    j.page.screenshot(path=str(path), full_page=True, animations="disabled")
    result.setdefault("screenshots", []).append(str(path))


def visit_history(j, identifier, result):
    j.nav("الأداء")
    period(j, "all")
    select_queue(j, "أغلقت خلال الفترة")
    open_case(j, identifier)
    j.click("link", "الاستجابة والتصعيد")
    summary = j.page.locator(".sla-summary")
    expect(summary).to_be_visible()
    data = workflow(j)["sla"]
    result.setdefault("reviewed_histories", []).append({"case_id": identifier, "visible_sla": summary.inner_text(), "verification": data})
    shot(j, result, f"case-{identifier}-sla")
    return data


def sla_value(j, label):
    return plain(j.page.locator(".sla-summary tr").filter(has=j.page.get_by_role("cell", name=j.text(label), exact=True)).locator("td").last.inner_text())


def follow_up(j, result, cause, title):
    dialog = corrective_dialog(j)
    dialog.locator("input[name=title]").fill(title)
    dialog.locator("input[name=due_at]").fill(local_input(j, stamp(utc_now() + timedelta(days=7))))
    choose(j, dialog, "root_cause_id", cause)
    j.click("button", "حفظ", dialog)
    saved = next(item for item in records(j, "corrective") if item["payload"]["title"] == title)
    assert saved["payload"]["root_cause_id"] == next(item["id"] for item in records(j, "root_cause") if item["payload"]["conclusion"] == cause)
    result["persisted_action"] = {"type": "linked corrective follow-up", "case_id": j.case_id, "record_id": saved["id"], "title": title}


def open_named_case(j, identifier, title):
    j.nav("إدارة القضايا")
    j.page.get_by_label(j.text("بحث"), exact=True).fill(title)
    j.click("button", "بحث")
    j.page.get_by_role("link", name=title, exact=True).click()
    j.settle()
    context(j, identifier)


def prepare_snapshot(j):
    if sys.platform != "win32":
        return prepare(j)
    # Store the actual snapshot without inventing renderer output on Windows.
    j.click("link", "التقارير والمراجعة")
    j.click("button", "إعداد تقرير جديد")
    return report_path(j)


def verify_metric_layout(j, result, state):
    metrics = j.page.locator(".response-metrics")
    expect(metrics.locator("pre")).to_have_count(0)
    text = metrics.inner_text()
    assert not any(token in text for token in ("_seconds", "negative interval excluded", '"milestones"', ": null"))
    if result["language"] == "en":
        assert not any("\u0600" <= character <= "\u06ff" for character in text)
    for width in (1440, 390):
        j.page.set_viewport_size({"width": width, "height": 1000})
        assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        assert metrics.evaluate("element => element.scrollWidth <= element.clientWidth")
        assert metrics.locator("td").evaluate_all(
            "cells => cells.every(cell => {const r=cell.getBoundingClientRect();return r.left>=0 && r.right<=innerWidth && cell.scrollWidth<=cell.clientWidth})"
        )
        # Layout assertions above use the normal viewport. Give a tall component
        # enough capture height so a full-component screenshot does not omit
        # offscreen painted content or acquire an overlaid sticky header.
        capture_height = max(1000, int(metrics.bounding_box()["height"]) + 120)
        j.page.set_viewport_size({"width": width, "height": capture_height})
        metrics.screenshot(path=str(ARTIFACTS / f"{result['scenario']}-{result['language']}-metrics-{state}-{width}.png"), animations="disabled")
        j.page.set_viewport_size({"width": width, "height": 1000})
    result.setdefault("metric_layout", []).append({"state": state, "widths": [1440, 390], "no_clipping": True, "visible_text": text})
    j.page.set_viewport_size({"width": 1440, "height": 1000})


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", list(SCENARIOS))
def test_calendar_decisions_preserve_evidenced_work(app, database, monkeypatch, language, scenario):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(review_module, "ARTIFACTS", ARTIFACTS)
    native_approval_blocked = scenario.startswith("NEXT-33") and sys.platform == "win32"
    service = local_worker_services(app.config) if scenario.startswith("NEXT-33") and not native_approval_blocked else nullcontext()
    with service, review_session(app, language, scenario) as (analyst, manager, result):
        result.update(
            human_participants=0,
            condition=SCENARIOS[scenario],
            initial_interpretation=SCENARIOS[scenario]["interpretation"],
            interpretation_kind="Scripted decision hypothesis based on visible labels; not observed human comprehension",
            setup_provenance="Authenticated API and database historical fixtures only; no simulated native report approval or closure",
            product_sha256={
                p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
                for p in ("socify/autopsy_workflow.py", "socify/soc_insights.py", "static/autopsy_operations.js", "static/soc-insights.js")
            },
            difficulties=[],
        )
        manager.login("manager@socify.local")
        context(manager, analyst.case_id)
        now = utc_now().replace(second=0, microsecond=0)
        continuous = {"mode": "24x7", "timezone": "UTC"}
        subject = manager
        if scenario.startswith("NEXT-13"):
            active = analyst.case_id
            cancelled = setup_case(manager, database, "Withdrawn duplicate request", now - timedelta(days=2))
            database.execute("UPDATE incident_cases SET status='cancelled' WHERE id=?", (cancelled,))
            setup_case(manager, database, "Delivered access investigation", now - timedelta(days=3), closed=now - timedelta(days=1))
            dashboard(manager, result)
            assert plain(manager.page.locator("[data-completion-count]").inner_text()) == ("1 من 2" if language == "ar" else "1 of 2")
            assert plain(manager.page.locator("[data-completion-value]").inner_text()) == "50%"
            assert counter(manager, "قضايا نشطة") == 1
            result["initial_action"] = "Inspect the withdrawn request through case search, then advance the remaining active case."
            open_named_case(manager, cancelled, "Withdrawn duplicate request")
            assert manager.state()["status"] == "cancelled"
            shot(manager, result, "withdrawn-history")
            manager.nav("الأداء")
            period(manager, "all")
            open_case(manager, active)
            save_note(manager, "The duplicate request was withdrawn; the active access investigation still needs evidence review before delivery.")
            result["persisted_action"] = {"type": "investigation note", "case_id": active}
            manager.nav("الأداء")
            period(manager, "all")
            assert plain(manager.page.locator("[data-completion-value]").inner_text()) == "50%"
            assert database.execute("SELECT status FROM incident_cases WHERE id=?", (cancelled,)).fetchone()[0] == "cancelled"
        elif scenario.startswith(("NEXT-14", "NEXT-15")):
            cause = "Response ownership requires review after the agreed target was missed"
            if scenario.startswith("NEXT-14"):
                friday = (now - timedelta(days=(now.weekday() - 4) % 7 + 7)).replace(hour=16, minute=30)
                long_start, long_end = friday, friday + timedelta(days=2, hours=17)
                business = {"mode": "business", "timezone": "UTC", "weekdays": [0, 1, 2, 3, 4], "start_hour": 9, "end_hour": 17, "holidays": []}
                on_time = setup_case(
                    manager, database, "Weekend access review", long_start, existing=analyst.case_id, closed=long_end, calendar=business, budget=90
                )
                late_start = now - timedelta(days=2)
                late = setup_case(
                    manager, database, "Continuous response ownership gap", late_start, closed=late_start + timedelta(hours=2), calendar=continuous, cause=cause
                )
                expected_elapsed, expected_pause = 3600, 0
                result["independent_expected_seconds"] = {
                    "business_work": 30 * 60 + 30 * 60,
                    "business_wall": (long_end - long_start).total_seconds(),
                    "continuous_work": 7200,
                }
            else:
                start = now - timedelta(days=5)
                on_time = setup_case(
                    manager,
                    database,
                    "Vendor wait resolved before closure",
                    start,
                    existing=analyst.case_id,
                    closed=start + timedelta(days=2),
                    calendar=continuous,
                    paused=start + timedelta(minutes=30),
                )
                late = setup_case(
                    manager, database, "Unpaused vendor response delay", start, closed=start + timedelta(days=2), calendar=continuous, cause=cause
                )
                expected_elapsed, expected_pause = 1800, 2 * 86400 - 1800
                result["independent_expected_seconds"] = {"paused_work": 1800, "excluded_wait": expected_pause, "unpaused_work": 2 * 86400}
            dashboard(manager, result, expected_speed="50%")
            result["initial_action"] = (
                "Open both completed cases, compare counted time and documented calendars or pauses, then follow up only on the breached case."
            )
            first = visit_history(manager, on_time, result)
            assert first["elapsed_work_seconds"] == expected_elapsed and first["paused_work_seconds"] == expected_pause
            assert first["remaining_work_seconds"] >= 0
            assert sla_value(manager, "الوقت المحتسب").startswith(str(expected_elapsed // 60) + " ")
            second = visit_history(manager, late, result)
            assert second["remaining_work_seconds"] < 0
            expect(manager.page.locator(".sla-summary")).to_contain_text(manager.text("مدة التجاوز"))
            follow_up(manager, result, cause, "Review response ownership at the next shift")
            assert database.execute("SELECT COUNT(*) FROM autopsy_records WHERE kind='corrective' AND case_id=?", (on_time,)).fetchone()[0] == 0
            manager.nav("الأداء")
            period(manager, "all")
            assert plain(manager.page.locator("[data-speed-value]").inner_text()) == "50%"
        elif scenario.startswith("NEXT-16"):
            start = datetime.fromisoformat("2026-11-01T01:15:00-04:00")
            end = datetime.fromisoformat("2026-11-01T01:45:00-05:00")
            events = [
                {"title": title, "timestamp": stamp(instant), "hostname": "DST-GATEWAY"}
                for title, instant in (("Gateway detection before clock change", start), ("Gateway containment after clock change", end))
            ]
            calendar = {"mode": "business", "timezone": "America/New_York", "weekdays": [0, 1, 2, 3, 6], "start_hour": 0, "end_hour": 4, "holidays": []}
            target = setup_case(
                manager, database, "Repeated-hour gateway response", start, existing=analyst.case_id, closed=end, calendar=calendar, budget=120, events=events
            )
            dashboard(manager, result, expected_speed="100%")
            result["independent_expected_seconds"] = (end.astimezone(UTC) - start.astimezone(UTC)).total_seconds()
            data = visit_history(manager, target, result)
            assert data["elapsed_work_seconds"] == 5400
            assert sla_value(manager, "الوقت المحتسب").startswith("90 ")
            result["initial_action"] = "Compare the two retained event instants with ninety counted minutes and record the clock-change review."
            manager.click("link", "التحقيق والخط الزمني")
            times = [manager.page.evaluate("v => formatTime(v)", stamp(value)) for value in (start, end)]
            assert times[0] != times[1]
            for value in times:
                expect(manager.page.locator("main")).to_contain_text(value)
            before = manager.page.evaluate("id => api(`/api/cases/${id}/timeline`)", target)
            shot(manager, result, "distinct-event-times")
            open_named_case(analyst, target, "Repeated-hour gateway response")
            analyst.click("link", "الاستجابة والتصعيد")
            analyst.click("button", "إنشاء مسودة مراجعة ما بعد الحادثة")
            manager.click("link", "الاستجابة والتصعيد")
            manager.click("button", "مراجعة المسودة")
            dialog = manager.page.get_by_role("dialog")
            summary = "01:15 -04:00 to 01:45 -05:00 is 05:15Z to 06:45Z, a 90-minute response within the 120-minute target."
            dialog.locator("textarea[name=executive_summary]").fill(summary)
            dialog.locator("textarea[name=lessons]").fill(
                "Compare the recorded offsets during clock changes rather than subtracting repeated wall-clock labels."
            )
            dialog.locator("textarea[name=limitations]").fill(
                "This review measures only the two retained gateway instants; it does not establish unobserved activity."
            )
            manager.click("button", "حفظ", dialog)
            review = workflow(manager)["postmortems"][0]
            assert review["payload"]["state"] == "reviewed" and review["payload"]["executive_summary"] == summary
            assert review["payload"]["generated_by"] != review["payload"]["reviewed_by"]
            assert manager.state()["status"] == "closed"
            expect(manager.page.locator("main")).to_contain_text(summary)
            after = manager.page.evaluate("id => api(`/api/cases/${id}/timeline`)", target)
            assert before == after
            result["persisted_action"] = {
                "type": "independent clock-change post-incident review",
                "case_id": target,
                "review_id": review["id"],
                "visible_distinct_times": times,
                "source_timeline_unchanged": True,
            }
        else:
            subject = analyst
            start = now - timedelta(days=1)
            target = setup_case(
                manager,
                database,
                "Gateway response chronology review",
                start,
                existing=analyst.case_id,
                events=[
                    {"title": "Detection confirmed at gateway", "timestamp": stamp(start), "hostname": "REVIEW-GATEWAY"},
                    {"title": "Containment confirmed at gateway", "timestamp": stamp(start + timedelta(minutes=20)), "hostname": "REVIEW-GATEWAY"},
                ],
            )
            analyst.page.evaluate(
                """async ({id,start,wrong}) => {
                    const c=await api(`/api/cases/${id}`), evidence=c.evidence[0].id;
                    for(const [title,phase,at] of [['Gateway detection','detection',start],['Gateway containment','containment',wrong]])
                        await api(`/api/cases/${id}/records/response`,{method:'POST',body:{title,phase,status:'succeeded',performed_by:state.user.id,performed_at:at,evidence_id:evidence,details:'Entered response milestone linked to retained gateway evidence'}});
                }""",
                {"id": target, "start": stamp(start), "wrong": stamp(start - timedelta(minutes=10))},
            )
            analyst.page.reload()
            analyst.settle()
            analyst.assessment("Gateway detection and containment documented; independent chronology review requested.")
            initial_path = prepare_snapshot(analyst)
            initial = report(analyst, initial_path)
            assert initial["payload"]["metrics"]["containment_delay_seconds"] is None
            manager.page.goto(manager.case_url)
            manager.settle()
            manager.click("link", "الاستجابة والتصعيد")
            manager.page.get_by_text(manager.text("قياسات الاستجابة وأساس حسابها"), exact=True).click()
            visible_metrics = manager.page.locator(".response-metrics")
            expect(visible_metrics.locator("[data-response-duration=containment_delay_seconds]")).to_have_text(manager.text("غير مقاس"))
            expect(visible_metrics).to_contain_text(manager.text("نهاية الفترة تسبق بدايتها؛ لم تُحسب المدة."))
            verify_metric_layout(manager, result, "invalid")
            result["resolved_observations"] = [
                "Raw JSON and untranslated issue codes were replaced with labelled durations, visible event times and translated exclusion reasons."
            ]
            result["initial_action"] = "Review contradictory timestamps against retained events, request correction, and withhold approval of the draft."
            shot(manager, result, "invalid-chronology")
            manager.click("link", "التقارير والمراجعة")
            manager.decision(
                "needs_followup",
                "Containment precedes detection in the entered milestone. Correct it against the retained gateway event at detection plus twenty minutes before approval.",
            )
            assert report(manager, initial_path)["state"] == "draft"
            analyst.page.reload()
            analyst.settle()
            analyst.click("link", "التحقيق والخط الزمني")
            expect(analyst.page.locator("main")).to_contain_text("Containment confirmed at gateway")
            shot(analyst, result, "supporting-evidence")
            analyst.click("link", "الاستجابة والتصعيد")
            dialog = edit(analyst, "Gateway containment")
            dialog.locator("input[name=performed_at]").fill(local_input(analyst, stamp(start + timedelta(minutes=20))))
            dialog.locator("textarea[name=details]").fill(
                "Corrected to the retained gateway containment event, twenty minutes after detection; prior entry was a transcription error."
            )
            analyst.click("button", "حفظ", dialog)
            assert workflow(analyst)["metrics"]["containment_delay_seconds"] == 1200
            analyst.page.locator(".response-metrics summary").click()
            expect(analyst.page.locator("[data-response-duration=containment_delay_seconds]")).to_have_text(
                analyst.page.evaluate("new Intl.NumberFormat(SOCifyLocale.language).format(1200)")
            )
            expect(analyst.page.locator(".response-metric-issues")).to_have_count(0)
            verify_metric_layout(analyst, result, "corrected")
            analyst.assessment("Chronology corrected against retained gateway evidence; containment followed detection by twenty minutes.")
            corrected_path = prepare_snapshot(analyst)
            manager.page.reload()
            manager.settle()
            if not native_approval_blocked:
                approve(manager)
            corrected = report(manager, corrected_path)
            assert corrected["payload"]["metrics"]["containment_delay_seconds"] == 1200
            if not native_approval_blocked:
                assert corrected["state"] == "approved" and corrected["formats"]
            else:
                assert corrected["state"] == "draft" and not corrected["formats"]
                result["native_approval"] = {
                    "status": "blocked",
                    "reason": "Windows cannot execute the isolated Linux report renderer; no stub or fabricated formats used.",
                    "ci_required": "Run this same test on Linux with the isolated native report service.",
                }
            assert report(manager, initial_path)["state"] == "draft"
            assert report(manager, initial_path)["payload"]["metrics"]["containment_delay_seconds"] is None
            assert manager.state()["status"] != "closed"
            result["persisted_action"] = {
                "type": "corrected evidenced milestone and retained snapshot"
                if native_approval_blocked
                else "corrected evidenced milestone and independent native report approval",
                "case_id": target,
                "previous_report": initial_path,
                "prepared_report": corrected_path,
                "containment_seconds": 1200,
            }
            subject = manager
        result["actual_outcome"] = result["persisted_action"]
        result["completion_claim"] = (
            "One scripted task completed in this language; historical fixture rows and intermediate clicks are not users or separate completions."
        )
        assert_accessible(subject.page)
        for width in (1440, 390):
            subject.page.set_viewport_size({"width": width, "height": 1000})
            assert subject.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            shot(subject, result, f"outcome-{width}")
    if native_approval_blocked:
        result["status"] = "partial_native_approval_blocked"
        result["completion_claim"] = "UI review and correction verified; full task remains incomplete until real native report approval succeeds on Linux."
        (ARTIFACTS / f"{scenario}-{language}.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        pytest.skip("UI correction and snapshots verified; native report approval requires the isolated Linux renderer")


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_response_metric_rendering_preserves_zero_missing_and_invalid_values(app, monkeypatch, language):
    """Component contracts are not additional user tasks or campaign scenarios."""
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(review_module, "ARTIFACTS", ARTIFACTS)
    with review_session(app, language, "response-metric-render-contract", create_case=False) as (j, _manager, result):
        result.update(kind="isolated rendering contract", human_participants=0, count_as_new_semantic_condition=False)
        j.page.evaluate(
            """() => {
                const metrics = autopsyResponseMetrics({
                    detection_delay_seconds:0,first_response_delay_seconds:0.000001,
                    acknowledgement_delay_seconds:5,containment_delay_seconds:null,
                    recovery_delay_seconds:-1,closure_delay_seconds:3600,
                    milestones:{detection:'2026-11-01T05:15:00Z',containment:null,first_evidenced_activity:'invalid'},
                    issues:['containment: negative interval excluded','recovery: future timestamp','acknowledgement: missing or invalid timestamp','unrecognized: unsupported condition']
                });
                metrics.open=true;
                document.querySelector('main').replaceChildren(panel(SOCifyLocale.text('قياسات مراحل الاستجابة'),metrics,true));
            }"""
        )
        for key, value in (("detection", 0), ("first_response", 0.000001), ("acknowledgement", 5), ("closure", 3600)):
            expected = j.page.evaluate("value => new Intl.NumberFormat(SOCifyLocale.language,{maximumFractionDigits:6}).format(value)", value)
            expect(j.page.locator(f"[data-response-duration={key}_delay_seconds]")).to_have_text(expected)
        for key in ("containment", "recovery"):
            expect(j.page.locator(f"[data-response-duration={key}_delay_seconds]")).to_have_text(j.text("غير مقاس"))
        expect(j.page.locator(".response-metric-issues")).to_contain_text(j.text("وقت مستقبلي؛ لا يدخل القياسات المؤكدة."))
        expect(j.page.locator(".response-metric-issues")).to_contain_text(j.text("وقت مفقود أو غير صالح؛ لا يمكن حساب المدة."))
        expect(j.page.locator(".response-metric-issues")).to_contain_text(j.text("تعذر احتساب هذا القياس؛ راجع أوقات الاستجابة."))
        summary = j.page.locator(".response-metrics summary")
        summary.focus()
        summary.press("Enter")
        expect(j.page.locator(".response-metrics")).to_have_js_property("open", False)
        summary.press("Enter")
        expect(j.page.locator(".response-metrics")).to_have_js_property("open", True)
        summary.press("Tab")
        expect(j.page.locator(".response-metric-durations")).to_be_focused()
        j.page.evaluate("document.activeElement?.blur()")
        result["keyboard"] = "Enter closes and opens the metric details; Tab reaches the labelled table region."
        verify_metric_layout(j, result, "boundary-contract")
        assert_accessible(j.page)
        result["outcomes"] = [
            "measured zero and microsecond preserved",
            "missing and negative values remain unmeasured",
            "all exclusion reasons readable",
            "AR/EN desktop and mobile layout",
        ]
