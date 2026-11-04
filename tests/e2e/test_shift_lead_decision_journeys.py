"""Distinct shift-lead decisions, followed by retained interface actions.

Historical dates, populations and source peers are explicit fixtures. These are
scripted task simulations, not observations of human participants.
"""

import hashlib
import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from playwright.sync_api import expect

from scripts.local_services import local_worker_services
from socify.timeutils import utc_now
from tests.e2e import test_review_workflow as review_module
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_case_continuity_journeys import workflow
from tests.e2e.test_case_summary_recovery_journeys import member_form
from tests.e2e.test_closed_performance_journeys import select_queue
from tests.e2e.test_investigation_link_journeys import corrective_dialog, records
from tests.e2e.test_native_corrective_followup import approve, pdf_link, prepare
from tests.e2e.test_performance_decision_journeys import describe, new_history, open_case, plain, policy_fixture, prepare_review, save_note, stamp
from tests.e2e.test_performance_goal_journeys import counter, delivery, period
from tests.e2e.test_report_recovery_journeys import report, report_path
from tests.e2e.test_review_workflow import review_session
from tests.e2e.test_source_goal_journeys import create_connector
from tests.e2e.test_source_lifecycle_journeys import source_row
from tests.integration.test_source_https_transport import tls_source  # noqa: F401 -- controlled TLS peer fixture

ARTIFACTS = Path("artifacts/usability_campaign/shift-lead-decisions")
SCENARIOS = [
    "NEXT-17-median-outlier-choice",
    "NEXT-18-cross-year-activity",
    "NEXT-25-unassigned-case-cohort",
    "NEXT-28-quiet-period-old-backlog",
    "NEXT-35-weighted-team-speed",
]
NOVELTY = {
    "NEXT-17": "Prior member/period filters do not distinguish a median bottleneck from a single extreme duration; this ends with a scoped corrective follow-up.",
    "NEXT-18": "Prior period filtering and history pagination do not distinguish matching month/day activity across years or reconcile chart and daily totals before choosing a case.",
    "NEXT-22": "Prior wrong-case source delivery and stale report retries do not cover a correctly scoped source blocked by a closed lifecycle and recovered through authorized reopening.",
    "NEXT-25": "Prior task handoff credit does not reconcile team case cohorts with active and closed unassigned cases before assigning an owner.",
    "NEXT-28": "Prior empty personal workspaces differ from an empty recent activity period with an older critical overdue investigation still requiring action.",
    "NEXT-35": "Prior missing SLA samples differ from unequal fully measured member populations: 1/1 and 1/19 must combine to 2/20, followed by a late-case corrective action.",
}


def evidence_context(monkeypatch):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(review_module, "ARTIFACTS", ARTIFACTS)


def describe_decision(result, scenario):
    describe(result, scenario)
    result["novelty_review"] = NOVELTY[scenario[:7]]
    result["persona"] = "Incoming shift lead reading operational evidence before acting"
    result["clean_round_claimed"] = False
    result["scenario_count"] = "One semantic condition; Arabic and English are variants, not separate users"


def capture(j, result, suffix="outcome"):
    assert_accessible(j.page)
    assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    result["final_case_id"] = j.case_id
    j.page.screenshot(path=str(ARTIFACTS / f"{result['scenario']}-{result['language']}-{suffix}.png"), full_page=True)


def focus_case(j, identifier):
    open_case(j, identifier)
    assert j.state()["id"] == identifier


def follow_up(j, title):
    dialog = corrective_dialog(j)
    dialog.locator("input[name=title]").fill(title)
    dialog.locator("input[name=due_at]").fill((utc_now() + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M"))
    j.click("button", "حفظ", dialog)
    saved = next(row for row in records(j, "corrective") if row["payload"]["title"] == title)
    assert saved["payload"]["status"] == "open"
    return saved


def duration_history(j, database, created, detection_minutes, containment_minutes, title):
    identifier = new_history(j, database, title, created - timedelta(hours=1))
    j.page.evaluate(
        """async ({id,start,detection,containment}) => {
            const detected=new Date(Date.parse(start)+detection*60000).toISOString();
            const contained=new Date(Date.parse(detected)+containment*60000).toISOString();
            await api(`/api/cases/${id}/imports`,{method:'POST',body:{filename:'retained-stage-times.json',content:JSON.stringify([
                {title:'First retained gateway activity',timestamp:start,hostname:'SHIFT-GATEWAY'},
                {title:'Detection timestamp',timestamp:detected,hostname:'SHIFT-GATEWAY'},
                {title:'Containment timestamp',timestamp:contained,hostname:'SHIFT-GATEWAY',action:'blocked'}
            ])}});
            const evidence=(await api(`/api/cases/${id}`)).evidence[0].id;
            const asset=await api(`/api/cases/${id}/records/asset`,{method:'POST',body:{name:'SHIFT-GATEWAY',type:'identity_provider',role:'affected',evidence_id:evidence,details:'Gateway in the retained records'}});
            await api(`/api/cases/${id}/records/foothold`,{method:'POST',body:{title:'Earliest retained gateway activity',asset_id:asset.id,first_observed_at:start,confidence:80,limitations:'Earliest retained evidence only',evidence_id:evidence}});
            for(const [phase,time] of [['detection',detected],['containment',contained]]) {
                await api(`/api/cases/${id}/records/response`,{method:'POST',body:{title:`${phase} timestamp`,phase,status:'succeeded',performed_by:state.user.id,performed_at:time,evidence_id:evidence,details:'Time corroborated by retained gateway records'}});
            }
        }""",
        {"id": identifier, "start": stamp(created), "detection": detection_minutes, "containment": containment_minutes},
    )
    database.execute(
        "UPDATE incident_cases SET status='closed',closed_at=? WHERE id=?",
        (stamp(created + timedelta(minutes=detection_minutes + containment_minutes + 60)), identifier),
    )
    return identifier


def create_unassigned(j, database, title, created, *, closed=False):
    case = j.page.evaluate("title => api('/api/cases',{method:'POST',body:{title,assignee:null}})", title)
    database.execute("UPDATE incident_cases SET created_at=? WHERE id=?", (stamp(created), case["id"]))
    if closed:
        database.execute("UPDATE incident_cases SET status='closed',closed_at=? WHERE id=?", (stamp(created + timedelta(hours=1)), case["id"]))
    return case["id"]


def attention(j, label):
    return int(plain(j.page.locator(".performance-attention").get_by_text(label, exact=True).locator("+ dd").inner_text()))


def team_row_counts(j, name):
    cells = delivery(j).get_by_role("row").filter(has=j.page.get_by_role("link", name=name, exact=True)).get_by_role("cell")
    return [int(plain(cells.nth(index).inner_text())) for index in (2, 3, 4)]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", SCENARIOS)
def test_shift_lead_acts_on_the_relevant_population(app, database, monkeypatch, language, scenario):
    evidence_context(monkeypatch)
    with review_session(app, language, scenario) as (j, manager, result):
        describe_decision(result, scenario)
        manager.login("manager@socify.local")
        manager.case_id, manager.case_url = j.case_id, j.case_url
        now = utc_now().replace(second=0, microsecond=0)
        analyst = j.page.evaluate("state.user.id")
        analyst_name = j.page.evaluate("state.user.name")
        subject = manager
        if scenario.startswith("NEXT-17"):
            histories = [
                duration_history(j, database, now - timedelta(days=3), detect, contain, f"Stage review {detect} minutes")
                for detect, contain in [(2, 5), (3, 6), (120, 7)]
            ]
        elif scenario.startswith("NEXT-18"):
            latest = (now - timedelta(days=3)).replace(day=1, hour=9, minute=0)
            previous = latest.replace(year=latest.year - 1)
            database.execute("UPDATE incident_cases SET created_at=?,title='Latest annual gateway burst' WHERE id=?", (stamp(latest), j.case_id))
            for index in range(2):
                new_history(j, database, f"Latest annual companion {index + 1}", latest + timedelta(minutes=index + 1))
                new_history(j, database, f"Prior-year gateway review {index + 1}", previous, closed=previous + timedelta(hours=1))
        elif scenario.startswith("NEXT-25"):
            unassigned = create_unassigned(manager, database, "Unclaimed gateway investigation", now - timedelta(days=1))
            unassigned_closed = create_unassigned(manager, database, "Historical unassigned closure", now - timedelta(days=2), closed=True)
        elif scenario.startswith("NEXT-28"):
            subject = j
            database.execute(
                "UPDATE incident_cases SET created_at=?,sla_due_at=?,severity='critical' WHERE id=?",
                (stamp(now - timedelta(days=40)), stamp(now - timedelta(days=5)), j.case_id),
            )
            j.page.evaluate(
                """({id,time}) => api(`/api/cases/${id}/imports`,{method:'POST',body:{filename:'older-critical-evidence.json',content:JSON.stringify([{title:'Unresolved gateway access review',timestamp:time,hostname:'OLD-CRITICAL-GATEWAY'}])}})""",
                {"id": j.case_id, "time": stamp(now - timedelta(days=30))},
            )
        else:
            database.execute(
                "INSERT INTO users(email,password_hash,name,name_ar,name_en,role,team,workspace_id,created_at) SELECT 'shift-second@socify.local',password_hash,'Second shift analyst','محلل الوردية الثانية','Second shift analyst','analyst',team,workspace_id,created_at FROM users WHERE id=?",
                (analyst,),
            )
            second = database.execute("SELECT id FROM users WHERE email='shift-second@socify.local'").fetchone()[0]
            database.execute("INSERT INTO workspace_memberships(workspace_id,user_id,role,created_at) VALUES(1,?,'analyst',?)", (second, stamp(now)))
            second_name = "محلل الوردية الثانية" if language == "ar" else "Second shift analyst"
            database.execute("UPDATE incident_cases SET created_at=? WHERE id=?", (stamp(now - timedelta(days=2)), j.case_id))
            policy_fixture(manager, j.case_id, 60)
            database.execute(
                "UPDATE incident_cases SET status='closed',closed_at=? WHERE id=?", (stamp(now - timedelta(days=2) + timedelta(minutes=30)), j.case_id)
            )
            histories = []
            for index in range(19):
                item = manager.page.evaluate(
                    "({title,assignee}) => api('/api/cases',{method:'POST',body:{title,assignee}})",
                    {"title": f"Second analyst retained review {index + 1}", "assignee": second},
                )
                database.execute("UPDATE incident_cases SET created_at=? WHERE id=?", (stamp(now - timedelta(days=2)), item["id"]))
                policy_fixture(manager, item["id"], 60)
                database.execute(
                    "UPDATE incident_cases SET status='closed',closed_at=? WHERE id=?",
                    (stamp(now - timedelta(days=2) + timedelta(minutes=30 if index == 0 else 120)), item["id"]),
                )
                histories.append(item["id"])

        subject.nav("الأداء")
        period(subject, "all" if scenario.startswith("NEXT-18") else "7")
        result["visible_decision_basis"] = subject.page.locator(".performance-view").inner_text()
        capture(subject, result, "decision")
        if scenario.startswith("NEXT-17"):
            durations = subject.page.locator(".performance-duration-row")
            assert plain(durations.nth(0).locator("strong").inner_text()).startswith("3 ")
            assert plain(durations.nth(2).locator("strong").inner_text()).startswith("6 ")
            for index in (0, 2):
                assert plain(durations.nth(index).locator(".performance-sample").inner_text()).endswith("3 من 3" if language == "ar" else "3 of 3")
            result["decision"] = (
                "Typical containment is six minutes versus three-minute detection; separately inspect the 120-minute detection exception without calling it typical."
            )
            select_queue(subject, "أغلقت خلال الفترة")
            focus_case(subject, histories[1])
            follow_up(subject, "Review the routine six-minute containment handoff without generalizing the detection exception")
            assert subject.state()["status"] == "closed"
            subject.nav("الأداء")
            period(subject, "7")
            select_queue(subject, "أغلقت خلال الفترة")
            focus_case(subject, histories[-1])
            subject.click("link", "التحقيق والخط الزمني")
            earliest = subject.page.locator(".record-card").filter(
                has=subject.page.get_by_role("heading", name="Earliest retained gateway activity", exact=True)
            )
            expect(earliest).to_be_visible()
            result["earliest_evidence_read"] = earliest.inner_text()
            subject.click("link", "الاستجابة والتصعيد")
            detected = subject.page.locator(".record-card").filter(has=subject.page.get_by_role("heading", name="detection timestamp", exact=True))
            expect(detected).to_be_visible()
            result["detection_evidence_read"] = detected.inner_text()
            assert workflow(subject)["metrics"]["detection_delay_seconds"] == 7200
            follow_up(subject, "Review the exceptional 120-minute detection delay separately from routine containment")
            assert subject.state()["status"] == "closed"
        elif scenario.startswith("NEXT-18"):
            subject.page.locator(".performance-data > summary").click()
            rows = subject.page.locator(".performance-data tbody tr")
            assert rows.count() == 2
            for date, opened, closed in [(previous.date().isoformat(), 2, 2), (latest.date().isoformat(), 3, 0)]:
                cells = rows.filter(has=subject.page.get_by_role("cell", name=date, exact=True)).get_by_role("cell")
                assert [int(plain(cells.nth(index).inner_text())) for index in (1, 2)] == [opened, closed]
            totals = subject.page.locator(".performance-trend > .performance-legend strong").all_inner_texts()
            assert [int(plain(value)) for value in totals] == [5, 2]
            result["decision"] = (
                f"Daily dates distinguish the {latest.year} burst of three from {previous.year}; continue the latest named gateway investigation."
            )
            focus_case(subject, j.case_id)
            save_note(
                subject,
                f"Review the {latest.date().isoformat()} gateway burst separately from the same calendar day in {previous.year}; latest opening count is three.",
            )
            subject.click("link", "التقارير والمراجعة")
            subject.click("button", "إعداد تقرير جديد")
            snapshot = report(subject, report_path(subject))["payload"]
            assert snapshot["case"]["title"] == "Latest annual gateway burst"
            assert str(latest.year) in json.dumps(snapshot["records"]["war_room"])
        elif scenario.startswith("NEXT-25"):
            assert counter(subject, "قضايا نشطة") == 2 and counter(subject, "أغلقت خلال الفترة") == 1
            assert attention(subject, "قضايا دون مسؤول" if language == "ar" else "Unassigned cases") == 1
            assert team_row_counts(subject, analyst_name)[:2] == [1, 0]
            assert team_row_counts(subject, subject.page.evaluate("state.user.name"))[:2] == [0, 0]
            result["decision"] = (
                "The unclaimed active case contributes to team work but no member credit; assign it to the eligible analyst without crediting the historical unassigned closure."
            )
            focus_case(subject, unassigned)
            form = member_form(subject, analyst_name)
            form.locator("[name=responsibility]").fill(subject.page.evaluate("caseResponsibilityLabel('owner')"))
            subject.click("button", "حفظ", form)
            assert subject.state()["assignee"] == analyst
            subject.nav("الأداء")
            assert counter(subject, "قضايا نشطة") == 2 and counter(subject, "أغلقت خلال الفترة") == 1
            assert attention(subject, "قضايا دون مسؤول" if language == "ar" else "Unassigned cases") == 0
            assert team_row_counts(subject, analyst_name)[:2] == [2, 0]
            assert database.execute("SELECT assignee FROM incident_cases WHERE id=?", (unassigned_closed,)).fetchone()[0] is None
            delivery(subject).get_by_role("link", name=analyst_name, exact=True).click()
            subject.settle()
            assert counter(subject, "قضايا نشطة") == 2
        elif scenario.startswith("NEXT-28"):
            expect(subject.page.locator("[data-completion-value]")).to_have_text("—")
            assert counter(subject, "قضايا نشطة") == 1 and counter(subject, "أغلقت خلال الفترة") == 0
            expect(subject.page.locator(".performance-chart-empty")).to_be_visible()
            assert attention(subject, "تجاوزت موعد القضية" if language == "ar" else "Past case deadline") == 1
            critical = subject.page.locator(".performance-severity-list li").filter(has=subject.page.locator(".severity.critical"))
            assert plain(critical.locator("strong").inner_text()) == "1"
            result["decision"] = "A quiet recent chart does not clear the older overdue critical investigation; resume its retained evidence review."
            focus_case(subject, j.case_id)
            subject.click("link", "السجلات والأدلة")
            expect(subject.page.get_by_role("cell", name="Unresolved gateway access review", exact=True)).to_be_visible()
            subject.transition("investigating")
            save_note(
                subject, "Resume the overdue critical gateway review using the retained older evidence; no recent case activity is not a closure decision."
            )
            assert subject.state()["status"] == "investigating" and subject.state()["severity"] == "critical"
        else:
            assert plain(subject.page.locator("[data-speed-value]").inner_text()) == "10%"
            assert plain(subject.page.locator(".performance-speed .performance-basis").inner_text()).endswith("20 من 20" if language == "ar" else "20 of 20")
            result["decision"] = (
                "Team compliance is two of twenty; inspect the second analyst's eighteen late cases, not an unweighted average of individual percentages."
            )
            delivery(subject).get_by_role("link", name=analyst_name, exact=True).click()
            subject.settle()
            assert plain(subject.page.locator("[data-speed-value]").inner_text()) == "100%"
            assert counter(subject, "أغلقت خلال الفترة") == 1
            subject.click("link", "الفريق", subject.page.locator(".channel-tabs"))
            delivery(subject).get_by_role("link", name=second_name, exact=True).click()
            subject.settle()
            assert plain(subject.page.locator("[data-speed-value]").inner_text()) == "5%"
            assert counter(subject, "أغلقت خلال الفترة") == 19
            select_queue(subject, "أغلقت خلال الفترة")
            focus_case(subject, histories[-1])
            subject.click("link", "الاستجابة والتصعيد")
            overdue = subject.page.locator(".sla-summary tr").filter(has=subject.page.get_by_role("cell", name=subject.text("مدة التجاوز"), exact=True))
            assert plain(overdue.get_by_role("cell").nth(1).inner_text()).startswith("60 ")
            result["chosen_case_sla"] = subject.page.locator(".sla-summary").inner_text()
            follow_up(subject, "Review the evidenced late-response workload for the second shift")
            subject.nav("الأداء")
            subject.click("link", "الفريق", subject.page.locator(".channel-tabs"))
            period(subject, "7")
            assert plain(subject.page.locator("[data-speed-value]").inner_text()) == "10%"
            assert team_row_counts(subject, analyst_name)[1] == 1 and team_row_counts(subject, second_name)[1] == 19
        result["outcomes"] = [
            "visible population and scope inspected",
            "decision followed by a persisted interface action",
            "unrelated history and attribution preserved",
        ]
        capture(subject, result)


@pytest.mark.e2e
@pytest.mark.skipif(sys.platform != "linux", reason="Requires the actual isolated Linux report service")
@pytest.mark.parametrize("language", ["ar", "en"])
def test_source_owner_reopens_closed_work_before_receiving_later_evidence(app, monkeypatch, tls_source, language):  # noqa: F811 -- imported fixture
    evidence_context(monkeypatch)
    monkeypatch.setenv("SOCIFY_SOURCE_ALLOWLIST", "siem.example")
    scenario = "NEXT-22-pull-into-closed-case"
    tls_source["responses"]["body"] = (
        json.dumps({"external_id": "later-review-1", "title": "Later gateway evidence", "hostname": "LATER-GATEWAY"}).encode() + b"\n"
    )
    with local_worker_services(app.config), review_session(app, language, scenario) as (j, manager, result):
        describe_decision(result, scenario)
        manager.login("manager@socify.local")
        manager.case_id, manager.case_url = j.case_id, j.case_url
        manager.page.goto(j.case_url)
        manager.settle()
        create_connector(manager, tls_source["url"] + "/events")
        prepare_review(j)
        manager.page.goto(j.case_url + "?tab=reports")
        manager.settle()
        approve(manager)
        prior_path = report_path(manager)
        prior = report(manager, prior_path)
        prior_pdf = pdf_link(manager).get_attribute("href")
        with manager.page.expect_download() as download:
            pdf_link(manager).click()
        prior_bytes = Path(download.value.path()).read_bytes()
        assert prior_bytes.startswith(b"%PDF-")
        manager.decision("closed", "Independent review accepted the report and retained maintenance evidence")
        before = manager.state()
        manager.click("link", "السجلات والأدلة")
        pull = source_row(manager).get_by_role("button", name=manager.text("سحب السجلات الآن"), exact=True)
        if pull.count() and pull.is_enabled():
            with manager.page.expect_response(lambda response: response.url.endswith("/pull") and response.request.method == "POST") as blocked:
                pull.click()
            manager.settle()
            assert blocked.value.status in {403, 409, 422}
            expect(manager.page.locator("#global-message")).to_be_visible()
            result["closed_pull_observation"] = manager.page.locator("#global-message").inner_text()
        else:
            if pull.count():
                expect(pull).to_be_disabled()
            result["closed_pull_observation"] = "Closed case offers no enabled source pull control"
        assert manager.state()["version"] == before["version"] and manager.state()["evidence"] == before["evidence"]
        assert report(manager, prior_path)["payload"] == prior["payload"]
        assert not tls_source["requests"]
        capture(manager, result, "closed-source")
        result["decision"] = (
            "Later evidence requires authorized reopening; keep the approved closed report unchanged and prepare a separate reviewable snapshot."
        )
        manager.transition("reopened")
        manager.click("link", "السجلات والأدلة")
        with manager.page.expect_response(lambda response: response.url.endswith("/pull") and response.request.method == "POST") as delivered:
            manager.click("button", "سحب السجلات الآن", source_row(manager))
        assert delivered.value.status == 200 and delivered.value.json()["accepted"] == 1
        expect(manager.page.get_by_role("cell", name="Later gateway evidence", exact=True)).to_be_visible()
        retained = manager.state()
        with manager.page.expect_response(lambda response: response.url.endswith("/pull") and response.request.method == "POST") as repeated:
            manager.click("button", "سحب السجلات الآن", source_row(manager))
        assert repeated.value.json()["accepted"] == 0 and repeated.value.json()["skipped"] == 1
        assert manager.state()["version"] == retained["version"] and manager.state()["evidence"] == retained["evidence"]
        latest_path = prepare(manager)
        latest = report(manager, latest_path)
        assert latest_path != prior_path and latest["sha256"] != prior["sha256"]
        assert len(latest["payload"]["imports"]) == len(prior["payload"]["imports"]) + 1
        assert report(manager, prior_path)["payload"] == prior["payload"]
        with manager.page.expect_download() as download:
            manager.page.locator(f'a[href="{prior_pdf}"]').click()
        assert Path(download.value.path()).read_bytes() == prior_bytes
        result["original_pdf_sha256"] = hashlib.sha256(prior_bytes).hexdigest()
        result["outcomes"] = [
            "closed investigation remained unchanged",
            "authorized UI reopening preceded real TLS delivery",
            "repeat delivery did not duplicate evidence",
            "new reviewable report preserved the approved snapshot and PDF",
        ]
        result["transport_limit"] = "Controlled local TLS peer, not an external vendor SIEM; real isolated native report worker, no fabricated PDF"
        capture(manager, result)
