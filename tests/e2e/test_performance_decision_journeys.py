"""Follow distinct dashboard decisions into retained investigation work.

Prepared histories are fixtures, never counted as user completions. The visible
decision trace is a scripted simulation, not evidence of human comprehension.
"""

import hashlib
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from playwright.sync_api import expect

from scripts.local_services import local_worker_services
from socify.timeutils import utc_now
from tests.e2e import test_review_workflow as review_module
from tests.e2e.test_batch_boundary_journeys import upload_logs
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_case_continuity_journeys import panel, record_dialog, workflow
from tests.e2e.test_closed_performance_journeys import select_queue
from tests.e2e.test_investigation_link_journeys import note_dialog, records
from tests.e2e.test_native_corrective_followup import approve, pdf_link, prepare
from tests.e2e.test_performance_goal_journeys import counter, period
from tests.e2e.test_report_recovery_journeys import report, report_path
from tests.e2e.test_report_sharing_journeys import open_preview
from tests.e2e.test_review_workflow import review_session

ARTIFACTS = Path("artifacts/usability_campaign/performance-decision-review")
SCENARIOS = [
    "NEXT-01-cohort-versus-closure-flow",
    "NEXT-02-sla-partial-measurement",
    "NEXT-03-implicit-deadline-not-proof",
    "NEXT-04-zero-versus-missing-response",
    "NEXT-05-severity-not-alert-volume",
    "NEXT-09-keyboard-chart-to-action",
    "NEXT-12-nonempty-unmeasurable-history",
]


def stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def plain(value):
    return value.translate(str.maketrans("٠١٢٣٤٥٦٧٨٩٫٪", "0123456789.%")).replace("\u061c", "").replace("\u200e", "").replace("\u200f", "")


def evidence_context(monkeypatch):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(review_module, "ARTIFACTS", ARTIFACTS)


def describe(result, scenario):
    head = Path(".git/HEAD").read_text().strip()
    if head.startswith("ref: "):
        reference = head.removeprefix("ref: ")
        ref_path = Path(".git") / reference
        head = (
            ref_path.read_text().strip()
            if ref_path.exists()
            else next(line.split()[0] for line in Path(".git/packed-refs").read_text().splitlines() if line.endswith(" " + reference))
        )
    result.update(
        head=head,
        production_files_sha256={
            path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
            for path in (
                "socify/soc_insights.py",
                "socify/autopsy_workflow.py",
                "socify/autopsy_reports.py",
                "socify/autopsy_report_render.py",
                "static/soc-insights.js",
                "static/comic-workspace.css",
                "static/autopsy_reports.js",
                "static/localization.js",
            )
        },
        persona="New analyst or shift lead making a scoped operational decision",
        human_participants=0,
        setup_provenance="Historical records prepared through authenticated API and timestamp fixtures; no setup row counts as a user or UI completion",
        semantic_condition=scenario,
        interpretation_kind="Scripted task interpretation checked against visible labels and independent retained-state assertions; no human comprehension claim",
    )


def new_history(j, database, title, created, *, closed=None, severity="medium"):
    item = j.page.evaluate("title => api('/api/cases',{method:'POST',body:{title}})", title)
    database.execute("UPDATE incident_cases SET created_at=?,severity=? WHERE id=?", (stamp(created), severity, item["id"]))
    if closed:
        database.execute("UPDATE incident_cases SET status='closed',closed_at=? WHERE id=?", (stamp(closed), item["id"]))
    return item["id"]


def policy_fixture(j, case_id, minutes):
    j.page.evaluate(
        """async ({id,minutes}) => {
            const c=await api(`/api/cases/${id}`);
            await api(`/api/cases/${id}/sla`, {method:'POST',body:{version:c.version,minutes,calendar:{mode:'24x7',timezone:'UTC'},reason:'Agreed response target in retained history'}});
        }""",
        {"id": case_id, "minutes": minutes},
    )


def tab_to(j, target):
    for _ in range(180):
        if target.evaluate("element => element === document.activeElement"):
            return
        j.page.keyboard.press("Tab")
    raise AssertionError("The intended visible control could not be reached with Tab")


def open_case(j, case_id, *, keyboard=False):
    target = j.page.locator(f"#performance-cases a[href='/cases/{case_id}']")
    if keyboard:
        tab_to(j, target)
        target.press("Enter")
    else:
        target.click()
    j.settle()
    j.case_id, j.case_url = case_id, f"{j.base}/cases/{case_id}"
    assert j.state()["id"] == case_id


def save_note(j, body, *, keyboard=False):
    if keyboard:
        link = j.page.get_by_role("link", name=j.text("التحقيق والخط الزمني"), exact=True)
        tab_to(j, link)
        link.press("Enter")
        j.settle()
        label = j.page.evaluate("SOCifyLocale.template`إضافة ${autopsyLabel('war_room')}`")
        add = j.page.get_by_role("button", name=label, exact=True)
        tab_to(j, add)
        add.press("Enter")
        dialog = j.page.get_by_role("dialog")
        dialog.locator("input[name=title]").fill("Next shift investigation decision")
    else:
        j.click("link", "التحقيق والخط الزمني")
        dialog = note_dialog(j)
    dialog.locator("textarea[name=body]").fill(body)
    if keyboard:
        save = dialog.get_by_role("button", name=j.text("حفظ"), exact=True)
        tab_to(j, save)
        save.press("Enter")
        j.settle()
    else:
        j.click("button", "حفظ", dialog)
    assert any(row["payload"]["body"] == body for row in records(j, "war_room"))


def configure_policy(j):
    j.click("link", "الاستجابة والتصعيد")
    form = panel(j, "SLA وجمع الأدلة ومراجعة ما بعد الحادثة").locator("form").filter(has=j.page.locator("input[name=minutes]"))
    form.locator("input[name=minutes]").fill("120")
    form.locator("input[name=reason]").fill("Agreed target for this active investigation after reviewing measurement coverage")
    j.click("button", "حفظ", form)
    assert workflow(j)["sla"]["configured"] and workflow(j)["sla"]["policy"]["minutes"] == 120
    expect(j.page.locator(".sla-summary")).to_contain_text(j.text("الوقت المتبقي"))


def capture(j, result):
    assert_accessible(j.page)
    assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    result["final_case_id"] = j.case_id
    result["outcomes"] = ["visible metric scope inspected", "intended case reached", "supported investigation action persisted"]
    j.page.screenshot(path=str(ARTIFACTS / f"{result['scenario']}-{result['language']}-outcome.png"), full_page=True)


def prepare_detection_history(j, database, case_id, start, *, closed=False):
    j.page.evaluate(
        """async ({id,start}) => {
            await api(`/api/cases/${id}/imports`,{method:'POST',body:{filename:'response-confirmation.json',content:JSON.stringify([
                {title:'Gateway detection confirmed',timestamp:start,hostname:'REVIEW-GATEWAY'},
                {title:'Gateway session containment confirmed',timestamp:new Date(Date.parse(start)+3600000).toISOString(),hostname:'REVIEW-GATEWAY',action:'blocked'}
            ])}});
            const evidence=(await api(`/api/cases/${id}`)).evidence[0].id;
            const asset=await api(`/api/cases/${id}/records/asset`,{method:'POST',body:{name:'REVIEW-GATEWAY',type:'identity_provider',role:'affected',evidence_id:evidence,details:'Gateway recorded in the retained event'}});
            await api(`/api/cases/${id}/records/foothold`,{method:'POST',body:{title:'First evidenced gateway activity',asset_id:asset.id,first_observed_at:start,confidence:80,limitations:'Earliest retained activity only',evidence_id:evidence}});
            await api(`/api/cases/${id}/records/response`,{method:'POST',body:{title:'Gateway detection confirmed',phase:'detection',status:'succeeded',performed_by:state.user.id,performed_at:start,evidence_id:evidence,details:'Timestamp confirmed against the gateway record'}});
        }""",
        {"id": case_id, "start": stamp(start)},
    )
    if closed:
        database.execute("UPDATE incident_cases SET status='closed',closed_at=? WHERE id=?", (stamp(start + timedelta(hours=1)), case_id))


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", SCENARIOS)
def test_dashboard_decision_advances_scoped_work(app, database, monkeypatch, language, scenario):
    evidence_context(monkeypatch)
    with review_session(app, language, scenario) as (j, manager, result):
        describe(result, scenario)
        now = utc_now().replace(second=0, microsecond=0)
        original_id = j.case_id
        manager.login("manager@socify.local")
        subject = manager if scenario.startswith(("NEXT-01", "NEXT-02", "NEXT-03", "NEXT-12")) else j
        manager.case_id, manager.case_url = original_id, j.case_url
        target = original_id
        if scenario.startswith("NEXT-01"):
            target = new_history(j, database, "Oldest new gateway case", now - timedelta(days=3))
            j.page.evaluate(
                """({id,time}) => api(`/api/cases/${id}/imports`,{method:'POST',body:{filename:'gateway-intake.json',content:JSON.stringify([{title:'Gateway activity pending review',timestamp:time,hostname:'REVIEW-GATEWAY'}])}})""",
                {"id": target, "time": stamp(now - timedelta(days=3))},
            )
            for index in range(3):
                new_history(j, database, f"Older retained closure {index + 1}", now - timedelta(days=30), closed=now - timedelta(days=2))
        elif scenario.startswith(("NEXT-02", "NEXT-03")):
            historical = []
            for index in range(10 if scenario.startswith("NEXT-02") else 3):
                created = now - timedelta(days=2)
                identifier = new_history(j, database, f"Response history {index + 1}", created)
                if scenario.startswith("NEXT-02") and index < 2:
                    policy_fixture(manager, identifier, 60)
                database.execute(
                    "UPDATE incident_cases SET status='closed',closed_at=?,sla_due_at=? WHERE id=?",
                    (stamp(created + timedelta(minutes=30 if index == 0 else 120)), stamp(created + timedelta(hours=6)), identifier),
                )
                historical.append(identifier)
            result["historical_case_ids"] = historical
        elif scenario.startswith("NEXT-04"):
            historical = new_history(j, database, "Previous zero-delay detection", now - timedelta(days=3))
            prepare_detection_history(j, database, historical, now - timedelta(days=2), closed=True)
            prepare_detection_history(j, database, original_id, now - timedelta(hours=2))
        elif scenario.startswith("NEXT-05"):
            low = new_history(j, database, "Repeated low-priority gateway events", now - timedelta(days=1), severity="low")
            for identifier, count in ((original_id, 2), (low, 15)):
                j.page.evaluate(
                    """({id,count}) => api(`/api/cases/${id}/imports`,{method:'POST',body:{filename:'gateway-events.json',content:JSON.stringify(Array.from({length:count},(_,n)=>({title:`Gateway event ${n+1}`,timestamp:new Date(Date.now()-3600000+n*1000).toISOString(),hostname:`REVIEW-HOST-${n}`,command_line:'powershell.exe -EncodedCommand YQ=='})))}})""",
                    {"id": identifier, "count": count},
                )
            database.execute("UPDATE incident_cases SET severity='critical' WHERE id=?", (original_id,))
            database.execute("UPDATE incident_cases SET severity='low' WHERE id=?", (low,))
            low_before = j.page.evaluate("id => api(`/api/cases/${id}`)", low)
            result["alert_volume"] = {
                str(identifier): database.execute("SELECT COUNT(*) FROM alerts WHERE owner_case_id=?", (identifier,)).fetchone()[0]
                for identifier in (original_id, low)
            }
            assert result["alert_volume"][str(low)] > result["alert_volume"][str(original_id)] > 0
        elif scenario.startswith("NEXT-09"):
            target = new_history(j, database, "Gateway case in the busiest interval", now - timedelta(days=4))
            for index in range(2):
                new_history(j, database, f"Other gateway review {index + 1}", now - timedelta(days=4))
            new_history(j, database, "Previous completed interval", now - timedelta(days=20), closed=now - timedelta(days=1))
        else:
            new_history(j, database, "Valid recent closure", now - timedelta(days=3), closed=now - timedelta(days=2))
            incomplete = new_history(j, database, "Incomplete historical chronology", now - timedelta(days=2))
            database.execute("UPDATE incident_cases SET status='closed',closed_at=NULL WHERE id=?", (incomplete,))
        subject.nav("الأداء")
        period(subject, "7")
        if scenario.startswith("NEXT-01"):
            subject.page.set_viewport_size({"width": 390, "height": 1000})
            assert subject.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            result["interaction_viewport"] = 390
        result["dashboard_before"] = subject.page.locator("main").inner_text()
        subject.page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-decision.png"), full_page=True)
        if scenario.startswith("NEXT-01"):
            assert plain(subject.page.locator("[data-completion-count]").inner_text()) == ("0 من 2" if language == "ar" else "0 of 2")
            assert plain(subject.page.locator("[data-completion-value]").inner_text()) == "0%"
            assert counter(subject, "أغلقت خلال الفترة") == 3
            result["decision"] = "Three older closures are throughput; neither of the two new cases is complete. Advance the oldest new case."
            task_title = subject.system_task_title("Validate primary evidence")
            task_links = subject.page.get_by_role("link", name=task_title, exact=True)
            expect(task_links).to_have_count(2)
            task_row = (
                subject.page.locator("tr").filter(has_text="Oldest new gateway case").filter(has=subject.page.get_by_role("link", name=task_title, exact=True))
            )
            expect(task_row).to_have_count(1)
            task_panel = task_row.locator("xpath=ancestor::section[1]")
            task_panel.evaluate("element => element.scrollIntoView({block:'center'})")
            task_wrap = task_row.locator("xpath=ancestor::div[contains(@class,'table-wrap')][1]")
            result["pending_task_layout"] = task_wrap.evaluate(
                "element => ({width:element.clientWidth,content:element.scrollWidth,cells:[...element.querySelectorAll('tbody tr:first-child td')].map(cell=>{const r=cell.getBoundingClientRect();return {text:cell.innerText,left:r.left,right:r.right}})})"
            )
            subject.page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-tasks-viewport.png"), animations="disabled")
            assert task_wrap.evaluate("element => element.scrollWidth <= element.clientWidth"), "Pending task context requires horizontal scrolling"
            assert task_row.locator("td").evaluate_all(
                "cells => cells.every(cell => {const r=cell.getBoundingClientRect(); return r.left >= 0 && r.right <= innerWidth && cell.scrollWidth <= cell.clientWidth})"
            ), "The task, case and status must all be readable before choosing the task"
            task_row.get_by_role("link", name=task_title, exact=True).click()
            subject.settle()
            subject.case_id, subject.case_url = target, f"{subject.base}/cases/{target}"
            assert subject.page.url.startswith(subject.case_url + "?")
            assert subject.state()["id"] == target
            result["task_disambiguation"] = (
                "The two identically named primary-evidence tasks are distinguished by their visible case context before activation."
            )
            save_note(subject, "New-period gateway work remains open; review the oldest retained gateway activity before claiming cohort completion.")
            for _ in range(3):
                if "/performance?" in subject.page.url:
                    break
                subject.page.go_back()
                subject.settle()
            assert "days=7" in subject.page.url
        elif scenario.startswith(("NEXT-02", "NEXT-03")):
            if scenario.startswith("NEXT-02"):
                assert plain(subject.page.locator("[data-speed-value]").inner_text()) == "50%"
                assert plain(subject.page.locator(".performance-speed .performance-basis").inner_text()).endswith("2 من 10" if language == "ar" else "2 of 10")
                result["decision"] = "Only two of ten closures have agreed targets; one is late. Inspect its retained policy, then configure the active case."
                select_queue(subject, "أغلقت خلال الفترة")
                open_case(subject, historical[1])
                subject.click("link", "الاستجابة والتصعيد")
                assert workflow(subject)["sla"]["remaining_work_seconds"] < 0
                expect(subject.page.locator("input[name=minutes]")).to_have_count(0)
                subject.nav("الأداء")
                period(subject, "7")
                select_queue(subject, "قضايا نشطة")
            else:
                expect(subject.page.locator("[data-speed-value]")).to_have_text("—")
                result["decision"] = "Legacy deadlines do not prove an agreed target. Configure only the active case; historic speed remains unmeasured."
            open_case(subject, original_id)
            configure_policy(subject)
            subject.nav("الأداء")
            period(subject, "7")
            assert plain(subject.page.locator("[data-speed-value]").inner_text()) == ("50%" if scenario.startswith("NEXT-02") else "—")
            assert database.execute("SELECT COUNT(*) FROM autopsy_records WHERE kind='workflow_sla' AND case_id!=?", (original_id,)).fetchone()[0] == (
                2 if scenario.startswith("NEXT-02") else 0
            )
        elif scenario.startswith("NEXT-04"):
            duration_rows = subject.page.locator(".performance-duration-row")
            assert plain(duration_rows.nth(0).locator("strong").inner_text()).startswith("0 ")
            expect(duration_rows.nth(2).locator("strong")).to_have_text("—")
            result["decision"] = (
                "Zero detection delay is measured in the closed history; containment is unmeasured. Document the available containment proof for the active case."
            )
            open_case(subject, original_id)
            subject.click("link", "الاستجابة والتصعيد")
            dialog = record_dialog(subject, "response")
            dialog.locator("input[name=title]").fill("Gateway containment confirmed")
            dialog.locator("input[name=phase]").fill(subject.page.evaluate("autopsyLabel('containment')"))
            dialog.locator("input[name=status]").fill(subject.page.evaluate("autopsyLabel('succeeded')"))
            dialog.locator("input[name=performed_by]").fill(subject.page.evaluate("state.user.name"))
            dialog.locator("input[name=performed_by]").press("ArrowDown")
            dialog.get_by_role("option").filter(has_text=subject.page.evaluate("state.user.name")).first.click()
            local_time = subject.page.evaluate(
                "value => {const date=new Date(value);return new Date(date-date.getTimezoneOffset()*60000).toISOString().slice(0,16)}",
                stamp(now - timedelta(hours=1)),
            )
            dialog.locator("input[name=performed_at]").fill(local_time)
            dialog.locator("input[name=evidence_id]").press("ArrowDown")
            dialog.get_by_role("option").filter(has_text="response-confirmation.json").first.click()
            dialog.locator("textarea[name=details]").fill(
                "The retained gateway record confirms containment at the recorded time; no live endpoint command was executed here."
            )
            subject.click("button", "حفظ", dialog)
            assert workflow(subject)["metrics"]["containment_delay_seconds"] == 3600
            subject.click("link", "التقارير والمراجعة")
            subject.click("button", "إعداد تقرير جديد")
            retained = report(subject, report_path(subject))
            assert retained["payload"]["metrics"]["containment_delay_seconds"] == 3600
            preview = open_preview(subject)
            retained_records = preview.get_by_text(subject.page.evaluate("autopsyReportFieldLabel('records')"), exact=True).locator("+ dd")
            retained_records.locator(":scope > details > summary").click()
            responses = retained_records.get_by_text(subject.page.evaluate("autopsyReportFieldLabel('response')"), exact=True).locator("+ dd")
            responses.locator(":scope > details > summary").click()
            expect(responses).to_contain_text("Gateway containment confirmed")
            selected_response = next(row for row in retained["payload"]["records"]["response"] if row["payload"]["title"] == "Gateway containment confirmed")
            response_detail = responses.locator(":scope > details > dl > dt").filter(has_text="Gateway containment confirmed").locator("+ dd")
            response_detail.locator(":scope > details > summary").click()
            metadata = response_detail.locator(":scope > details > dl")
            labels = metadata.locator(":scope > dt").all_inner_texts()
            for internal in ["id", "kind", "created_by", "updated_by"]:
                assert subject.page.evaluate("key => autopsyReportFieldLabel(key)", internal) not in labels
            expect(metadata).to_contain_text(selected_response["created_by_name"])
            expect(metadata).to_contain_text(selected_response["updated_by_name"])
            payload_detail = metadata.get_by_text(subject.page.evaluate("autopsyReportFieldLabel('payload')"), exact=True).locator("+ dd")
            payload_detail.locator(":scope > details > summary").click()
            evidence_reference = payload_detail.get_by_text(subject.page.evaluate("autopsyReportFieldLabel('evidence_id')"), exact=True).locator("+ dd")
            expect(evidence_reference).to_have_text(str(selected_response["payload"]["evidence_id"]))
            assert subject.page.evaluate("autopsyReportFieldLabel('performed_by')") != "Port"
            if language == "ar":
                expect(payload_detail.get_by_text("المرحلة", exact=True).locator("+ dd")).to_have_text("الاحتواء")
                expect(payload_detail.get_by_text("الحالة", exact=True).locator("+ dd")).to_have_text("نجح")
            result["report_response_list"] = responses.inner_text()
            responses.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-response-records.png"), animations="disabled")
            metric_preview = preview.get_by_text(subject.page.evaluate("autopsyReportFieldLabel('metrics')"), exact=True).locator("+ dd")
            metric_preview.locator(":scope > details > summary").click()
            metric_value = metric_preview.get_by_text(subject.page.evaluate("autopsyReportFieldLabel('containment_delay_seconds')"), exact=True).locator("+ dd")
            expect(metric_value).to_have_text("3600")
            metric_labels = metric_preview.locator(":scope > details > dl > dt").all_inner_texts()
            assert not {"first_response_delay_seconds", "milestones"}.intersection(metric_labels)
            if language == "en":
                basis = metric_preview.get_by_text("Metric calculation basis and limitations", exact=True).locator("+ dd").inner_text()
                assert not any("\u0600" <= character <= "\u06ff" for character in basis)
            metric_preview.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-report-metrics.png"), animations="disabled")
            subject.nav("الأداء")
            period(subject, "7")
            expect(subject.page.locator(".performance-duration-row").nth(2).locator("strong")).to_have_text("—")
            result["aggregate_basis"] = "The active case changes its own report metrics; closed-case aggregate correctly remains unchanged."
        elif scenario.startswith("NEXT-05"):
            assert counter(subject, "قضايا نشطة") == 2
            critical = subject.page.locator(".performance-severity-list li").filter(has=subject.page.locator(".severity.critical"))
            assert plain(critical.locator("strong").inner_text()) == "1"
            result["decision"] = "The distribution counts cases. Choose the critical investigation even though the low case has more alerts."
            open_case(subject, original_id)
            save_note(
                subject,
                "Prioritize the critical gateway case for evidence correlation. The separate low-priority alert volume does not establish this case's impact or authorize an endpoint action.",
            )
            unchanged = subject.page.evaluate("id => api(`/api/cases/${id}`)", low)
            assert unchanged["version"] == low_before["version"] and unchanged["evidence"] == low_before["evidence"]
        elif scenario.startswith("NEXT-09"):
            bars = subject.page.locator(".performance-trend-bucket")
            tab_to(subject, bars.first)
            bars.first.press("Home")
            observed = []
            for index in range(bars.count()):
                observed.append(bars.nth(index).get_attribute("aria-label"))
                if index < bars.count() - 1:
                    bars.nth(index).press("ArrowRight")
            largest = next(text for text in observed if ("أنشئت 3" if language == "ar" else "Opened 3") in plain(text))
            result["keyboard_observations"] = observed
            result["decision"] = "Choose the named gateway case in the interval showing three opened cases: " + largest
            daily = subject.page.get_by_text("عرض الأرقام اليومية" if language == "ar" else "Daily figures", exact=True)
            tab_to(subject, daily)
            daily.press("Enter")
            expect(subject.page.locator(".performance-data")).to_have_attribute("open", "")
            open_case(subject, target, keyboard=True)
            save_note(
                subject,
                "Prioritize correlation of the retained gateway activity in the busiest opening interval; closures are a separate series.",
                keyboard=True,
            )
        else:
            expect(subject.page.locator("[data-completion-value]")).to_have_text("—")
            assert plain(subject.page.locator("[data-completion-count]").inner_text()) == ("1 من 3" if language == "ar" else "1 of 3")
            expect(subject.page.locator(".performance-completion")).to_contain_text("غير قابلة للحساب" if language == "ar" else "Not measurable")
            expect(subject.page.locator("[data-speed-value]")).to_have_text("—")
            result["decision"] = (
                "One known closure, one active case and one unmeasurable history cannot yield a reliable completion percentage. Advance only the active case."
            )
            open_case(subject, original_id)
            save_note(subject, "Continue current evidence review; do not invent the missing closure time in the historical investigation.")
            assert database.execute("SELECT closed_at FROM incident_cases WHERE id=?", (incomplete,)).fetchone()[0] is None
        capture(subject, result)


def prepare_review(j):
    upload_logs(j, "approved-maintenance.json", "Service owner confirmed the retained activity")
    j.assessment("Retained owner approval confirms authorized maintenance; no compromise established.")
    j.click("link", "التحقيق والخط الزمني")
    j.record("root_cause", {"category": "other", "conclusion": "Retained owner approval explains the activity", "evidence_id": "approved-maintenance.json"})
    j.click("link", "الاستجابة والتصعيد")
    j.record(
        "response",
        {
            "title": "Validate approved maintenance",
            "phase": "validation",
            "status": "not_applicable",
            "details": "No containment is needed for the evidenced authorized maintenance.",
        },
    )
    j.transition("awaiting_review")
    while j.page.get_by_role("button", name=j.text("إكمال المهمة"), exact=True).count():
        j.page.get_by_role("button", name=j.text("إكمال المهمة"), exact=True).first.click()
        j.settle()
    assert all(task["status"] in {"completed", "reviewed"} for task in j.state()["tasks"])
    prepare(j)


@pytest.mark.e2e
@pytest.mark.skipif(sys.platform == "win32", reason="Requires the isolated native report service")
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", ["NEXT-08-tasks-done-case-awaits-review", "NEXT-11-concurrent-dashboard-snapshot"])
def test_dashboard_completion_follows_independent_native_review(app, database, monkeypatch, language, scenario):
    evidence_context(monkeypatch)
    with local_worker_services(app.config), review_session(app, language, scenario) as (j, manager, result):
        describe(result, scenario)
        prepare_review(j)
        original_id, original_url = j.case_id, j.case_url
        next_case = new_history(j, database, "Next gateway investigation", utc_now() - timedelta(hours=2)) if scenario.startswith("NEXT-11") else None
        manager.login("manager@socify.local")
        manager.case_id, manager.case_url = original_id, original_url
        j.nav("الأداء")
        period(j, "7")
        assert plain(j.page.locator("[data-completion-value]").inner_text()) == "0%"
        assert counter(j, "بانتظار المراجعة") == 1
        assert counter(j, "مهام معلقة") == (2 if next_case else 0)
        result["decision"] = "Completed tasks are not a closed incident. The prepared report still needs an independent authorized review."
        manager.nav("الأداء")
        select_queue(manager, "بانتظار المراجعة")
        manager.page.locator(f"#performance-cases a[href='/cases/{original_id}?tab=reports']").click()
        manager.settle()
        approve(manager)
        download_url = pdf_link(manager).get_attribute("href")
        with manager.page.expect_download() as pending:
            pdf_link(manager).click()
        original_pdf = Path(pending.value.path()).read_bytes()
        assert original_pdf.startswith(b"%PDF-")
        manager.decision("closed", "Independent review accepted the retained evidence, completed tasks and report.")
        assert manager.state()["status"] == "closed"
        j.page.reload()
        j.settle()
        assert counter(j, "أغلقت خلال الفترة") == 1 and counter(j, "بانتظار المراجعة") == 0
        assert counter(j, "قضايا نشطة") == (1 if next_case else 0)
        assert plain(j.page.locator("[data-completion-value]").inner_text()) == ("50%" if next_case else "100%")
        select_queue(j, "أغلقت خلال الفترة")
        open_case(j, original_id)
        j.click("link", "التقارير والمراجعة")
        with j.page.expect_download() as pending:
            j.page.locator(f'a[href="{download_url}"]').first.click()
        assert Path(pending.value.path()).read_bytes() == original_pdf
        result["retained_report_sha256"] = hashlib.sha256(original_pdf).hexdigest()
        if next_case:
            j.nav("الأداء")
            period(j, "7")
            select_queue(j, "قضايا نشطة")
            expect(j.page.locator(f"#performance-cases a[href='/cases/{original_id}']")).to_have_count(0)
            open_case(j, next_case)
            save_note(j, "The colleague closed the reviewed maintenance case. Continue this separate gateway investigation without repeating completed work.")
        capture(j, result)


@pytest.mark.e2e
def test_report_preview_nested_titles_are_safe_text(app, monkeypatch):
    evidence_context(monkeypatch)
    with review_session(app, "en", "report-preview-nested-title-text", create_case=False) as (j, _manager, result):
        result["kind"] = "Component security check with synthetic record titles; not a simulated user journey"
        title = "Containment <img src=x onerror=window.__reportTitleInjected=1> & reviewed"
        name = "Gateway <svg onload=window.__reportTitleInjected=1>"
        j.page.evaluate(
            """({title,name}) => {
                window.__reportTitleInjected=0;
                const data=[{id:7,payload:{title}},{id:8,payload:{name}},{id:9,payload:{title:{unexpected:'object'},name:42}}];
                const preview=document.createElement('section'); preview.id='record-title-probe';
                preview.append(autopsyReportPreview(data)); document.getElementById('workspace').append(preview);
            }""",
            {"title": title, "name": name},
        )
        preview = j.page.locator("#record-title-probe")
        headers = preview.locator(":scope > dl > dt")
        assert title in headers.nth(0).inner_text() and name in headers.nth(1).inner_text()
        assert headers.nth(2).inner_text().endswith("9")
        expect(preview.locator("img,svg,script")).to_have_count(0)
        assert j.page.evaluate("window.__reportTitleInjected") == 0
        preview.locator(":scope > dl > dd > details > summary").first.click()
        expect(preview.locator(":scope > dl > dd").first).to_contain_text("7")
        result["outcomes"] = [
            "nested title and name identify records",
            "HTML-like titles remain literal text",
            "nontext nested names fall back to the ID",
            "original record ID remains in the expanded detail",
        ]


@pytest.mark.e2e
def test_report_record_identity_filter_preserves_payload_and_evidence_references(app, monkeypatch):
    evidence_context(monkeypatch)
    with review_session(app, "en", "report-record-identity-scope", create_case=False) as (j, _manager, result):
        result["kind"] = "Component security and scope check; not a simulated user journey"
        j.page.evaluate(
            """() => {
                const data={records:{war_room:[{id:7,kind:'war_room',created_by:3,updated_by:4,
                    created_by_name:'Author <img src=x>',updated_by_name:'Editor <svg>',
                    payload:{title:'Preserved investigation decision',id:91,kind:'payload-kind',evidence_id:39,alert_id:41,status:'constructor',phase:'bespoke-phase',basis:'constructor'}},
                    {id:8,kind:'war_room',created_by:5,updated_by:5,payload:{title:'Legacy unnamed author'}}]},
                    evidence:[{id:39,title:'Original gateway evidence'}],alerts:[{id:41,title:'Related alert'}]};
                const preview=document.createElement('section');preview.id='record-scope-probe';
                preview.append(autopsyReportPreview(data));document.getElementById('workspace').append(preview);
            }"""
        )
        preview = j.page.locator("#record-scope-probe")
        for _ in range(20):
            collapsed = preview.locator("details:not([open]) > summary")
            if not collapsed.count():
                break
            collapsed.first.click()
        expect(preview.locator("details:not([open])")).to_have_count(0)
        expect(preview.locator("img,svg,script")).to_have_count(0)
        author = preview.get_by_text("Author", exact=True).locator("..")
        labels = author.locator(":scope > dt").all_inner_texts()
        assert not {"ID", "Type", "Author ID", "Last editor ID"}.intersection(labels)
        expect(author).to_contain_text("Author <img src=x>")
        expect(author).to_contain_text("Editor <svg>")
        expect(author.get_by_text("Metric calculation basis and limitations", exact=True).locator("+ dd")).to_have_text("constructor")
        for retained in ["payload-kind", "91", "39", "41", "Legacy unnamed author", "constructor", "bespoke-phase"]:
            expect(preview).to_contain_text(retained)
        for title, identifier in [("Original gateway evidence", 39), ("Related alert", 41)]:
            retained_detail = preview.locator("dt").filter(has_text=f"Title: {title}").locator("+ dd")
            expect(retained_detail.get_by_text("ID", exact=True).locator("+ dd")).to_have_text(str(identifier))
        expect(preview.get_by_text("Author", exact=True)).to_have_count(1)
        expect(preview.get_by_text("Last editor", exact=True)).to_have_count(1)
        expect(preview.locator("dt").filter(has_text="Author ID")).to_have_count(0)
        expect(preview.locator("dt").filter(has_text="Last editor ID")).to_have_count(0)
        result["outcomes"] = [
            "only investigation wrapper metadata hidden",
            "retained author and editor names render as text",
            "payload ID, kind, evidence and alert references preserved",
            "standalone evidence and alert IDs preserved",
            "legacy snapshot author not guessed",
        ]
