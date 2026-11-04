"""Complete four existing native conditions; variants are not new user families.

All decisions use the interface. A real isolated renderer is required for native
acceptance; Windows records the reachable boundary and skips without approving,
closing, manufacturing formats, or claiming completion.
"""

import hashlib
import json
from contextlib import nullcontext
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from playwright.sync_api import expect

from scripts.local_services import local_worker_services
from socify.timeutils import utc_now
from tests.e2e import test_native_delivery_decisions as native
from tests.e2e import test_review_workflow as sessions
from tests.e2e.test_case_continuity_journeys import record_dialog, workflow
from tests.e2e.test_closed_performance_journeys import select_queue
from tests.e2e.test_followup_handoff_journeys import edit
from tests.e2e.test_investigation_link_journeys import choose
from tests.e2e.test_performance_decision_journeys import open_case, plain, save_note
from tests.e2e.test_performance_goal_journeys import counter, period
from tests.e2e.test_report_recovery_journeys import report
from tests.e2e.test_source_goal_journeys import create_connector
from tests.e2e.test_source_lifecycle_journeys import source_row
from tests.e2e.test_timeline_decision_journeys import local_input
from tests.integration.test_source_https_transport import tls_source  # noqa: F401 -- real owned TLS peer

ARTIFACTS = Path("artifacts/usability_campaign/native-completion-decisions")
NOTE = "The retained owner approval covers this synthetic maintenance replay; no compromise or live endpoint action is established."
FILENAME = "approved-maintenance.json"


@pytest.fixture(autouse=True)
def evidence_directory(monkeypatch):
    """Redirect evidence files only; product and renderer results are untouched."""
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(sessions, "ARTIFACTS", ARTIFACTS)
    monkeypatch.setattr(native, "ARTIFACTS", ARTIFACTS)


def describe(result):
    result.update(
        plan_id="-".join(result["scenario"].split("-")[:2]),
        kind="Existing native acceptance condition, scripted interface decisions",
        human_participants=0,
        count_as_new_semantic_condition=False,
        native_condition_completed=False,
        setup="Isolated seeded accounts and harmless retained fixture evidence; no fabricated approval, closure or renderer output.",
        test_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        renderer_sha256=hashlib.sha256(Path("socify/autopsy_report_render.py").read_bytes()).hexdigest(),
    )


def finish(result):
    blocked = native.native_blocker()
    if blocked:
        result.update(
            status="partial_native_blocked", native_blocker=blocked, completion_claim="Native reading, approval and downstream delivery remain unverified."
        )
    else:
        result.update(native_condition_completed=True, completion_claim="Existing scripted condition completed in this language; no human or new-family claim.")
    (ARTIFACTS / f"{result['scenario']}-{result['language']}.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    if blocked:
        pytest.skip(blocked)


def retained_work(j):
    digest = native.upload(
        j,
        [{"title": "Owner approved the retained maintenance replay", "hostname": "REVIEW-GATEWAY", "timestamp": utc_now().isoformat()}],
        FILENAME,
    )
    native.complete_investigation(j, NOTE, evidence=FILENAME)
    return digest, native.snapshot(j)


def exact_draft(j, path):
    current, retained = j.state(), report(j, path)
    assert path == f"/api/cases/{current['id']}/reports/{retained['id']}"
    assert retained["case_id"] == current["id"]
    assert retained["payload"]["case"]["reference"] == current["reference"]
    assert retained["payload"]["case"]["version"] == retained["source_version"] == current["version"]
    assert retained["state"] == "draft"
    assert retained["created_by"] != j.page.evaluate("state.user.id")
    return retained


def read_draft(j, path, result, markers):
    native.visit(j, j.case_id)
    retained = exact_draft(j, path)
    native.read_preview(j, path, result, [retained["payload"]["case"]["reference"], *markers])
    result.setdefault("review_bindings", []).append(
        {
            "case_id": j.case_id,
            "report_id": retained["id"],
            "path": path,
            "sha256": retained["sha256"],
            "source_version": retained["source_version"],
            "created_by": retained["created_by"],
            "reviewed_by": j.page.evaluate("state.user.id"),
            "state_before_review": retained["state"],
        }
    )
    if native.NATIVE:
        values = native.review_native_report(j, path, result, markers)
        exact_draft(j, path)
        assert report(j, path)["sha256"] == retained["sha256"]
        return values
    assert retained["formats"] == []
    return None


def reject_draft_closure(manager, path, result):
    native.visit(manager, manager.case_id)
    before = manager.state()
    assert before["status"] == "awaiting_review" and report(manager, path)["state"] == "draft"
    if native.NATIVE:
        assert manager.page.locator(".closure-requirements li").all_text_contents() == [manager.text("تقرير كامل معتمد مطابق لإصدار القضية الحالي")]
    with manager.page.expect_response(lambda r: r.url.endswith("/quick-report/acknowledge") and r.request.method == "POST") as pending:
        manager.decision("closed", "Tasks are complete, but this current report has not yet been independently reviewed.")
    assert pending.value.status == 409 and pending.value.json()["error"]["code"] == "CASE_CLOSURE_INCOMPLETE"
    expect(manager.page.locator(".closure-requirements")).to_have_attribute("open", "")
    expect(manager.page.locator(".closure-requirements")).to_contain_text(manager.text("تقرير كامل معتمد مطابق لإصدار القضية الحالي"))
    assert manager.state()["version"] == before["version"] and manager.state()["status"] == before["status"]
    assert report(manager, path)["state"] == "draft"
    result["unreviewed_closure"] = {"status": 409, "case_version_unchanged": True, "draft_unchanged": True}


def approve_and_close(manager, path):
    exact_draft(manager, path)
    native.approve_reviewed_report(manager, path)
    manager.decision("closed", "Independently read the current PDF and DOCX, retained evidence and investigation decisions before delivery.")
    state = manager.state()
    assert state["status"] == "closed" and state["closed_at"]


def next_case(j):
    j.nav("إدارة القضايا")
    j.click("button", "إنشاء قضية")
    dialog = j.page.get_by_role("dialog")
    dialog.locator("input[name=title]").fill("Next gateway investigation")
    j.click("button", "حفظ", dialog)
    j.page.wait_for_url("**/cases/*")
    identifier = int(j.page.url.rstrip("/").rsplit("/", 1)[-1].split("?", 1)[0])
    return identifier


def returned_activity(j, result, opened):
    """Read the chart and its daily table after the colleague's real closure."""
    j.page.locator(".performance-data > summary").click()
    rows = j.page.locator(".performance-data tbody tr")
    values = [tuple(int(plain(cell)) for cell in rows.nth(index).locator("td").all_inner_texts()[1:]) for index in range(rows.count())]
    assert values and all(len(row) == 2 for row in values)
    assert sum(row[0] for row in values) == opened and sum(row[1] for row in values) == 1
    bars = j.page.locator(".performance-trend-bucket")
    opened_label, closed_label = j.text("أنشئت"), j.text("أغلقت")
    for index in range(bars.count()):
        bar = bars.nth(index)
        label = plain(bar.get_attribute("aria-label"))
        if f"{opened_label} {opened}" in label and f"{closed_label} 1" in label:
            bar.click()
            expect(bar).to_have_attribute("aria-pressed", "true")
            readout = plain(j.page.locator(".performance-trend-readout").inner_text())
            assert f"{opened_label} {opened}" in readout and f"{closed_label} 1" in readout
            result["returned_activity"] = {"opened": opened, "closed": 1, "daily_rows": values, "chart_readout": readout}
            return
    raise AssertionError("The returning lead's chart does not match the visible daily figures")


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", ["NEXT-08-tasks-done-case-awaits-review", "NEXT-11-concurrent-dashboard-snapshot"])
def test_native_review_precedes_closure_and_returning_lead_delivery(app, language, scenario):
    with local_worker_services(app.config) if native.NATIVE else nullcontext(), sessions.review_session(app, language, scenario) as (j, manager, result):
        describe(result)
        digest, path = retained_work(j)
        original_id = j.case_id
        later = next_case(j) if scenario.startswith("NEXT-11") else None
        j.case_id, j.case_url = original_id, f"{j.base}/cases/{original_id}"
        native.manager_context(j, manager)
        j.nav("الأداء")
        period(j, "7")
        assert plain(j.page.locator("[data-completion-value]").inner_text()) == "0%"
        assert counter(j, "بانتظار المراجعة") == 1 and counter(j, "مهام معلقة") == (2 if later else 0)
        result["interpretation"] = "Completed tasks are not delivered work; the current report still needs an independent review."
        native.shot(j, result, "awaiting-independent-review")
        manager.nav("الأداء")
        period(manager, "7")
        select_queue(manager, "بانتظار المراجعة")
        manager.page.locator(f"#performance-cases a[href='/cases/{original_id}?tab=reports']").click()
        manager.settle()
        reject_draft_closure(manager, path, result)
        files = read_draft(manager, path, result, [digest, NOTE])
        if native.NATIVE:
            original_pdf, original_docx, _, _ = files
            approved_snapshot = report(manager, path)
            approve_and_close(manager, path)
            j.page.reload()
            j.settle()
            assert counter(j, "أغلقت خلال الفترة") == 1 and counter(j, "بانتظار المراجعة") == 0
            assert counter(j, "قضايا نشطة") == (1 if later else 0)
            assert plain(j.page.locator("[data-completion-value]").inner_text()) == ("50%" if later else "100%")
            assert counter(j, "مهام معلقة") == (2 if later else 0)
            returned_activity(j, result, 2 if later else 1)
            native.shot(j, result, "returning-lead-cohort")
            select_queue(j, "أغلقت خلال الفترة")
            open_case(j, original_id)
            j.click("link", "التقارير والمراجعة")
            native.assert_report_unchanged(j, path, approved_snapshot)
            assert native.download(j, path, "pdf") == original_pdf
            assert native.download(j, path, "docx") == original_docx
            if later:
                j.nav("الأداء")
                period(j, "7")
                select_queue(j, "قضايا نشطة")
                expect(j.page.locator(f"#performance-cases a[href='/cases/{original_id}']")).to_have_count(0)
                open_case(j, later)
                save_note(j, "The colleague delivered the reviewed maintenance case; continue this distinct gateway investigation.")
                assert j.state()["status"] != "closed"
            result["delivery"] = {
                "case_id": original_id,
                "report": path,
                "pdf_sha256": hashlib.sha256(original_pdf).hexdigest(),
                "docx_sha256": hashlib.sha256(original_docx).hexdigest(),
                "next_case": later,
                "closed_count": 1,
            }
        native.capture(manager, result)
    finish(result)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_reopened_source_requires_fresh_native_review_before_redelivery(app, monkeypatch, tls_source, language):  # noqa: F811
    monkeypatch.setenv("SOCIFY_SOURCE_ALLOWLIST", "siem.example")
    scenario = "NEXT-22-pull-into-closed-case"
    body = json.dumps({"external_id": "later-review-1", "title": "Later gateway evidence", "hostname": "LATER-GATEWAY"}).encode() + b"\n"
    tls_source["responses"]["body"] = body
    with local_worker_services(app.config) if native.NATIVE else nullcontext(), sessions.review_session(app, language, scenario) as (j, manager, result):
        describe(result)
        native.manager_context(j, manager)
        create_connector(manager, tls_source["url"] + "/events")
        digest, first_path = retained_work(j)
        first_files = read_draft(manager, first_path, result, [digest, NOTE])
        if native.NATIVE:
            first = report(manager, first_path)
            original_pdf, original_docx, _, _ = first_files
            approve_and_close(manager, first_path)
            baseline = manager.state()
            manager.click("link", "السجلات والأدلة")
            pull = source_row(manager).get_by_role("button", name=manager.text("سحب السجلات الآن"), exact=True)
            if pull.count() and pull.is_enabled():
                with manager.page.expect_response(lambda r: r.url.endswith("/pull") and r.request.method == "POST") as rejected:
                    pull.click()
                manager.settle()
                assert rejected.value.status in {403, 409, 422}
                expect(manager.page.locator("#global-message")).to_be_visible()
            elif pull.count():
                expect(pull).to_be_disabled()
            assert not tls_source["requests"]
            assert manager.state()["version"] == baseline["version"] and manager.state()["evidence"] == baseline["evidence"]
            native.assert_report_unchanged(manager, first_path, first)
            native.shot(manager, result, "closed-source-rejected")
            manager.transition("reopened")
            assert manager.state()["status"] == "reopened"
            accepted = native.pull(manager)
            assert accepted["accepted"] == 1
            expect(manager.page.get_by_role("cell", name="Later gateway evidence", exact=True)).to_be_visible()
            received = manager.state()
            repeated = native.pull(manager)
            assert repeated["accepted"] == 0 and repeated["skipped"] == 1
            assert manager.state()["version"] == received["version"] and manager.state()["evidence"] == received["evidence"]
            native.visit(j, j.case_id)
            updated_note = (
                "Later gateway evidence was retained after authorized reopening; the earlier approved maintenance report remains historical and unchanged."
            )
            native.assessment(j, updated_note, "siem_builtin_rule")
            j.transition("awaiting_review")
            second_path = native.snapshot(j)
            second = report(j, second_path)
            assert second_path != first_path and second["sha256"] != first["sha256"]
            assert len(second["payload"]["imports"]) == len(first["payload"]["imports"]) + 1
            native.visit(manager, j.case_id)
            native.reject_unreviewed_close(manager, second_path, result, first_path)
            second_files = read_draft(manager, second_path, result, [hashlib.sha256(body).hexdigest(), updated_note])
            approve_and_close(manager, second_path)
            native.assert_report_unchanged(manager, first_path, first)
            assert report(manager, first_path)["state"] == "approved"
            assert native.download(manager, first_path, "pdf") == original_pdf
            assert native.download(manager, first_path, "docx") == original_docx
            result["redelivery"] = {
                "previous_report": first_path,
                "new_report": second_path,
                "accepted": accepted,
                "repeat": repeated,
                "original_pdf_sha256": hashlib.sha256(original_pdf).hexdigest(),
                "current_pdf_sha256": hashlib.sha256(second_files[0]).hexdigest(),
                "case_status": manager.state()["status"],
            }
            result["transport_limit"] = "Actual owned TLS peer and isolated native renderer; not a vendor SIEM or customer incident."
        native.capture(manager, result)
    finish(result)


def response_milestone(j, phase, at):
    j.click("link", "الاستجابة والتصعيد")
    dialog = record_dialog(j, "response")
    dialog.locator("input[name=title]").fill(f"Gateway {phase}")
    for field, value in (("phase", phase), ("status", "succeeded")):
        dialog.locator(f"input[name={field}]").fill(j.page.evaluate("value => autopsyLabel(value)", value))
    choose(j, dialog, "performed_by", j.page.evaluate("state.user.name"))
    dialog.locator("input[name=performed_at]").fill(local_input(j, at))
    dialog.locator("input[name=evidence_id]").press("ArrowDown")
    dialog.get_by_role("option").first.click()
    dialog.locator("textarea[name=details]").fill("Recorded gateway milestone; compare this entered time with the retained gateway events.")
    j.click("button", "حفظ", dialog)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_corrected_chronology_is_read_in_native_files_before_independent_approval(app, language):
    scenario = "NEXT-33-impossible-response-chronology"
    with local_worker_services(app.config) if native.NATIVE else nullcontext(), sessions.review_session(app, language, scenario) as (j, manager, result):
        describe(result)
        start = (utc_now() - timedelta(hours=2)).replace(second=0, microsecond=0)
        digest = native.upload(
            j,
            [
                {"title": title, "timestamp": at.isoformat(), "hostname": "REVIEW-GATEWAY"}
                for title, at in (("Detection confirmed at gateway", start), ("Containment confirmed at gateway", start + timedelta(minutes=20)))
            ],
            "response-clock-evidence.json",
        )
        response_milestone(j, "detection", start.isoformat())
        response_milestone(j, "containment", (start - timedelta(minutes=10)).isoformat())
        initial_note = "Gateway detection and containment documented; independent chronology review requested."
        j.assessment(initial_note)
        initial_path = native.snapshot(j)
        initial = report(j, initial_path)
        assert initial["payload"]["metrics"]["containment_delay_seconds"] is None
        native.manager_context(j, manager)
        manager.click("link", "الاستجابة والتصعيد")
        manager.page.locator(".response-metrics summary").click()
        metrics = manager.page.locator(".response-metrics")
        expect(metrics.locator("[data-response-duration=containment_delay_seconds]")).to_have_text(manager.text("غير مقاس"))
        expect(metrics).to_contain_text(manager.text("نهاية الفترة تسبق بدايتها؛ لم تُحسب المدة."))
        native.shot(manager, result, "chronology-unmeasured")
        initial_files = read_draft(manager, initial_path, result, [digest, initial_note])
        if native.NATIVE:
            native.assert_pdf_cell(initial_files[3], "المدة حتى الاحتواء بالثواني", "غير قابل للحساب")
            assert ("المدة حتى الاحتواء بالثواني", "غير قابل للحساب") in initial_files[2]
        manager.decision(
            "needs_followup", "Containment precedes detection; correct it to the retained gateway event twenty minutes after detection before approval."
        )
        assert report(manager, initial_path)["state"] == "draft"
        native.visit(j, j.case_id)
        j.click("link", "التحقيق والخط الزمني")
        expect(j.page.locator("main")).to_contain_text("Containment confirmed at gateway")
        j.click("link", "الاستجابة والتصعيد")
        dialog = edit(j, "Gateway containment")
        dialog.locator("input[name=performed_at]").fill(local_input(j, (start + timedelta(minutes=20)).isoformat()))
        dialog.locator("textarea[name=details]").fill(
            "Corrected to the retained gateway containment event, twenty minutes after detection; the prior entry was a transcription error."
        )
        j.click("button", "حفظ", dialog)
        assert workflow(j)["metrics"]["containment_delay_seconds"] == 1200
        corrected_note = "Chronology corrected against retained gateway evidence; containment followed detection by twenty minutes."
        j.assessment(corrected_note)
        corrected_path = native.snapshot(j)
        assert corrected_path != initial_path
        corrected_files = read_draft(manager, corrected_path, result, [digest, corrected_note])
        if native.NATIVE:
            assert ("المدة حتى الاحتواء بالثواني", "1200.0") in corrected_files[2] or ("المدة حتى الاحتواء بالثواني", "1200") in corrected_files[2]
            native.assert_pdf_cell(corrected_files[3], "المدة حتى الاحتواء بالثواني", Decimal(1200))
            exact_draft(manager, corrected_path)
            native.approve_reviewed_report(manager, corrected_path)
            assert report(manager, corrected_path)["state"] == "approved"
            assert native.download(manager, initial_path, "pdf") == initial_files[0]
            assert native.download(manager, initial_path, "docx") == initial_files[1]
            result["native_metric_review"] = {
                "containment_seconds": 1200,
                "previous_pdf_sha256": hashlib.sha256(initial_files[0]).hexdigest(),
                "corrected_pdf_sha256": hashlib.sha256(corrected_files[0]).hexdigest(),
                "reviewed_before_approval": True,
            }
        native.assert_report_unchanged(manager, initial_path, initial)
        assert report(manager, initial_path)["state"] == "draft"
        assert report(manager, initial_path)["payload"]["metrics"]["containment_delay_seconds"] is None
        assert report(manager, corrected_path)["payload"]["metrics"]["containment_delay_seconds"] == 1200
        assert manager.state()["status"] != "closed"
        result["corrected_chronology"] = {
            "original_report": initial_path,
            "corrected_report": corrected_path,
            "source_sha256": digest,
            "containment_seconds": 1200,
            "original_unapproved": True,
            "case_closed": False,
        }
        native.capture(manager, result)
    finish(result)
