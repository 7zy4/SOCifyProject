"""Hash-bound reputation recovery and dated conflicting assessments through the UI.

These are scripted acceptance decisions, not human comprehension measurements.
The application retains inert fixtures; no sample is executed or uploaded externally.
"""

import hashlib
import json
import subprocess
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import expect

from tests.e2e import test_review_workflow as review_module
from tests.e2e.test_blue_team_decision_journeys import conclude
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_followup_decision_journeys import preview_note
from tests.e2e.test_investigation_link_journeys import records
from tests.e2e.test_report_recovery_journeys import report, report_path

ARTIFACTS = Path("artifacts/usability_campaign/reputation-decisions")
PRODUCT_FILES = ("socify/autopsy_samples.py", "socify/autopsy_reports.py", "static/autopsy.js", "static/autopsy_analysis.js", "static/localization.js")
SPECIMEN_A = b"Inert text specimen A; no instructions or executable content."
SPECIMEN_B = b"Inert text specimen B; a different retained subject."


def sha(content):
    return hashlib.sha256(content).hexdigest()


def fingerprint():
    return {name: sha(Path(name).read_bytes()) for name in PRODUCT_FILES}


@contextmanager
def reputation_session(app, monkeypatch, language, scenario):
    folder = ARTIFACTS / "attempts" / f"{scenario}-{language}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}"
    folder.mkdir(parents=True)
    monkeypatch.setattr(review_module, "ARTIFACTS", folder)
    with review_module.review_session(app, language, scenario) as (j, _manager, result):
        result.update(
            plan_id=scenario,
            human_participants=0,
            semantic_condition=scenario,
            interpretation_kind="Scripted decision hypothesis checked against visible evidence; no human feedback or spontaneous comprehension claim",
            setup_provenance="Seeded isolated analyst and initial case only. Samples, reports, corrections, conclusions and snapshots are submitted through visible controls. APIs are read-only independent assertions.",
            checked_revision=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),  # noqa: S603,S607
            test_file_sha256=sha(Path(__file__).read_bytes()),
            product_hashes_before=fingerprint(),
            native_delivery_claim=False,
            clean_round_claim=False,
            failed_user_attempts=[],
            harness_errors=[],
            external_browser_requests=[],
        )
        j.page.on(
            "request",
            lambda request: result["external_browser_requests"].append(request.url)
            if urlsplit(request.url).scheme in {"http", "https"} and urlsplit(request.url).netloc != urlsplit(j.base).netloc
            else None,
        )
        try:
            yield j, result, folder
            assert not result["external_browser_requests"], "PRODUCT: the browser sent investigation data to an external host"
            result["outcome_classification"] = "completed scripted user task"
        except Exception as error:
            result["outcome_classification"] = "product failure" if "PRODUCT:" in str(error) else "unclassified failure pending review"
            if "PRODUCT:" not in str(error):
                result["harness_errors"].append({"error": str(error), "classification": "pending review; not yet classified as a product defect"})
            raise
        finally:
            result["product_hashes_after"] = fingerprint()
            result["product_changed_during_attempt"] = result["product_hashes_before"] != result["product_hashes_after"]


def capture(j, result, folder, stage):
    result.setdefault("visible_observations", []).append({"stage": stage, "text": j.page.locator("main").inner_text()})
    for width in (1440, 390):
        j.page.set_viewport_size({"width": width, "height": 1000})
        assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "PRODUCT: horizontal page overflow"
        assert j.page.locator(".reputation-record .alert-property-table td").evaluate_all(
            "cells => cells.every(cell => cell.scrollWidth <= cell.clientWidth + 1)"
        ), "PRODUCT: a reputation identity or result is clipped within its cell"
        assert j.page.locator(".reputation-record .table-wrap").evaluate_all("tables => tables.every(table => table.scrollWidth <= table.clientWidth + 1)"), (
            "PRODUCT: reputation result counts require horizontal scrolling inside a field"
        )
        j.page.evaluate("scrollTo({top: 0, behavior: 'instant'})")
        path = folder / f"{stage}-{width}.png"
        j.page.screenshot(path=str(path), full_page=True)
        result.setdefault("screenshots", []).append(str(path))
    j.page.set_viewport_size({"width": 1440, "height": 1000})


def files(j):
    j.click("link", "التحليل")
    j.page.locator(".analysis-tools a[href*='analysis=files']").click()
    j.settle()


def samples(j):
    return j.page.evaluate("id => api(`/api/cases/${id}/samples`)", j.case_id)["items"]


def quarantine(j, name, content):
    j.page.locator("input[name=sample]").set_input_files({"name": name, "mimeType": "text/plain", "buffer": content})
    j.click("button", "حجر العينة")
    expect(j.page.get_by_text(sha(content), exact=True).first).to_be_visible()
    return next(row for row in samples(j) if row["sha256"] == sha(content))


def vt_report(digest, timestamp, malicious):
    return json.dumps(
        {
            "data": {
                "id": digest,
                "type": "file",
                "attributes": {
                    "sha256": digest,
                    "last_analysis_date": timestamp,
                    "last_analysis_stats": {"malicious": malicious, "undetected": 4 - malicious},
                    "last_analysis_results": {
                        "Synthetic inert assessment": {
                            "category": "malicious" if malicious else "undetected",
                            "result": "Fixture finding" if malicious else None,
                        }
                    },
                },
            }
        }
    ).encode()


def select_subject(j, digest):
    control = j.page.locator("input[name=subject]")
    control.fill(digest)
    control.press("ArrowDown")
    j.page.get_by_role("option").filter(has_text=digest).click()
    return control.input_value()


def import_report(j, raw, name):
    j.page.locator("input[name=vt_report]").set_input_files({"name": name, "mimeType": "application/json", "buffer": raw})
    with j.page.expect_response(lambda response: response.url.endswith("/reputation/virustotal") and response.request.method == "POST") as response:
        j.click("button", "استيراد نتيجة الفحص")
    return response.value


def reputation_card(j, source_digest):
    return j.page.locator(".record-card").filter(has=j.page.get_by_text(source_digest, exact=True))


def readable_record(j, card, language):
    # Internal payload keys/JSON are not a usable localized assessment table.
    internal = {"sample_id", "imported_by", "examined_at", "source_sha256", "authenticity", "stats", "engines"}
    headings = set(card.locator("th").all_text_contents())
    assert not headings & internal, f"PRODUCT: imported reputation exposes internal field names: {sorted(headings & internal)}"
    expect(card).to_contain_text("غير متحقق" if language == "ar" else "Unverified")
    expect(card).to_contain_text("لا يثبت سلامة" if language == "ar" else "does not establish safety")
    card.locator("summary").click()
    expect(card.get_by_text("Synthetic inert assessment", exact=True)).to_be_visible()
    card.locator("summary").click()


def retained_bytes(j, record):
    response = j.page.request.get(f"{j.base}/api/incidents/{j.case_id}/evidence/{record['payload']['evidence_id']}/content")
    assert response.ok, "PRODUCT: the original attached report is not retrievable"
    return response.body()


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_wrong_sample_report_can_be_corrected_without_replacing_evidence(app, monkeypatch, language):
    with reputation_session(app, monkeypatch, language, "AFTER-45") as (j, result, folder):
        result.update(
            goal="Recover from selecting a similar report for another specimen, attach the correct report and reopen its retained evidence.",
            novelty="The existing browser test only attaches one correct report; parser tests reject wrong hashes without an interface recovery decision.",
            nearest=[
                "test_autopsy_browser.py::test_local_sample_manual_reputation_and_team_assignment_browser",
                "test_autopsy_samples.py::test_reputation_invalid_or_mismatched_reports_fail_closed",
            ],
            decision_hypothesis="The filename is insufficient: use the visible specimen hash after rejection, retain both specimens and change only the attached report.",
        )
        files(j)
        a = quarantine(j, "attachment-01.txt", SPECIMEN_A)
        b = quarantine(j, "attachment-01-copy.txt", SPECIMEN_B)
        original_samples = samples(j)
        selected = select_subject(j, a["sha256"])
        wrong = vt_report(b["sha256"], 1793491200, 2)
        correct = vt_report(a["sha256"], 1793491200, 1)
        response = import_report(j, wrong, "attachment-01-report.json")
        result["failed_user_attempts"].append(
            {
                "selected_subject": selected,
                "attached_source_sha256": sha(wrong),
                "status": response.status,
                "response": response.json(),
                "expected_recoverable_error": True,
            }
        )
        capture(j, result, folder, "wrong-subject-rejected")
        assert response.status == 422, "PRODUCT: a report for another hash was accepted"
        assert not records(j, "reputation"), "PRODUCT: rejected report created or silently rebound an assessment"
        assert samples(j) == original_samples, "PRODUCT: rejected report altered retained samples"
        expect(j.page.locator("input[name=subject]")).to_have_value(selected)
        error = j.page.locator(".reputation-import-error")
        expect(error).to_be_visible()
        expect(error).to_contain_text(j.text("بصمة التقرير لا تطابق العينة أو المؤشر المحدد"))
        # A different visible selection must not keep an error bound to sample A.
        select_subject(j, b["sha256"])
        expect(error).not_to_be_visible()
        select_subject(j, a["sha256"])
        # Transport regression within this same recovery condition: the POST commits,
        # but one subsequent case GET fails. No result, worker or native export is mocked.
        result["fault_injection"] = "Exactly one GET /api/cases/:id returns 503 after the correct report POST; all writes and retained report bytes are real."
        requests = []
        j.page.on("request", lambda request: requests.append({"method": request.method, "path": urlsplit(request.url).path}))
        j.page.route(
            f"**/api/cases/{j.case_id}",
            lambda route: route.fulfill(status=503, json={"error": {"code": "SERVICE_UNAVAILABLE", "message": "Controlled case-read failure"}}),
            times=1,
        )
        assert import_report(j, correct, "attachment-01-corrected.json").status == 201
        saved = j.page.locator(".reputation-import-saved")
        expect(saved).to_contain_text("تم حفظ النتيجة؛ تعذر تحديث العرض" if language == "ar" else "Result saved; the view could not be refreshed")
        expect(j.page.get_by_role("button", name=j.text("استيراد نتيجة الفحص"), exact=True)).to_be_disabled()
        capture(j, result, folder, "committed-result-read-failure")
        j.click("button", "إعادة المحاولة", j.page.locator("form").filter(has=j.page.locator("input[name=vt_report]")))
        assert sum(item["method"] == "POST" and item["path"].endswith("/reputation/virustotal") for item in requests) == 1, (
            "PRODUCT: read recovery repeated the committed reputation POST"
        )
        result["post_commit_recovery_requests"] = requests
        expect(j.page.locator(".reputation-import-error")).not_to_be_visible()
        rows = records(j, "reputation")
        assert len(rows) == 1 and rows[0]["payload"]["sample_id"] == a["id"]
        assert rows[0]["payload"]["sha256"] == a["sha256"]
        assert rows[0]["payload"]["source_sha256"] == sha(correct)
        assert retained_bytes(j, rows[0]) == correct
        j.page.reload()
        j.settle()
        card = reputation_card(j, sha(correct))
        expect(card).to_be_visible()
        capture(j, result, folder, "correct-subject-retained")
        readable_record(j, card, language)
        with j.page.expect_download() as download:
            card.get_by_role("link", name=j.text("تنزيل الأصل"), exact=True).click()
        assert Path(download.value.path()).read_bytes() == correct
        assert samples(j) == original_samples and len(records(j, "reputation")) == 1
        assert_accessible(j.page)
        result["persisted_outcome"] = {
            "sample_a": a,
            "sample_b": b,
            "reputation_id": rows[0]["id"],
            "source_sha256": sha(correct),
            "download_matches_original": True,
        }
        result["outcomes"] = [
            "Wrong hash rejected with visible correction feedback",
            "Selected specimen preserved",
            "Correct report attached exactly once",
            "Original JSON reopened through the interface",
        ]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_conflicting_dated_reports_keep_history_and_do_not_establish_safety(app, monkeypatch, language):
    with reputation_session(app, monkeypatch, language, "AFTER-46") as (j, result, folder):
        result.update(
            goal="Compare contradictory dated imported assessments, retain both sources and update the bounded conclusion in a new snapshot.",
            novelty="Existing integration tests keep one report; AFTER-38 changes indicator validity, not two manually supplied sample reports with opposing statistics.",
            nearest=[
                "test_autopsy_samples.py::test_quarantine_local_analysis_and_manual_virustotal_join_the_case",
                "test_followup_decision_journeys.py::test_indicator_expiry_changes_current_assessment_without_rewriting_history",
            ],
            decision_hypothesis="A later zero detection count does not validate a specimen's safety or invalidate the preserved earlier assessment.",
        )
        files(j)
        sample = quarantine(j, "dated-attachment.txt", SPECIMEN_A)
        select_subject(j, sample["sha256"])
        first_raw = vt_report(sample["sha256"], 1793491200, 2)
        second_raw = vt_report(sample["sha256"], 1793577600, 0)
        assert import_report(j, first_raw, "assessment-2026-11-01.json").status == 201
        first = records(j, "reputation")[0]
        initial_note = (
            "The 2026-11-01 imported assessment reports two detections. Its authenticity is unverified; this does not establish execution or compromise."
        )
        snapshot_a = conclude(j, initial_note)
        path_a = report_path(j)
        hash_a = sha(json.dumps(snapshot_a["payload"], sort_keys=True).encode())
        files(j)
        select_subject(j, sample["sha256"])
        before_case = j.state()
        assert import_report(j, second_raw, "assessment-2026-11-02.json").status == 201
        history = records(j, "reputation")
        assert len(history) == 2, "PRODUCT: importing a second assessment replaced earlier evidence"
        assert next(row for row in history if row["id"] == first["id"]) == first, "PRODUCT: earlier assessment history was rewritten"
        assert j.state()["status"] == before_case["status"], "PRODUCT: zero detections automatically changed the case status"
        assert j.state()["context"] == before_case["context"], "PRODUCT: zero detections automatically changed the investigation assessment"
        capture(j, result, folder, "conflicting-history")
        for raw, expected_date, count in [(first_raw, "2026-11-01T00:00:00Z", 2), (second_raw, "2026-11-02T00:00:00Z", 0)]:
            row = next(row for row in history if row["payload"]["source_sha256"] == sha(raw))
            assert row["payload"]["examined_at"] == expected_date and row["payload"]["stats"]["malicious"] == count
            assert retained_bytes(j, row) == raw
            card = reputation_card(j, sha(raw))
            expect(card).to_contain_text(j.page.evaluate("value => formatTime(value)", expected_date))
            readable_record(j, card, language)
        final_note = "The imported 2026-11-01 report records two malicious detections; the 2026-11-02 report records zero and four undetected. Both refer to the same SHA-256. Neither source is independently authenticated. Zero detections does not establish safety; retain both dated sources and seek corroborating evidence before deciding impact."
        snapshot_b = conclude(j, final_note)
        path_b = report_path(j)
        preview_note(j, final_note)
        assert path_b != path_a
        assert sha(json.dumps(report(j, path_a)["payload"], sort_keys=True).encode()) == hash_a, "PRODUCT: updated conclusion mutated the first snapshot"
        assert len(snapshot_a["payload"]["records"]["reputation"]) == 1
        assert len(snapshot_b["payload"]["records"]["reputation"]) == 2
        assert final_note in json.dumps(snapshot_b["payload"]) and final_note not in json.dumps(snapshot_a["payload"])
        capture(j, result, folder, "qualified-conclusion-snapshot")
        assert_accessible(j.page)
        result["persisted_outcome"] = {
            "sample_sha256": sample["sha256"],
            "report_sources": [sha(first_raw), sha(second_raw)],
            "snapshot_a": path_a,
            "snapshot_a_sha256": hash_a,
            "snapshot_b": path_b,
            "snapshot_b_sha256": sha(json.dumps(snapshot_b["payload"], sort_keys=True).encode()),
            "qualified_conclusion": final_note,
        }
        result["outcomes"] = [
            "Both original reports and analysis dates retained",
            "Zero detections did not resolve or close the case",
            "Qualified conclusion saved through the interface and read in snapshot preview",
            "Original snapshot unchanged; new snapshot includes both assessments",
        ]
