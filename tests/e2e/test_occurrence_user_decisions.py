"""Decide from corrected observations and only the source occurrences granted to me."""

import hashlib
import json
import subprocess
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import pytest
from playwright.sync_api import expect

import tests.e2e.test_review_workflow as review_module
from tests.e2e.test_batch_boundary_journeys import restrict_batch
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_report_recovery_journeys import report, report_path
from tests.e2e.test_review_workflow import review_session
from tests.e2e.test_scope_continuity_decision_journeys import save_note, stored_logs

ARTIFACTS = Path("artifacts/usability_campaign/occurrence-user-decisions")
PRODUCTION = (
    "socify/event_identity.py",
    "socify/autopsy_ingestion.py",
    "socify/ingestion.py",
    "socify/events.py",
    "socify/autopsy_reports.py",
    "static/autopsy_data.js",
    "static/autopsy.js",
)
GOALS = {
    "AFTER-40": "Retain conflicting provider observations under one identifier and prepare a qualified new report snapshot without rewriting earlier facts.",
    "AFTER-41": "Review and export a shared event through my permitted origin, lose that origin safely, and resume after explicit restoration.",
}


@contextmanager
def occurrence_session(app, monkeypatch, language, scenario):
    folder = ARTIFACTS / "attempts" / f"{scenario}-{language}-{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}"
    folder.mkdir(parents=True)
    monkeypatch.setattr(review_module, "ARTIFACTS", folder)
    try:
        with review_session(app, language, scenario) as (j, manager, result):
            result.update(
                plan_id=scenario,
                goal=GOALS[scenario],
                human_participants=0,
                semantic_conditions=1,
                interpretation_kind="Scripted simulated task with visible evidence; not a blind human comprehension study",
                initial_interpretation=None,
                checked_revision=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),  # noqa: S603,S607
                production_hashes={name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in PRODUCTION},
                evidence_folder=str(folder),
                setup_provenance="Isolated seeded accounts and harmless provider exports; user actions use visible controls. Read-only service checks assess retained facts and access.",
                native_output_claim=False,
            )
            try:
                yield j, manager, result, folder
                result["outcome_classification"] = "completed simulated decision"
            except Exception as error:
                result["outcome_classification"] = "product failure" if "PRODUCT:" in str(error) else "unclassified failure pending review"
                raise
            finally:
                result["production_hashes_after"] = {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in PRODUCTION}
    finally:
        path = folder / f"{scenario}-{language}.json"
        if path.exists():
            saved = json.loads(path.read_text(encoding="utf-8"))
            row = {key: saved.get(key) for key in ("scenario", "language", "status", "outcome_classification", "error", "checked_revision")}
            row["evidence"] = str(path)
            with (ARTIFACTS / "attempt-ledger.jsonl").open("a", encoding="utf-8") as output:
                output.write(json.dumps(row, ensure_ascii=False) + "\n")


def observation(**changes):
    return {
        "source": "identity-gateway-export",
        "external_id": "GATEWAY-447",
        "timestamp": "2026-11-02T08:00:00Z",
        "hostname": "IDENTITY-GATEWAY",
        "title": "Gateway original failed observation",
        "username": "service-before",
        "outcome": "failed",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc AAAA",
        **changes,
    }


def upload(j, filename, row, *, pretty=False):
    j.click("link", "السجلات والأدلة")
    content = json.dumps([row], ensure_ascii=False, sort_keys=pretty, indent=2 if pretty else None).encode()
    j.page.locator("input[name=file]").set_input_files({"name": filename, "mimeType": "application/json", "buffer": content})
    j.page.locator("summary").filter(has_text=j.text("خيارات الاستيراد")).click()
    j.page.locator("input[name=source_label]").fill("Identity gateway export")
    j.click("button", "استيراد وفحص فوري")
    expect(j.page.get_by_role("cell", name=row["title"], exact=True).first).to_be_visible()
    imports = j.page.evaluate("id => api(`/api/cases/${id}/imports`)", j.case_id)["items"]
    job = next(item for item in imports if item["original_filename"] == filename)
    return job, content


def detail(j, title):
    row = j.page.get_by_role("row").filter(has=j.page.get_by_role("cell", name=title, exact=True))
    j.click("button", "تفاصيل السجل", row)
    dialog = j.page.get_by_role("dialog")
    value = json.loads(dialog.locator("pre").inner_text())
    return value, dialog


def capture(j, folder, stage):
    for width in (1440, 390):
        j.page.set_viewport_size({"width": width, "height": 1000})
        j.page.evaluate("window.scrollTo({top: 0, behavior: 'instant'})")
        assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "PRODUCT: horizontal document overflow"
        j.page.screenshot(path=str(folder / f"{stage}-{width}.png"), full_page=True)
        j.page.screenshot(path=str(folder / f"{stage}-{width}-viewport.png"))
    j.page.set_viewport_size({"width": 1440, "height": 1000})


def preserve_as_evidence(j, title):
    field = j.page.locator("input[name=event_id]")
    field.fill(title)
    field.press("ArrowDown")
    j.page.get_by_role("option").filter(has_text=title).first.click()
    j.click("button", "حفظ", field.locator("xpath=ancestor::form"))


def original(j, filename):
    row = j.page.get_by_role("row").filter(has=j.page.get_by_role("cell", name=filename, exact=True))
    link = row.get_by_role("link", name=j.text("تنزيل الأصل"), exact=True)
    href = link.get_attribute("href")
    with j.page.expect_download() as downloaded:
        link.click()
    return Path(downloaded.value.path()).read_bytes(), href


def export_json(j):
    link = j.page.locator('a[href*="/logs/export?format=json&redacted=0"]')
    href = link.get_attribute("href")
    with j.page.expect_download() as downloaded:
        link.click()
    content = Path(downloaded.value.path()).read_text(encoding="utf-8-sig")
    return json.loads(content), content, href


def prepare_snapshot(j):
    j.click("link", "التقارير والمراجعة")
    j.click("button", "إعداد تقرير جديد")
    path = report_path(j)
    value = report(j, path)
    j.click("button", "إلغاء المعالجة")
    assert report(j, path)["job"]["state"] == "cancelled"
    return path, value


def read_snapshot_note(j, note):
    revision = j.page.locator(".report-revision").first
    revision.locator("summary").filter(has_text=j.text("عرض بيانات النسخة للمراجعة")).click()
    preview = revision.locator(".report-preview")
    records = preview.locator("dt").filter(has_text=j.text("سجلات التحقيق")).locator("xpath=following-sibling::dd[1]")
    for _ in range(20):
        collapsed = records.locator("details:not([open]) > summary:visible")
        if not collapsed.count():
            break
        summary = collapsed.first.element_handle()
        assert summary is not None
        summary.click()
        j.page.wait_for_function("summary => summary.parentElement.open && summary.parentElement.children.length > 1", arg=summary)
    expect(records.get_by_text(note, exact=True)).to_be_visible()


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_corrected_provider_facts_remain_distinct_and_support_a_qualified_report(app, monkeypatch, language):
    with occurrence_session(app, monkeypatch, language, "AFTER-40") as (j, _manager, result, folder):
        first = observation()
        first_job, first_bytes = upload(j, "gateway-before.json", first)
        before = stored_logs(j)
        first_alerts = j.page.evaluate("id => api(`/api/cases/${id}/alerts`)", j.case_id)["items"]
        assert before["total"] == 1 and first_alerts, "Fixture must retain one observation and its rule proof"
        viewed, dialog = detail(j, first["title"])
        expect(dialog).to_contain_text("service-before")
        expect(dialog).to_contain_text("failed")
        j.click("button", "إغلاق", dialog)
        preserve_as_evidence(j, first["title"])
        save_note(j, "Provider GATEWAY-447 first receipt names service-before with a failed outcome. Preserve this source observation pending confirmation.")
        old_path, old_report = prepare_snapshot(j)

        corrected = observation(title="Gateway corrected successful observation", username="service-after", outcome="success")
        second_job, second_bytes = upload(j, "gateway-corrected.json", corrected, pretty=True)
        current = stored_logs(j)
        assert current["total"] == 2 and second_job["accepted"] == 1, "PRODUCT: changed provider facts were swallowed as an unchanged duplicate"
        assert len({row["id"] for row in current["items"]}) == 2, "PRODUCT: corrected observation overwrote the retained event"
        retained_first = next(row for row in current["items"] if row["id"] == before["items"][0]["id"])
        for name in ("title", "event_time", "username", "raw_payload"):
            assert retained_first.get(name) == before["items"][0].get(name), f"PRODUCT: original {name} changed after provider correction"
        viewed_second, dialog = detail(j, corrected["title"])
        expect(dialog).to_contain_text("service-after")
        expect(dialog).to_contain_text("success")
        expect(dialog).to_contain_text("GATEWAY-447")
        capture(j, folder, "corrected-observation-details")
        j.click("button", "إغلاق", dialog)
        original_again, dialog = detail(j, first["title"])
        assert original_again == viewed, "PRODUCT: earlier observation details mutated"
        j.click("button", "إغلاق", dialog)
        preserve_as_evidence(j, corrected["title"])
        for filename, expected in (("gateway-before.json", first_bytes), ("gateway-corrected.json", second_bytes)):
            downloaded, _ = original(j, filename)
            assert downloaded == expected, "PRODUCT: provider original bytes changed"
        after_alerts = j.page.evaluate("id => api(`/api/cases/${id}/alerts`)", j.case_id)["items"]
        for old in first_alerts:
            assert next(row for row in after_alerts if row["id"] == old["id"]) == old, "PRODUCT: correction silently rewrote an earlier alert"
        conclusion = (
            "GATEWAY-447 has conflicting provider receipts at the same observed time: service-before/failed and service-after/success. "
            "Both originals are retained. The identifier alone does not establish two independent incidents; confirm the correction with the source owner before choosing an account or outcome."
        )
        result["initial_interpretation"] = (
            "Observed two different account/outcome combinations sharing the same provider identifier and timestamp; retain both and qualify the conclusion."
        )
        save_note(j, conclusion)
        new_path, new_report = prepare_snapshot(j)
        payload = json.dumps(new_report["payload"], ensure_ascii=False)
        assert conclusion in payload and "service-before" in payload and "service-after" in payload, "PRODUCT: new snapshot does not represent the discrepancy"
        assert new_report["id"] != old_report["id"] and new_report["sha256"] != old_report["sha256"]
        assert report(j, old_path)["payload"] == old_report["payload"] and report(j, old_path)["sha256"] == old_report["sha256"], (
            "PRODUCT: new source facts modified the earlier report snapshot"
        )
        assert len(j.state()["reports"]) == 2 and j.state()["status"] != "closed"
        read_snapshot_note(j, conclusion)
        assert_accessible(j.page)
        capture(j, folder, "qualified-report-prepared")
        result.update(
            before_events=before,
            after_events=current,
            receipt_ids=[first_job["id"], second_job["id"]],
            receipt_hashes=[hashlib.sha256(first_bytes).hexdigest(), hashlib.sha256(second_bytes).hexdigest()],
            visible_correction=viewed_second,
            report_snapshots=[{"path": old_path, "sha256": old_report["sha256"]}, {"path": new_path, "sha256": new_report["sha256"]}],
            outcomes=[
                "Both changed source observations retained",
                "Earlier alert, original and snapshot unchanged",
                "Qualified new report snapshot prepared from both receipts",
                "No native PDF or closure claimed",
            ],
        )


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_shared_event_keeps_only_permitted_origin_through_revocation_and_restoration(app, monkeypatch, language):
    with occurrence_session(app, monkeypatch, language, "AFTER-41") as (j, manager, result, folder):
        case_id, case_url = j.case_id, j.case_url
        analyst_name = j.page.evaluate("state.user.name")
        manager.login("manager@socify.local")
        manager.page.goto(case_url)
        manager.settle()
        shared = observation(title="Assigned shared gateway observation")
        hidden_job, hidden_bytes = upload(manager, "restricted-provider-receipt.json", shared)
        allowed_job, allowed_bytes = upload(manager, "assigned-provider-receipt.json", shared, pretty=True)
        assert (allowed_job["accepted"], allowed_job["skipped"]) == (0, 1), "Fixture requires one canonical event with two occurrences"
        restrict_batch(manager, "restricted-provider-receipt.json")
        restrict_batch(manager, "assigned-provider-receipt.json", analyst_name)
        j.click("link", "السجلات والأدلة")
        expect(j.page.locator("main")).not_to_contain_text("restricted-provider-receipt.json")
        expect(j.page.get_by_role("link", name=j.text("التحقيق والخط الزمني"), exact=True)).to_have_count(0)
        expect(j.page.get_by_role("link", name=j.text("التقارير والمراجعة"), exact=True)).to_have_count(0)
        visible = stored_logs(j)
        assert visible["total"] == 1 and visible["items"][0]["import_job_id"] == allowed_job["id"], "PRODUCT: canonical event chose a forbidden origin"
        viewed, dialog = detail(j, shared["title"])
        detail_text = dialog.locator("pre").inner_text()
        hidden_hash, allowed_hash = hashlib.sha256(hidden_bytes).hexdigest(), hashlib.sha256(allowed_bytes).hexdigest()
        assert hidden_hash not in detail_text and allowed_hash in detail_text, "PRODUCT: restricted primary provenance leaked through event details"
        assert viewed["import_job_id"] == allowed_job["id"]
        j.click("button", "إغلاق", dialog)
        downloaded, original_url = original(j, "assigned-provider-receipt.json")
        assert downloaded == allowed_bytes
        exported, export_text, export_url = export_json(j)
        assert len(exported) == 1 and exported[0]["import_job_id"] == allowed_job["id"]
        assert hidden_hash not in export_text and "restricted-provider-receipt.json" not in export_text
        assert allowed_hash in export_text
        result["initial_interpretation"] = (
            "Only the assigned receipt is visible and exportable; investigation context and report controls correctly require full case access."
        )
        capture(j, folder, "permitted-origin-only")

        restrict_batch(manager, "assigned-provider-receipt.json")
        stale_row = j.page.get_by_role("row").filter(has=j.page.get_by_role("cell", name=shared["title"], exact=True))
        j.click("button", "تفاصيل السجل", stale_row)
        expect(j.page.get_by_role("dialog")).to_have_count(0)
        expect(j.page.locator("#global-message")).to_be_visible()
        j.click("button", "بحث السجلات")
        expect(j.page.get_by_text(j.text("لا سجلات في النطاق"), exact=True)).to_be_visible()
        expect(j.page.locator("main")).not_to_contain_text("assigned-provider-receipt.json")
        expect(j.page.locator("main")).not_to_contain_text("restricted-provider-receipt.json")
        assert stored_logs(j)["total"] == 0, "PRODUCT: loss of allowed origin fell back to restricted provenance"
        denied_original = j.page.request.get(j.base + original_url)
        denied_event = j.page.request.get(f"{j.base}/api/cases/{case_id}/logs/{viewed['id']}")
        empty_export = j.page.request.get(j.base + export_url)
        assert denied_original.status in {403, 404} and denied_event.status in {403, 404}
        assert empty_export.status == 200 and empty_export.json() == [], "PRODUCT: a saved export URL exposed an unauthorized occurrence"
        capture(j, folder, "all-occurrences-withheld")
        result["revocation_oracle"] = {"original_status": denied_original.status, "event_status": denied_event.status, "export_count": len(empty_export.json())}

        j.click("link", "جميع القضايا")
        j.create_case()
        independent_case = j.case_id
        save_note(j, "Unrelated authorized review remains available while access to another receipt is withheld.")
        result["continuity_only"] = {"independent_case_id": independent_case, "note_saved": True, "not_substitute_for_original_task": True}
        restrict_batch(manager, "assigned-provider-receipt.json", analyst_name)
        j.case_id, j.case_url = case_id, case_url
        j.page.goto(case_url + "?tab=logs")
        j.settle()
        restored = stored_logs(j)
        assert restored["total"] == 1 and restored["items"][0]["id"] == viewed["id"]
        assert restored["items"][0]["import_job_id"] == allowed_job["id"]
        expect(j.page.locator("main")).not_to_contain_text("restricted-provider-receipt.json")
        expect(j.page.get_by_role("link", name=j.text("التقارير والمراجعة"), exact=True)).to_have_count(0)
        restored_download, _ = original(j, "assigned-provider-receipt.json")
        assert restored_download == allowed_bytes
        restored_export, restored_text, _ = export_json(j)
        assert len(restored_export) == 1 and hidden_hash not in restored_text and allowed_hash in restored_text
        assert_accessible(j.page)
        capture(j, folder, "permitted-origin-restored")
        result.update(
            allowed_receipt=allowed_job["id"],
            restricted_receipt_oracle=hidden_job["id"],
            source_hashes={"allowed": allowed_hash, "restricted": hidden_hash},
            permission_scope="Partial batch review/export only; no partial investigation note or report claimed",
            outcomes=[
                "One shared event presented through the permitted receipt",
                "Original bytes and export provenance remain scoped",
                "Revocation removed access without fallback",
                "Explicit restoration resumed the original review/export task",
                "Unrelated case action verified separately as continuity",
            ],
        )
