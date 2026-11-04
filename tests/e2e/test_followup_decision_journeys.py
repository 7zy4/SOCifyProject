"""Follow-up user decisions at invitation, intelligence and queued-policy boundaries.

These are scripted acceptance tasks, never observations of human comprehension.
Clock/worker scheduling is explicit setup; decisions use visible controls.
"""

import hashlib
import json
import subprocess
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import expect

from socify import autopsy_intel
from tests.e2e import test_review_workflow as review_module
from tests.e2e.test_blue_team_decision_journeys import conclude
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_case_membership_journeys import grant
from tests.e2e.test_detection_workflow_journeys import finish, job, open_detection, queue, read_result, result_value
from tests.e2e.test_detection_workflow_journeys import upload as upload_scan
from tests.e2e.test_followup_handoff_journeys import manager_case
from tests.e2e.test_investigation_link_journeys import note_dialog, records
from tests.e2e.test_library_draft_journeys import intel_area, intel_draft
from tests.e2e.test_report_recovery_journeys import report, report_path
from tests.e2e.test_review_workflow import review_session
from tests.e2e.test_rule_authoring_journeys import TITLE, attach, check, publish, target
from tests.e2e.test_watchlist_intelligence_journeys import IP, inspect_enrichment, observable
from tests.e2e.test_watchlist_intelligence_journeys import upload as upload_indicator

ARTIFACTS = Path("artifacts/usability_campaign/followup-decisions")
FILES = (
    "socify/auth.py",
    "socify/teams.py",
    "socify/autopsy_intel.py",
    "socify/autopsy_detection.py",
    "socify/detection.py",
    "socify/autopsy_worker.py",
    "socify/autopsy_reports.py",
    "socify/event_identity.py",
    "socify/autopsy_pipeline.py",
    "socify/security.py",
    "static/register.js",
    "static/autopsy_operations.js",
    "static/autopsy_team.js",
    "static/autopsy.js",
    "static/localization.js",
)
SCENARIOS = {
    "AFTER-37": {
        "goal": "Renew an expired invitation, join the intended team and save the first permitted case action.",
        "decision_hypothesis": "An expired invitation needs a new manager-issued credential, not a new workspace or broader role.",
        "novelty": "Prior invite_join is an ordinary join; invite_email_recovery changes the email. This crosses invitation expiry and uses a newly issued credential before completing case work.",
        "nearest": ["artifacts/usability_campaign/security_journeys.py:invite_join", "artifacts/usability_campaign/team_journeys.py:invite_email_recovery"],
    },
    "AFTER-38": {
        "goal": "Revise an assessment when an active source's indicator expires, then use a genuinely valid update.",
        "decision_hypothesis": "A formerly supported indicator becomes unknown when its validity ends; absence of a current match is not proof of safety.",
        "novelty": "Prior unmatched/current-source stories start with no match or switch versions. Here entry validity expires during one investigation while its bundle remains active.",
        "nearest": [
            "tests/e2e/test_watchlist_intelligence_journeys.py:intel-unmatched-unknown",
            "tests/e2e/test_intel_use_journeys.py:intel-recovery-colleague-source",
        ],
    },
    "AFTER-42": {
        "goal": "Review the completed scan after a manager changes its rule while the job is queued, and save a bounded investigation conclusion.",
        "decision_hypothesis": "The scan uses active rules when execution begins; no new alerts under the revised rule does not establish benign activity.",
        "novelty": "Prior rule-updated-detection runs sequential scans and detection-continue-batch keeps the policy stable. The rule changes while this real job is pending.",
        "nearest": [
            "tests/e2e/test_rule_authoring_journeys.py:rule-updated-detection",
            "tests/e2e/test_detection_workflow_journeys.py:detection-continue-batch",
        ],
    },
}


def fingerprints():
    return {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in FILES if Path(name).exists()}


def stamp(value):
    return value.isoformat().replace("+00:00", "Z")


@contextmanager
def decision_session(app, monkeypatch, language, scenario):
    folder = ARTIFACTS / "attempts" / f"{scenario}-{language}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}"
    folder.mkdir(parents=True)
    monkeypatch.setattr(review_module, "ARTIFACTS", folder)
    try:
        with review_session(app, language, scenario) as (j, manager, result):
            result.update(
                **SCENARIOS[scenario],
                plan_id=scenario,
                phase="development acceptance; no clean-round claim",
                interpretation_kind="Scripted decision hypothesis and observed interface behavior; no human interpretation or satisfaction measurement",
                human_participants=0,
                checked_revision=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),  # noqa: S603,S607
                test_file_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                production_hashes_before=fingerprints(),
                setup_provenance="Isolated seeded accounts and one initial case. Clock aging and worker scheduling, if used, are setup only. All user decisions and corrections use visible controls.",
                evidence_folder=str(folder),
                clean_round_claim=False,
            )
            try:
                yield j, manager, result, folder
                result["outcome_classification"] = "completed scripted user task"
            except Exception as error:
                result["outcome_classification"] = "product failure" if "PRODUCT:" in str(error) else "unclassified failure pending review"
                raise
            finally:
                result["production_hashes_after"] = fingerprints()
                result["product_changed_during_attempt"] = result["production_hashes_before"] != result["production_hashes_after"]
    finally:
        path = folder / f"{scenario}-{language}.json"
        if path.exists():
            value = json.loads(path.read_text(encoding="utf-8"))
            row = {key: value.get(key) for key in ("plan_id", "language", "status", "outcome_classification", "checked_revision", "error")}
            row["evidence"] = str(path)
            with (ARTIFACTS / "attempt-ledger.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(row, ensure_ascii=False) + "\n")


def capture(j, result, folder, stage):
    result.setdefault("visible_observations", []).append({"stage": stage, "text": j.page.locator("main").inner_text()})
    for width in (1440, 390):
        j.page.set_viewport_size({"width": width, "height": 1000})
        assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "PRODUCT: horizontal page overflow"
        path = folder / f"{stage}-{width}.png"
        j.page.screenshot(path=str(path), full_page=True, mask=[j.page.locator("input[name=invitation_token],input[name=password]")])
        result.setdefault("screenshots", []).append(str(path))
    j.page.set_viewport_size({"width": 1440, "height": 1000})


def open_case_from_tool(j):
    if not urlsplit(j.page.url).path.startswith(f"/cases/{j.case_id}"):
        j.click("link", "فتح التحقيق")


def save_note(j, title, body):
    open_case_from_tool(j)
    j.click("link", "التحقيق والخط الزمني")
    dialog = note_dialog(j)
    dialog.locator("input[name=title]").fill(title)
    dialog.locator("textarea[name=body]").fill(body)
    j.click("button", "حفظ", dialog)
    expect(j.page.get_by_role("heading", name=title, exact=True)).to_be_visible()
    return next(row for row in records(j, "war_room") if row["payload"]["title"] == title and row["payload"]["body"] == body)


def invitation(manager, email):
    manager.nav("الفريق")
    form = manager.page.locator("section.panel").filter(has=manager.page.get_by_role("heading", name=manager.text("دعوة عضو جديد"), exact=True))
    form.locator("input[name=email]").fill(email)
    form.locator("input[name=role]").fill(manager.page.evaluate("autopsyLabel('analyst')"))
    manager.click("button", "حفظ", form)
    address = manager.page.get_by_label(manager.text("رابط التسجيل بالدعوة"), exact=True).input_value()
    manager.click("button", "إغلاق", manager.page.get_by_role("dialog"))
    return address


def fill_registration(j, address, email, name, *, retained=False):
    j.page.goto(address)
    j.settle()
    expected_token = parse_qs(urlsplit(address).fragment)["invitation_token"][0]
    assert j.page.locator("input[name=invitation_token]").input_value() == expected_token, (
        "PRODUCT: opening a renewed invitation in the same registration tab retained the old token"
    )
    assert "invitation_token" not in j.page.url, "PRODUCT: invitation credential remains in the address bar"
    if retained:
        expect(j.page.locator("input[name=name]")).to_have_value(name)
        expect(j.page.locator("input[name=email]")).to_have_value(email)
        expect(j.page.locator("[data-registration-error='INVALID_INVITATION']")).not_to_be_visible()
    for key, value in {"name": name, "email": email, "password": DEMO_LOGIN_VALUE}.items():
        j.page.locator(f"input[name={key}]").fill(value)
    j.page.locator("button[type=submit]").click()
    j.settle()


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_expired_invitation_is_renewed_before_first_case_action(app, database, monkeypatch, language):
    with decision_session(app, monkeypatch, language, "AFTER-37") as (j, manager, result, folder):
        manager_case(j, manager)
        email, name = "incoming.analyst@example.test", "Incoming Analyst"
        workspaces_before = database.execute("SELECT COUNT(*) FROM training_workspaces").fetchone()[0]
        expired_url = invitation(manager, email)
        token = parse_qs(urlsplit(expired_url).fragment)["invitation_token"][0]
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        database.execute("UPDATE team_invitations SET expires_at=? WHERE token_hash=?", (stamp(datetime.now(UTC) - timedelta(hours=1)), token_hash))
        result["setup_only"] = (
            "The first UI-created invitation was aged beyond its one-day validity in the isolated database. No user or membership was inserted by setup."
        )
        j.page.locator(".account-menu > summary").click()
        j.click("button", "خروج", j.page.locator(".account-menu"))
        fill_registration(j, expired_url, email, name)
        expect(j.page.locator("[data-registration-error='INVALID_INVITATION']")).to_be_visible()
        expect(j.page.locator("input[name=name]")).to_have_value(name)
        expect(j.page.locator("input[name=email]")).to_have_value(email)
        assert not database.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone(), "PRODUCT: expired invitation created an account"
        capture(j, result, folder, "expired-invitation-rejected")
        valid_url = invitation(manager, email)
        assert valid_url != expired_url
        fill_registration(j, valid_url, email, name, retained=True)
        expect(j.page).to_have_url(j.base + "/login")
        j.login(email)
        identity = j.page.evaluate("api('/api/auth/me')")["user"]
        assert identity["role"] == "analyst", "PRODUCT: renewed invitation broadened the assigned role"
        assert database.execute("SELECT COUNT(*) FROM workspace_memberships WHERE user_id=?", (identity["id"],)).fetchone()[0] == 1
        assert database.execute("SELECT COUNT(*) FROM training_workspaces").fetchone()[0] == workspaces_before
        assert database.execute("SELECT consumed_at FROM team_invitations WHERE token_hash=?", (token_hash,)).fetchone()[0] is None
        grant(manager, name)
        j.nav("إدارة القضايا")
        j.page.locator("a.case-link").filter(has_text="Authorized maintenance investigation").click()
        j.settle()
        saved = save_note(
            j, "First permitted shift review", "Joined the intended team with a renewed invitation and reviewed the explicitly assigned investigation."
        )
        assert saved["created_by"] == identity["id"], "PRODUCT: new member action attributed to another account"
        j.nav("الفريق")
        expect(j.page.get_by_role("heading", name=j.text("دعوة عضو جديد"), exact=True)).to_have_count(0)
        result["persisted_outcome"] = {"member_id": identity["id"], "case_id": j.case_id, "record_id": saved["id"], "role": identity["role"]}
        result["outcomes"] = [
            "Expired invitation rejected with retained identity fields",
            "Renewed invitation joined the original team once",
            "Correct limited role retained",
            "Authorized first investigation action saved",
        ]
        assert_accessible(j.page)
        capture(j, result, folder, "new-member-permitted-work")


def publish_indicator(manager, version, valid_until, verdict="malicious"):
    manager.nav("مكتبة التحليل المحلي")
    intel_draft(manager)
    scope = intel_area(manager)
    scope.locator("input[name=version]").fill(version)
    item = {"type": "ip", "value": IP, "verdict": verdict, "confidence": 80, "valid_from": "2020-01-01T00:00:00Z", "valid_until": valid_until}
    scope.locator("input[type=file]").set_input_files({"name": "validity-window.json", "mimeType": "application/json", "buffer": json.dumps([item]).encode()})
    manager.click("button", "حفظ", scope)
    listed = manager.page.locator("section.panel").filter(has=manager.page.get_by_role("heading", name=manager.text("إصدارات مصادر TI وGeoIP"), exact=True))
    manager.click("button", "تفعيل الإصدار", listed.locator("tbody tr").first)


def enrich(j):
    j.nav("استخبارات التهديدات")
    dialog = inspect_enrichment(j)
    j.click("button", "إثراء محلي بالإصدارات الحالية", dialog)
    return inspect_enrichment(j)


def preview_note(j, text):
    j.page.locator("summary").filter(has_text=j.text("عرض بيانات النسخة للمراجعة")).first.click()
    preview = j.page.locator(".report-preview").first
    data = preview.locator("dt").filter(has_text=j.text("سجلات التحقيق")).locator("xpath=following-sibling::dd[1]")
    for _ in range(20):
        collapsed = data.locator("details:not([open]) > summary:visible")
        if not collapsed.count():
            break
        collapsed.first.click()
    expect(data.get_by_text(text, exact=True)).to_be_visible()


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_indicator_expiry_changes_current_assessment_without_rewriting_history(app, monkeypatch, language):
    with decision_session(app, monkeypatch, language, "AFTER-38") as (j, manager, result, folder):
        manager_case(j, manager)
        start = datetime.now(UTC).replace(microsecond=0)
        current = [start]
        monkeypatch.setattr(autopsy_intel, "utc_now", lambda: current[0])
        monkeypatch.setattr(autopsy_intel, "iso_now", lambda: stamp(current[0]))
        end = start + timedelta(hours=1)
        result["setup_only"] = {
            "clock": "Only local intelligence lookup clock advances; browser/session clock does not change.",
            "start": stamp(start),
            "entry_expires": stamp(end),
            "bundle_expires": "2030-01-01",
        }
        publish_indicator(manager, "1", stamp(end))
        upload_indicator(j)
        dialog = enrich(j)
        before = observable(j)["enrichment"]
        assert before["verdict"] == "malicious" and len(before["matches"]) == 1
        expect(dialog).to_contain_text(IP)
        capture(j, result, folder, "valid-indicator-assessment")
        j.click("button", "إغلاق", dialog)
        initial_note = "The retained indicator currently has a matching time-limited source assessment; this alone does not prove a successful compromise."
        open_case_from_tool(j)
        original = conclude(j, initial_note)
        original_path = report_path(j)
        original_hash = hashlib.sha256(json.dumps(original["payload"], sort_keys=True).encode()).hexdigest()
        current[0] = end + timedelta(seconds=1)
        dialog = enrich(j)
        expired = observable(j)["enrichment"]
        assert expired["status"] == "no_match" and expired["verdict"] == "unknown" and not expired["matches"], (
            "PRODUCT: expired entry still supplies a current verdict"
        )
        assert expired["configuration_sha256"] == before["configuration_sha256"], "Fixture error: the bundle changed instead of entry validity"
        expect(dialog).to_contain_text(j.text("غير معروف"))
        capture(j, result, folder, "entry-expired-current-result")
        j.click("button", "إغلاق", dialog)
        gap_note = "The previously matching source entry has expired. Current enrichment is unknown, not benign; retain the historical assessment and request a current supported source."
        saved_gap = save_note(j, "Expired intelligence requires review", gap_note)
        retained = report(j, original_path)
        assert hashlib.sha256(json.dumps(retained["payload"], sort_keys=True).encode()).hexdigest() == original_hash, (
            "PRODUCT: expiry changed a retained report snapshot"
        )
        publish_indicator(manager, "2", stamp(current[0] + timedelta(days=7)), verdict="suspicious")
        dialog = enrich(j)
        updated = observable(j)["enrichment"]
        assert updated["verdict"] == "suspicious" and updated["matches"][0]["version"] == "2"
        capture(j, result, folder, "valid-replacement-assessment")
        j.click("button", "إغلاق", dialog)
        final_note = "A newly valid source supports a suspicious assessment. The expired malicious assessment remains historical; no benign finding or successful compromise is inferred from the temporary lack of a match."
        open_case_from_tool(j)
        fresh = conclude(j, final_note)
        preview_note(j, final_note)
        assert report_path(j) != original_path
        historical = [r["payload"]["verdict"] for r in records(j, "analysis") if r["payload"].get("analysis_type") == "local_intelligence"]
        assert {"malicious", "unknown", "suspicious"}.issubset(historical), "PRODUCT: enrichment history was replaced instead of retained"
        result["persisted_outcome"] = {
            "uncertainty_note_id": saved_gap["id"],
            "prior_snapshot_sha256": original_hash,
            "new_report_id": fresh["id"] if "id" in fresh else report_path(j),
            "retained_assessments": historical,
        }
        result["native_delivery_claim"] = False
        result["outcomes"] = [
            "Entry expiry in an active bundle produced unknown, never benign",
            "Uncertainty documented through the investigation UI",
            "Manager's valid replacement used by the analyst",
            "All three assessments and the prior snapshot retained",
            "Updated conclusion read in a new report snapshot preview",
        ]
        assert_accessible(j.page)
        capture(j, result, folder, "updated-conclusion-preview")


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_rule_change_while_scan_is_pending_uses_start_time_policy(app, monkeypatch, language):
    with decision_session(app, monkeypatch, language, "AFTER-42") as (j, manager, result, folder):
        manager_case(j, manager)
        upload_scan(j, 2, prefix="Suspicious gateway")
        manager.nav("مكتبة التحليل المحلي")
        attach(manager, "Suspicious gateway")
        check(manager)
        first = publish(manager)
        assert first.status == 201
        result["old_policy"] = {"rule_id": first.json()["id"], "version": first.json()["version"], "match": "Suspicious gateway", "title": TITLE}
        open_detection(j)
        identifier = queue(j)
        queued = job(j, identifier)
        assert queued["state"] == "queued"
        result["setup_only"] = (
            "The real local worker is not started until after a second actor publishes the new rule. No response, result or alert is stubbed. Two retained events were imported via UI before either scan."
        )
        result["queued_parameters"] = queued.get("parameters")
        capture(j, result, folder, "queued-before-rule-change")
        attach(manager, "Revised gateway")
        target(manager)
        check(manager)
        second = publish(manager)
        assert second.status == 201 and second.json()["id"] == first.json()["id"]
        result["new_policy"] = {"rule_id": second.json()["id"], "version": second.json()["version"], "match": "Revised gateway", "title": TITLE}
        capture(manager, result, folder, "manager-published-changed-rule")
        completed = finish(j, app, identifier)
        dialog = read_result(j)
        evaluated = result_value(j, dialog, "السجلات المفحوصة").inner_text().translate(str.maketrans("٠١٢٣٤٥٦٧٨٩", "0123456789"))
        assert evaluated.strip() == "2", "PRODUCT: the scan did not cover the two requested retained events"
        result["result_visible_text"] = dialog.inner_text()
        record = next(r for r in records(j, "analysis") if r["id"] == completed["result_record_id"])
        result["retained_result"] = record
        result["completed_job"] = completed
        capture(j, result, folder, "completed-after-rule-change")
        # The owner-adjudicated contract is rules active at execution, not at queue time.
        # The new selector cannot match the retained events; the old one could.
        # Historical attribution is a separate audit enhancement, not a UI revision field.
        payload = record["payload"]
        alert_count = result_value(j, dialog, "التنبيهات الجديدة").inner_text().translate(str.maketrans("٠١٢٣٤٥٦٧٨٩", "0123456789"))
        assert alert_count.strip() == "0" and payload["alert_ids"] == [], "PRODUCT: the queued scan used the superseded matching rule"
        assert payload["evaluated_events"] == 2 and payload["status"] == "evaluated"
        result["retained_policy_reference"] = next(
            (
                payload[key]
                for key in ("rules", "rule_set", "rules_snapshot", "ruleset", "executed_rules", "rule_versions", "execution_policy")
                if payload.get(key)
            ),
            None,
        )
        result["execution_contract_review"] = (
            "Active rules at worker execution inside one BEGIN IMMEDIATE transaction; no within-batch policy drift established."
        )
        result["audit_enhancement"] = (
            "Retain a rule-set fingerprint/reference with the run for later audit without adding rule revision numbers to the interface."
        )
        j.click("button", "إغلاق", dialog)
        note = "The queued scan completed over two retained events without new alerts after the detection rule changed before execution. No new alert is not proof of benign activity; retain the source events for manual investigation."
        saved = save_note(j, "Queued rule-change review", note)
        result["persisted_outcome"] = {"case_id": j.case_id, "record_id": saved["id"], "result_record_id": record["id"]}
        result["outcomes"] = [
            "Rule changed by a separate actor before the queued job began",
            "Completed result agrees with execution-time rule contract",
            "Bounded investigation conclusion saved without inferring safety",
        ]
        assert_accessible(j.page)
        capture(j, result, folder, "queued-policy-conclusion-saved")
