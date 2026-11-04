"""Scoped decisions after permission, account, alert, and source boundaries."""

import hashlib
import json
import subprocess
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import expect

import tests.e2e.test_review_workflow as review_module
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_investigation_link_journeys import note_dialog, records
from tests.e2e.test_performance_goal_journeys import counter, number
from tests.e2e.test_report_recovery_journeys import report, report_path
from tests.e2e.test_review_workflow import review_session

ARTIFACTS = Path("artifacts/usability_campaign/scope-continuity-decisions")
SCENARIOS = {
    "NEXT-26": "Continue my own investigation after my temporary management access ends.",
    "NEXT-27": "Use a shared workstation for my own case without accessing the previous account's team work.",
    "NEXT-29": "Resolve the final noisy alert and finish its required report while leaving independent closure to the reviewer.",
    "NEXT-30": "Import reordered overlapping exports and investigate only the genuinely new event.",
}
PRODUCTION = (
    "socify/soc_insights.py",
    "socify/security.py",
    "socify/ingestion.py",
    "socify/events.py",
    "static/soc-insights.js",
    "static/app.js",
    "socify/event_identity.py",
    "socify/sources.py",
    "socify/autopsy_pipeline.py",
    "socify/autopsy_ingestion.py",
    "socify/case_counts.py",
    "socify/cases.py",
    "socify/windows_logon.py",
    "socify/autopsy_capsules.py",
    "socify/autopsy_reports.py",
)


@contextmanager
def decision_session(app, monkeypatch, language, scenario):
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    folder = ARTIFACTS / "attempts" / f"{scenario}-{language}-{stamp}"
    folder.mkdir(parents=True)
    monkeypatch.setattr(review_module, "ARTIFACTS", folder)
    try:
        with review_session(app, language, scenario) as (j, manager, result):
            result.update(
                plan_id=scenario,
                checked_revision=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),  # noqa: S603,S607
                production_hashes={name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in PRODUCTION},
                goal=SCENARIOS[scenario],
                human_participants=0,
                interpretation_kind="Scripted simulated task with retained-state assessment; no claim of blind human comprehension",
                initial_interpretation=SCENARIOS[scenario],
                setup_provenance="Isolated seeded accounts and prepared history; all task actions use visible controls. API/DB only set up preconditions or verify retained results.",
                evidence_folder=str(folder),
            )
            try:
                yield j, manager, result, folder
                result["outcome_classification"] = "passed after product fix" if scenario == "NEXT-30" else "first-attempt success"
            except Exception as error:
                result["outcome_classification"] = "product failure" if "PRODUCT:" in str(error) else "unclassified failure pending review"
                raise
            finally:
                result["production_hashes_after"] = {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in PRODUCTION}
    finally:
        path = folder / f"{scenario}-{language}.json"
        if path.exists():
            result = json.loads(path.read_text(encoding="utf-8"))
            row = {key: result.get(key) for key in ("plan_id", "language", "checked_revision", "status", "outcome_classification", "error")}
            row["evidence"] = str(path)
            with (ARTIFACTS / "attempt-ledger.jsonl").open("a", encoding="utf-8") as output:
                output.write(json.dumps(row, ensure_ascii=False) + "\n")


def capture(j, folder, stage):
    for width in (1440, 390):
        j.page.set_viewport_size({"width": width, "height": 1000})
        assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "PRODUCT: horizontal document overflow"
        j.page.screenshot(path=str(folder / f"{stage}-{width}.png"), full_page=True)
    j.page.set_viewport_size({"width": 1440, "height": 1000})


def save_note(j, message):
    j.click("link", "التحقيق والخط الزمني")
    dialog = note_dialog(j)
    dialog.locator("textarea[name=body]").fill(message)
    j.click("button", "حفظ", dialog)
    assert any(item["payload"]["body"] == message for item in records(j, "war_room")), "PRODUCT: investigation decision was not retained"


def personal_case(j, case_id):
    j.nav("الأداء")
    link = j.page.locator(f"#performance-cases a[href='/cases/{case_id}']")
    expect(link).to_be_visible()
    link.click()
    j.settle()
    j.case_id, j.case_url = case_id, f"{j.base}/cases/{case_id}"


def upload(j, filename, rows, *, pretty=False):
    j.click("link", "السجلات والأدلة")
    content = json.dumps(rows, ensure_ascii=False, indent=4 if pretty else None, sort_keys=pretty).encode()
    j.page.locator("input[name=file]").set_input_files({"name": filename, "mimeType": "application/json", "buffer": content})
    j.click("button", "استيراد وفحص فوري")
    expect(j.page.get_by_role("cell", name=rows[0]["title"], exact=True).first).to_be_visible()


def stored_logs(j):
    return j.page.evaluate("id => api(`/api/cases/${id}/logs?limit=100`)", j.case_id)


def prepare_private_history(manager):
    return manager.page.evaluate("() => api('/api/cases',{method:'POST',body:{title:'Restricted management escalation history'}})")["id"]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_role_loss_removes_loaded_team_graphics_but_personal_work_continues(app, database, monkeypatch, language):
    with decision_session(app, monkeypatch, language, "NEXT-26") as (j, manager, result, folder):
        person = j.page.evaluate("state.user.name")
        # Prepared temporary role is context; ending it is a separate user's visible action.
        database.execute("UPDATE users SET role='soc_manager' WHERE email='analyst@socify.local'")
        manager.login("manager@socify.local")
        secret_id = prepare_private_history(manager)
        j.page.reload()
        j.settle()
        j.nav("الأداء")
        expect(j.page.locator(f"#performance-cases a[href='/cases/{secret_id}']")).to_be_visible()
        capture(j, folder, "privileged-before")
        result["initial_visible_workload"] = counter(j, "قضايا نشطة")
        manager.nav("الفريق")
        row = manager.page.locator("tr").filter(has=manager.page.get_by_role("cell", name="analyst@socify.local", exact=True))
        manager.click("button", "إدارة العضو", row)
        dialog = manager.page.get_by_role("dialog")
        role_form = dialog.locator("form").filter(has=manager.page.locator("input[name=role]"))
        role_form.locator("input[name=role]").fill(manager.page.evaluate("autopsyLabel('analyst')"))
        manager.click("button", "حفظ", role_form)
        assert database.execute("SELECT role FROM users WHERE email='analyst@socify.local'").fetchone()[0] == "analyst"
        j.click("button", "تطبيق", j.page.locator(".filter-row"))
        capture(j, folder, "denied-refresh")
        assert urlsplit(j.page.url).path == "/login", "PRODUCT: revoked management session did not return to sign-in"
        assert j.page.locator(".performance-trend, .performance-severity, .performance-ring").count() == 0, (
            "PRODUCT: privileged derived graphics retained after rejection"
        )
        assert "Restricted management escalation history" not in j.page.locator("main").inner_text(), "PRODUCT: denied chart retains management case"
        result["revoked_session_status"] = j.page.request.get(j.base + "/api/soc/performance?member=team").status
        assert result["revoked_session_status"] in {401, 403}
        j.login("analyst@socify.local")
        assert j.page.request.get(j.base + "/api/soc/performance?member=team").status == 403
        personal_case(j, j.case_id)
        save_note(j, "Continued my retained investigation after temporary management duty ended.")
        assert_accessible(j.page)
        capture(j, folder, "personal-work-complete")
        result["outcomes"] = ["Loaded team graphics cleared after role loss", "Team API remains denied", f"Personal investigation saved by {person}"]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_shared_workstation_history_cannot_resurrect_the_prior_accounts_charts(app, monkeypatch, language):
    with decision_session(app, monkeypatch, language, "NEXT-27") as (analyst, j, result, folder):
        case_id = analyst.case_id
        j.login("manager@socify.local")
        secret_id = prepare_private_history(j)
        j.nav("الأداء")
        j.click("link", "الفريق", j.page.locator(".channel-tabs"))
        expect(j.page.locator(f"#performance-cases a[href='/cases/{secret_id}']")).to_be_visible()
        saved_url = j.page.url
        capture(j, folder, "previous-account")
        j.page.locator(".account-menu summary").click()
        j.page.locator("form[action='/logout'] button").click()
        j.page.wait_for_url("**/login")
        j.login("analyst@socify.local")
        for direction in ("back", "back", "forward"):
            getattr(j.page, f"go_{direction}")()
            j.settle()
            text = j.page.locator("body").inner_text()
            result.setdefault("history_trace", []).append({"direction": direction, "url": j.page.url, "visible_text": text})
            assert "Restricted management escalation history" not in text, "PRODUCT: previous account's management history resurrected"
        j.page.goto(saved_url)
        j.settle()
        capture(j, folder, "saved-team-url")
        expect(j.page.get_by_text(j.text("تعذر تحميل الأداء"), exact=True)).to_be_visible()
        assert j.page.locator(".performance-trend, .performance-severity, .performance-ring").count() == 0, (
            "PRODUCT: prior account's chart survived sign-in boundary"
        )
        assert j.page.request.get(j.base + "/api/soc/performance?member=team").status == 403
        personal_case(j, case_id)
        save_note(j, "Reviewed my own case after signing in on the shared workstation.")
        capture(j, folder, "current-account-action")
        result["outcomes"] = ["Back/forward and saved team URL do not restore prior account data", "Current account completed its own investigation action"]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_last_false_positive_verdict_does_not_complete_the_case(app, monkeypatch, language):
    with decision_session(app, monkeypatch, language, "NEXT-29") as (j, _manager, result, folder):
        upload(
            j,
            "approved-rule-test.json",
            [
                {
                    "title": "Approved detection test CHG-73",
                    "timestamp": "2026-11-02T09:00:00Z",
                    "hostname": "TEST-REVIEW",
                    "process_name": "powershell.exe",
                    "command_line": "powershell.exe -enc AAAA",
                    "change_authorization": "CHG-73: intentional detection test with no execution",
                }
            ],
        )
        alerts = j.page.evaluate("id => api(`/api/cases/${id}/alerts`)", j.case_id)["items"]
        assert len(alerts) == 1, "Fixture requires exactly one final undecided alert"
        j.nav("الأداء")
        attention = j.page.get_by_text(j.text("تنبيهات دون قرار"), exact=True).locator("+ dd")
        assert number(attention.inner_text()) == 1
        before = j.page.evaluate("() => api('/api/soc/performance?member=me&days=30')")
        capture(j, folder, "one-undecided-alert")
        personal_case(j, j.case_id)
        j.click("link", "التحليل")
        j.click("link", "الكشف")
        j.click("button", "تفاصيل ومراجعة")
        dialog = j.page.get_by_role("dialog")
        dialog.locator("input[name=verdict]").fill(j.page.evaluate("autopsyLabel('false_positive')"))
        dialog.locator("input[name=attack_outcome]").fill(j.page.evaluate("autopsyLabel('unknown')"))
        dialog.locator("textarea[name=reason]").fill("CHG-73 identifies an intentional non-executing detection test; retain the report for independent review.")
        j.click("button", "حفظ", dialog)
        j.click("button", "إغلاق", dialog)
        j.nav("الأداء")
        assert number(j.page.get_by_text(j.text("تنبيهات دون قرار"), exact=True).locator("+ dd").inner_text()) == 0, (
            "PRODUCT: decided alert remains in undecided attention count"
        )
        after = j.page.evaluate("() => api('/api/soc/performance?member=me&days=30')")
        result["before_verdict"] = before
        result["after_verdict"] = after
        assert after["counts"]["open"] == before["counts"]["open"] == 1, "PRODUCT: alert verdict changed active case workload"
        assert after["counts"]["closed"] == before["counts"]["closed"] == 0, "PRODUCT: alert verdict completed the case"
        capture(j, folder, "verdict-with-open-case")
        personal_case(j, j.case_id)
        save_note(
            j, "CHG-73 was an authorized rule test. The false-positive verdict is recorded; independent report review and case closure remain outstanding."
        )
        j.click("link", "التقارير والمراجعة")
        j.click("button", "إعداد تقرير جديد")
        retained = report(j, report_path(j))
        result["report_id"] = retained["id"]
        assert "CHG-73" in json.dumps(retained["payload"], ensure_ascii=False)
        assert j.state()["status"] != "closed", "PRODUCT: preparing report bypassed independent closure"
        capture(j, folder, "remaining-report-prepared")
        result["outcomes"] = [
            "Final undecided-alert count cleared",
            "Case workload and completion unchanged by verdict",
            "Remaining report prepared from the documented finding without automatic closure",
        ]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_reordered_overlapping_exports_identify_the_new_event_without_silent_multiplication(app, monkeypatch, language):
    with decision_session(app, monkeypatch, language, "NEXT-30") as (j, _manager, result, folder):
        common = {"source": "gateway-export", "hostname": "EXPORT-GATEWAY", "timestamp": "2026-11-02T08:00:00Z"}
        one = {**common, "external_id": "gateway-001", "title": "Gateway retained observation one"}
        two = {**common, "external_id": "gateway-002", "title": "Gateway retained observation two", "timestamp": "2026-11-02T08:01:00Z"}
        new = {
            **common,
            "external_id": "gateway-003",
            "title": "New gateway encoded command",
            "timestamp": "2026-11-02T08:02:00Z",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc AAAA",
        }
        upload(j, "gateway-first.json", [one, two])
        first = stored_logs(j)
        assert first["total"] == 2
        upload(j, "gateway-reexport.json", [two, one, new], pretty=True)
        actual = stored_logs(j)
        result["before_export"] = first
        result["after_reexport"] = actual
        capture(j, folder, "overlapping-export-result")
        search = j.page.get_by_role("form", name=j.text("بحث سجلات القضية"), exact=True)
        search.locator("input[name=q]").fill("New gateway encoded command")
        j.click("button", "بحث السجلات", search)
        expect(j.page.get_by_role("cell", name="New gateway encoded command", exact=True)).to_be_visible()
        row = j.page.get_by_role("row").filter(has=j.page.get_by_role("cell", name="New gateway encoded command", exact=True))
        j.click("button", "تفاصيل السجل", row)
        expect(j.page.get_by_role("dialog")).to_contain_text("powershell.exe -enc AAAA")
        j.click("button", "إغلاق", j.page.get_by_role("dialog"))
        save_note(
            j,
            "The genuinely new gateway-003 event contains an encoded PowerShell command and requires investigation; gateway-001 and gateway-002 are overlapping prior observations.",
        )
        result["new_event_investigated"] = True
        capture(j, folder, "new-event-investigated")
        assert actual["total"] == 3, "PRODUCT: overlapping exports multiplied stable source event identities without identifying the duplicates"
        original = {item["id"]: item for item in first["items"]}
        for item in actual["items"]:
            if item["id"] in original:
                for field in ("title", "event_time", "hostname"):
                    assert item[field] == original[item["id"]][field], "PRODUCT: overlapping export mutated an existing event fact"
        result["outcomes"] = [
            "Overlapping stable event identities retained once",
            "Genuinely new event found and investigated",
            "Original event facts preserved",
        ]
