"""Source owners recover provider-side changes without accepting error documents."""

import json
from pathlib import Path

import pytest
from playwright.sync_api import expect

from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_investigation_link_journeys import note_dialog, records
from tests.e2e.test_report_recovery_journeys import report, report_path
from tests.e2e.test_review_workflow import review_session
from tests.e2e.test_source_goal_journeys import create_connector, visible_logs
from tests.e2e.test_source_lifecycle_journeys import source_actions, source_row
from tests.integration.test_source_https_transport import tls_source  # noqa: F401 -- controlled trusted peer

ARTIFACTS = Path("artifacts/usability_campaign/source-provider-decisions")


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("status", [302, 429])
def test_source_owner_recovers_provider_status_without_importing_error_content(app, monkeypatch, tls_source, language, status):  # noqa: F811
    monkeypatch.setenv("SOCIFY_SOURCE_ALLOWLIST", "siem.example")
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    scenario = "source-provider-migration" if status == 302 else "source-provider-rate-limit"
    old = {"external_id": "provider-old", "title": "Previously retained provider record", "hostname": "PROVIDER-HOST"}
    new = {"external_id": "provider-new", "title": "Current provider investigation record", "hostname": "PROVIDER-HOST"}
    tls_source["responses"]["body"] = json.dumps(old).encode()
    with review_session(app, language, scenario) as (analyst, manager, result):
        result["plan_id"] = "NEXT-20" if status == 302 else "NEXT-21"
        result["initial_goal"] = "Collect the next provider export in the existing investigation without changing its retained evidence."
        manager.login("manager@socify.local")
        manager.case_url, manager.case_id = analyst.case_url, analyst.case_id
        manager.page.goto(manager.case_url)
        manager.settle()
        connector = create_connector(manager, tls_source["url"] + "/provider-status")
        with manager.page.expect_response(lambda r: r.url.endswith("/pull") and r.request.method == "POST") as first:
            manager.click("button", "سحب السجلات الآن", source_row(manager))
        assert first.value.json()["accepted"] == 1
        manager.click("link", "التقارير والمراجعة")
        manager.click("button", "إعداد تقرير جديد")
        prior_path = report_path(manager)
        prior = report(manager, prior_path)
        manager.click("link", "السجلات والأدلة")
        before = manager.state()
        tls_source["responses"]["status"] = status
        tls_source["responses"]["error_body"] = json.dumps(
            {"title": "Provider error must never become evidence", "process_name": "powershell.exe", "command_line": "powershell.exe -enc AAAA"}
        ).encode()
        request_count = len(tls_source["requests"])
        with manager.page.expect_response(lambda r: r.url.endswith("/pull") and r.request.method == "POST") as rejected:
            manager.click("button", "سحب السجلات الآن", source_row(manager))
        assert rejected.value.status == 422
        expect(manager.page.locator("#global-message")).to_be_visible()
        result["failure_message"] = manager.page.locator("#global-message").inner_text()
        manager.page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-rejected.png"), full_page=True)
        assert len(tls_source["requests"]) == request_count + 1, "No automatic redirect following or retry storm"
        after = manager.state()
        assert before["version"] == after["version"] and before["evidence"] == after["evidence"]
        assert manager.page.evaluate("id=>api(`/api/cases/${id}/logs`)", manager.case_id)["total"] == 1
        assert report(manager, prior_path)["payload"] == prior["payload"]
        expected = "رابط المصدر يعيد التوجيه؛ حدّثه إلى الرابط المباشر" if status == 302 else "المصدر يقيّد معدل الطلبات؛ أعد المحاولة لاحقًا"
        expect(manager.page.locator("#global-message")).to_contain_text(manager.text(expected))
        if status == 302:
            result["decision"] = "The source changed location; use the direct endpoint supplied by its owner on this existing connector."
            manager.click("button", "تعديل المصدر", source_actions(manager))
            dialog = manager.page.get_by_role("dialog")
            dialog.locator("input[name=endpoint]").fill(tls_source["url"] + "/events")
            manager.click("button", "حفظ", dialog)
        else:
            result["decision"] = "Wait for provider availability and deliberately retry this source; its error document is not an investigation event."
        # External provider recovery, not a user mutation through the application API.
        tls_source["responses"]["status"] = 200
        tls_source["responses"]["body"] = json.dumps(new).encode()
        with manager.page.expect_response(lambda r: r.url.endswith("/pull") and r.request.method == "POST") as recovered:
            manager.click("button", "سحب السجلات الآن", source_row(manager))
        assert recovered.value.status == 200 and recovered.value.json()["accepted"] == 1
        assert recovered.value.json()["alerts_triggered"] == 0
        assert visible_logs(manager)["total"] == 2
        expect(manager.page.get_by_role("cell", name=new["title"], exact=True)).to_be_visible()
        expect(manager.page.get_by_role("cell", name="Provider error must never become evidence", exact=True)).to_have_count(0)
        sources = manager.page.evaluate("id=>api(`/api/cases/${id}/siem-connectors`)", manager.case_id)["items"]
        assert len(sources) == 1 and sources[0]["id"] == connector["id"] and sources[0]["rows_ingested"] == 2
        assert sources[0]["status"] == "connected"
        assert connector["ingest_key"] not in manager.page.locator("body").inner_text()
        manager.click("link", "التحقيق والخط الزمني")
        dialog = note_dialog(manager)
        note = "Provider delivery recovered; both retained records reviewed and the provider error excluded from investigation evidence."
        dialog.locator("textarea[name=body]").fill(note)
        manager.click("button", "حفظ", dialog)
        assert any(r["payload"].get("body") == note for r in records(manager, "war_room"))
        assert report(manager, prior_path)["payload"] == prior["payload"]
        assert_accessible(manager.page)
        result["outcomes"] = [
            "Provider cause visible",
            "Error payload excluded",
            "Same source recovered",
            "Both actual records reviewed",
            "Follow-up note saved",
            "Prior snapshot unchanged",
        ]
        result["scope_limit"] = "Controlled trusted local TLS peer; no production vendor availability, pagination or rate-policy claim."
    (ARTIFACTS / f"{scenario}-{language}.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
