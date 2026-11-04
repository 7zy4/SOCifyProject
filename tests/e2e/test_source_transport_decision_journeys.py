"""Recover source delivery through the interface after real controlled TLS faults."""

import hashlib
import json
import time
from pathlib import Path

import pytest
from playwright.sync_api import expect

from socify import outbound
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_investigation_link_journeys import note_dialog, records
from tests.e2e.test_report_recovery_journeys import report, report_path
from tests.e2e.test_review_workflow import review_session
from tests.e2e.test_source_goal_journeys import create_connector, visible_logs
from tests.e2e.test_source_lifecycle_journeys import source_actions, source_row
from tests.integration.test_source_https_transport import tls_source  # noqa: F401 -- shared controlled TLS peer fixture

ARTIFACTS = Path("artifacts/usability_campaign/source-transport-decisions")


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("fault", ["truncated", "slow-headers"])
def test_source_owner_recovers_incomplete_delivery_without_partial_evidence(app, monkeypatch, tls_source, language, fault):  # noqa: F811 -- imported fixture
    monkeypatch.setenv("SOCIFY_SOURCE_ALLOWLIST", "siem.example")
    event = {
        "external_id": "response-1",
        "title": "Retained source event",
        "hostname": "SOURCE-REVIEW-HOST",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc AAAA",
    }
    prefix = json.dumps(event).encode() + b"\n"
    tls_source["responses"]["body"] = prefix
    original_connection = outbound._PinnedHTTPSConnection
    if fault == "slow-headers":

        class ShortDeadlineConnection(original_connection):
            def __init__(self, target, deadline):
                super().__init__(target, time.monotonic() + 0.75)

        monkeypatch.setattr(outbound, "_PinnedHTTPSConnection", ShortDeadlineConnection)
    scenario = f"source-transport-{fault}-decision"
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with review_session(app, language, scenario) as (analyst, manager, result):
        manager.login("manager@socify.local")
        manager.case_url = analyst.case_url
        manager.page.goto(manager.case_url)
        manager.settle()
        manager.click("link", "التقارير والمراجعة")
        manager.click("button", "إعداد تقرير جديد")
        prior_path = report_path(manager)
        prior_report = report(manager, prior_path)
        connector = create_connector(manager, tls_source["url"] + "/" + fault)
        before = manager.state()
        with manager.page.expect_response(lambda response: response.url.endswith("/pull") and response.request.method == "POST") as failed:
            manager.click("button", "سحب السجلات الآن", source_row(manager))
        assert failed.value.status == 422, failed.value.json()
        expect(manager.page.locator("#global-message")).to_be_visible()
        expect(manager.page.locator("#global-message")).not_to_have_text("")
        assert manager.page.evaluate("id => api(`/api/cases/${id}/logs`)", manager.case_id)["total"] == 0
        after_failure = manager.state()
        assert after_failure["version"] == before["version"] and after_failure["evidence"] == before["evidence"]
        manager.page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-failure.png"), full_page=True)
        result["failure_message"] = manager.page.locator("#global-message").inner_text()
        result["decision"] = "The failed transfer supplies no usable evidence; correct the source and retry before investigating its records."
        assert report(manager, prior_path)["sha256"] == prior_report["sha256"]
        assert report(manager, prior_path)["payload"] == prior_report["payload"]
        if fault == "slow-headers":
            source_case_id, source_case_url = manager.case_id, manager.case_url
            manager.nav("إدارة القضايا")
            manager.create_case()
            manager.click("link", "التحقيق والخط الزمني")
            dialog = note_dialog(manager)
            note = "Continue this independent evidence review while the source owner restores the other case export."
            dialog.locator("textarea[name=body]").fill(note)
            manager.click("button", "حفظ", dialog)
            assert records(manager, "war_room")[0]["payload"]["body"] == note
            manager.case_id, manager.case_url = source_case_id, source_case_url
            manager.page.goto(source_case_url + "?tab=logs")
            manager.settle()

        # A source operator restores the peer endpoint; no record or case task is completed through an API.
        row = source_actions(manager)
        manager.click("button", "تعديل المصدر", row)
        dialog = manager.page.get_by_role("dialog")
        dialog.locator("input[name=endpoint]").fill(tls_source["url"] + "/events")
        manager.click("button", "حفظ", dialog)
        monkeypatch.setattr(outbound, "_PinnedHTTPSConnection", original_connection)
        tls_source["responses"]["body"] = prefix + json.dumps({"external_id": "response-2", "title": "Complete source export marker"}).encode() + b"\n"
        with manager.page.expect_response(lambda response: response.url.endswith("/pull") and response.request.method == "POST") as pulled:
            manager.click("button", "سحب السجلات الآن", source_row(manager))
        assert pulled.value.status == 200 and pulled.value.json()["accepted"] == 2
        assert pulled.value.json()["alerts_triggered"] > 0
        assert visible_logs(manager)["total"] >= 2
        expect(manager.page.get_by_role("cell", name="Retained source event", exact=True)).to_be_visible()
        expect(source_row(manager)).to_contain_text(manager.text("تم استقبال السجلات"))
        retained = manager.state()
        with manager.page.expect_response(lambda response: response.url.endswith("/pull") and response.request.method == "POST") as repeated:
            manager.click("button", "سحب السجلات الآن", source_row(manager))
        assert repeated.value.status == 200
        assert repeated.value.json()["accepted"] == 0 and repeated.value.json()["skipped"] == 2
        assert manager.state()["version"] == retained["version"] and manager.state()["evidence"] == retained["evidence"]
        assert connector["ingest_key"] not in manager.page.locator("body").inner_text()
        assert len(tls_source["requests"]) == 3
        assert report(manager, prior_path)["payload"] == prior_report["payload"]
        manager.nav("المراقبة")
        manager.page.locator("[data-alert-toggle]").first.click()
        manager.settle()
        expect(manager.page.locator(".dossier-view")).to_contain_text("SOURCE-REVIEW-HOST")
        manager.page.goto(manager.case_url + "?tab=reports")
        manager.settle()
        manager.click("button", "إعداد تقرير جديد")
        latest_report = report(manager, report_path(manager))
        assert latest_report["sha256"] != prior_report["sha256"]
        assert len(latest_report["payload"]["imports"]) == 1
        assert latest_report["payload"]["imports"][0]["accepted"] == 2
        assert latest_report["payload"]["imports"][0]["sha256"] == hashlib.sha256(tls_source["responses"]["body"]).hexdigest()
        assert latest_report["payload"]["alerts"] and latest_report["payload"]["summary"]["counts"]["normalized_logs"] >= 2
        assert prior_report["payload"]["imports"] == [] and prior_report["payload"]["summary"]["counts"]["normalized_logs"] == 0
        assert report(manager, prior_path)["payload"] == prior_report["payload"]
        assert_accessible(manager.page)
        result["plan_id"] = "NEXT-06" if fault == "truncated" else "NEXT-07"
        result["outcomes"] = [
            "An incomplete or timed-out TLS response retained no partial event, evidence or case revision",
            "The visible source form corrected the destination and a complete response delivered both records and an evidenced alert",
            "A repeated pull preserved evidence identity and case revision",
            "The resulting alert was inspected through its visible dossier, and a new report snapshot included the complete export without changing the prior snapshot",
        ]
        result["scope_limit"] = (
            "Owned local TLS peer with a trusted test certificate and controlled DNS/address routing; not a vendor SIEM or public-network failure. Timeout budget shortened only in this test."
        )
    (ARTIFACTS / f"{scenario}-{language}.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
