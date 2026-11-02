"""Operate an existing source through the interface without creating replacement sources."""

import json

import pytest
from playwright.sync_api import expect

from tests.e2e.test_review_workflow import review_session
from tests.e2e.test_source_goal_journeys import create_connector, send_records, visible_logs


def source_row(journey):
    panel = journey.page.locator("section.panel").filter(has=journey.page.get_by_role("heading", name=journey.text("ربط SIEM مباشر بالقضية"), exact=True))
    return panel.get_by_role("row").filter(has=journey.page.get_by_role("cell", name="Identity gateway records", exact=True))


def source_actions(journey):
    row = source_row(journey)
    row.locator("summary").filter(has_text=journey.text("إدارة المصدر")).click()
    return row


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "source-rotate-key",
        "source-disable-retains-evidence",
        "source-resume-delivery",
        "source-cancel-rotation",
        "source-cancel-disable",
        "source-rename",
        "source-analyst-management",
    ],
)
def test_source_owner_can_manage_delivery_without_losing_retained_records(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        connector = create_connector(j)
        payload = json.dumps({"events": [{"external_id": "lifecycle-001", "title": "Retained gateway record", "hostname": "ID-GATEWAY"}]}).encode()
        assert send_records(j.base, connector, payload)[1]["accepted"] == 1
        if scenario == "source-analyst-management":
            visible_logs(j)
            expect(j.page.get_by_role("button", name=j.text("تجديد مفتاح الإرسال"), exact=True)).to_have_count(0)
            expect(j.page.get_by_role("button", name=j.text("إيقاف استقبال السجلات"), exact=True)).to_have_count(0)
            result["outcomes"] = ["analyst retains evidence access", "source management follows the existing manager permission"]
            return
        manager.login("manager@socify.local")
        manager.page.goto(j.case_url + "?tab=logs")
        manager.settle()
        row = source_actions(manager)
        if scenario in {"source-rotate-key", "source-cancel-rotation"}:
            manager.page.once("dialog", lambda dialog: dialog.dismiss() if scenario == "source-cancel-rotation" else dialog.accept())
            if scenario == "source-cancel-rotation":
                manager.click("button", "تجديد مفتاح الإرسال", row)
                assert send_records(j.base, connector, payload)[1]["skipped"] == 1
            else:
                with manager.page.expect_response(lambda response: response.url.endswith("/rotate-key") and response.request.method == "POST") as changed:
                    manager.click("button", "تجديد مفتاح الإرسال", row)
                updated = changed.value.json()
                dialog = manager.page.get_by_role("dialog")
                expect(dialog.locator("pre")).to_contain_text(updated["ingest_key"])
                manager.click("button", "إغلاق", dialog)
                assert send_records(j.base, connector, payload)[0] == 401
                assert send_records(j.base, connector, payload, token=updated["ingest_key"])[1]["skipped"] == 1
                assert updated["ingest_key"] not in manager.page.locator("body").inner_text()
        elif scenario == "source-rename":
            manager.click("button", "تعديل المصدر", row)
            dialog = manager.page.get_by_role("dialog")
            dialog.locator("input[name=name]").fill("Identity gateway — reviewed")
            manager.click("button", "حفظ", dialog)
            expect(manager.page.get_by_role("cell", name="Identity gateway — reviewed", exact=True)).to_be_visible()
            assert send_records(j.base, connector, payload)[1]["skipped"] == 1
        else:
            manager.page.once("dialog", lambda dialog: dialog.dismiss() if scenario == "source-cancel-disable" else dialog.accept())
            manager.click("button", "إيقاف استقبال السجلات", row)
            if scenario == "source-cancel-disable":
                assert send_records(j.base, connector, payload)[1]["skipped"] == 1
            else:
                expect(source_row(manager)).to_contain_text(manager.text("متوقف"))
                assert send_records(j.base, connector, payload)[0] == 401
                if scenario == "source-resume-delivery":
                    row = source_actions(manager)
                    manager.click("button", "استئناف استقبال السجلات", row)
                    expect(source_row(manager)).to_contain_text(manager.text("بانتظار السجلات"))
                    assert send_records(j.base, connector, payload)[1]["skipped"] == 1
                    next_payload = json.dumps({"events": [{"external_id": "lifecycle-002", "title": "New gateway record"}]}).encode()
                    assert send_records(j.base, connector, next_payload)[1]["accepted"] == 1
        assert visible_logs(manager)["total"] == (2 if scenario == "source-resume-delivery" else 1)
        sources = manager.page.evaluate("id => api(`/api/cases/${id}/siem-connectors`)", j.case_id)["items"]
        assert len(sources) == 1 and sources[0]["id"] == connector["id"]
        assert "ingest_key" not in sources[0]
        for width in (390, 1440):
            manager.page.set_viewport_size({"width": width, "height": 1000})
            assert manager.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        result["outcomes"] = [scenario, "retained records preserved", "same source reused", "no credential exposed in the persistent view"]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_sender_retry_does_not_invalidate_the_investigators_report(app, language):
    with review_session(app, language, "source-retry-report-freshness") as (j, _manager, result):
        connector = create_connector(j)
        payload = json.dumps({"events": [{"title": "Retained identity result", "hostname": "ID-GATEWAY"}]}).encode()
        assert send_records(j.base, connector, payload)[1]["accepted"] == 1
        j.click("link", "التقارير والمراجعة")
        j.click("button", "إعداد تقرير جديد")
        expect(j.page.locator(".report-revision")).to_have_count(1)
        before = j.state()
        assert send_records(j.base, connector, payload)[1]["skipped"] == 1
        j.page.reload()
        j.settle()
        expect(j.page.locator(".report-revision")).not_to_contain_text(j.text("تغيرت القضية بعد إعداد هذا التقرير"))
        after = j.state()
        assert after["version"] == before["version"]
        assert len(after["evidence"]) == len(before["evidence"]) == 1
        assert len(j.page.evaluate("id => api(`/api/cases/${id}/imports`)", j.case_id)["items"]) == 1
        result["outcomes"] = ["delivery retry acknowledged", "no duplicated evidence or import", "case and report stay current when evidence is unchanged"]
