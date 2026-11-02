"""Configure a case source through the UI and deliver records as its external sender."""

import json
import secrets
import urllib.error
import urllib.request

import pytest
from playwright.sync_api import expect

from tests.e2e.test_review_workflow import review_session


def create_connector(journey, endpoint=None):
    journey.click("link", "السجلات والأدلة")
    journey.page.locator("summary").filter(has_text=journey.text("إضافة مصدر SIEM")).click()
    form = journey.page.get_by_role("form", name=journey.text("ربط SIEM مباشر"), exact=True)
    form.locator("input[name=name]").fill("Identity gateway records")
    if endpoint:
        form.locator("input[name=endpoint]").fill(endpoint)
    with journey.page.expect_response(lambda response: response.url.endswith("/siem-connectors") and response.request.method == "POST") as response:
        journey.click("button", "إنشاء موصل SIEM مباشر", form)
    created = response.value.json()
    dialog = journey.page.get_by_role("dialog")
    expect(dialog.locator("pre")).to_contain_text("X-SOCify-Source-Key:")
    journey.click("button", "إغلاق", dialog)
    return created


def send_records(base, connector, content, *, token=None, case_id=None):
    url = base + connector["ingest_url"] + (f"?case_id={case_id}" if case_id is not None else "")
    request = urllib.request.Request(  # noqa: S310 -- bound to the test's local HTTP server
        url,
        data=content,
        headers={"Content-Type": "application/json", "X-SOCify-Source-Key": token or connector["ingest_key"]},
        method="POST",
    )
    try:
        response = urllib.request.urlopen(request, timeout=10)  # noqa: S310
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, json.loads(response.read())


def visible_logs(journey):
    journey.page.reload()
    journey.settle()
    return journey.page.evaluate("id => api(`/api/cases/${id}/logs`)", journey.case_id)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    ["source-first-ingest", "source-duplicate", "source-key-recovery", "source-payload-recovery", "source-case-boundary", "source-pull-policy-recovery"],
)
def test_case_source_delivers_only_its_authorized_records(app, monkeypatch, language, scenario):
    monkeypatch.delenv("SOCIFY_SOURCE_ALLOWLIST", raising=False)
    with review_session(app, language, scenario) as (j, manager, result):
        connector = create_connector(j, "https://siem.example.test/events" if scenario == "source-pull-policy-recovery" else None)
        assert connector["status"] == "not_tested"
        expect(j.page.get_by_role("cell", name=j.text("بانتظار السجلات"), exact=True)).to_be_visible()
        payload = json.dumps(
            {
                "events": [
                    {"external_id": "identity-001", "title": "Routine identity gateway review", "hostname": "ID-GATEWAY", "timestamp": "2026-11-02T09:00:00Z"}
                ]
            }
        ).encode()
        if scenario == "source-case-boundary":
            manager.login("manager@socify.local")
            manager.create_case()
            code, _ = send_records(j.base, connector, payload, case_id=manager.case_id)
            assert code in {403, 422}, "A case-scoped source must not write to a different case"
            assert visible_logs(manager)["total"] == 0
        elif scenario == "source-key-recovery":
            code, _ = send_records(j.base, connector, payload, token=secrets.token_urlsafe(32))
            assert code == 401
            assert visible_logs(j)["total"] == 0
        elif scenario == "source-payload-recovery":
            code, _ = send_records(j.base, connector, b"")
            assert code == 422
            assert visible_logs(j)["total"] == 0
        elif scenario == "source-pull-policy-recovery":
            j.click("button", "سحب السجلات الآن")
            expect(j.page.locator("#global-message")).to_be_visible()
            assert j.page.evaluate("id => api(`/api/cases/${id}/logs`)", j.case_id)["total"] == 0
            result["scope_limit"] = "Blocked outbound pull; recovery uses a real local webhook sender. No production SIEM was connected."
        code, delivered = send_records(j.base, connector, payload)
        assert code == 201 and delivered["accepted"] == 1
        if scenario == "source-duplicate":
            code, duplicate = send_records(j.base, connector, payload)
            assert code == 201 and duplicate["accepted"] == 0 and duplicate["skipped"] == 1
        assert visible_logs(j)["total"] == 1
        expect(j.page.get_by_role("cell", name="Routine identity gateway review", exact=True)).to_be_visible()
        sources = j.page.evaluate("id => api(`/api/cases/${id}/siem-connectors`)", j.case_id)
        assert sources["items"][0]["rows_ingested"] == 1
        assert sources["items"][0]["status"] == "connected"
        expect(j.page.get_by_role("cell", name=j.text("تم استقبال السجلات"), exact=True)).to_be_visible()
        assert connector["ingest_key"] not in json.dumps(sources)
        assert connector["ingest_key"] not in j.page.locator("body").inner_text()
        for width in (390, 1440):
            j.page.set_viewport_size({"width": width, "height": 1000})
            assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        result["outcomes"] = [
            "connector configured through the interface",
            scenario,
            "external delivery retained in the intended case",
            "one-time credential absent after dismissal",
        ]
