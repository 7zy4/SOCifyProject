"""Recover a reviewed intelligence import after its acknowledgement is lost."""

import json

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import expect

from tests.e2e.test_followup_handoff_journeys import evidence_images
from tests.e2e.test_library_draft_journeys import intel_area, intel_draft, intel_items
from tests.e2e.test_review_workflow import ARTIFACTS, review_session
from tests.e2e.test_rule_authoring_journeys import change_author_role

PATH = "/api/autopsy/intelligence"


def save(j):
    with j.page.expect_response(lambda r: r.url.endswith(PATH) and r.request.method == "POST") as response:
        j.click("button", "حفظ", intel_area(j))
    return response.value


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "intel-receipt-lost",
        "intel-receipt-malformed",
        "intel-receipt-gateway",
        "intel-receipt-repeat",
        "intel-receipt-reload",
        "intel-receipt-refresh-failure",
        "intel-receipt-storage-disabled",
        "intel-receipt-new-version",
        "intel-receipt-changed-content",
        "intel-receipt-already-active",
        "intel-receipt-permission-recovery",
        "intel-receipt-invalid-session-response",
        "intel-network-before-commit",
        "intel-network-signin-page",
    ],
)
def test_author_recovers_the_intended_intelligence_import(app, language, scenario):
    with review_session(app, language, scenario) as (analyst, manager, result):
        manager.login("manager@socify.local")
        permissions = scenario in {"intel-receipt-permission-recovery", "intel-receipt-invalid-session-response"}
        if scenario == "intel-receipt-already-active" or permissions:
            change_author_role(manager, "soc_manager")
            analyst.login("analyst@socify.local")
        j = analyst if permissions else manager
        j.nav("مكتبة التحليل المحلي")
        if scenario == "intel-receipt-storage-disabled":
            j.page.evaluate("Object.defineProperty(window, 'sessionStorage', {get() {throw new DOMException('Blocked', 'SecurityError')}})")
        intel_draft(j)
        committed = []
        losses = 2 if scenario == "intel-receipt-repeat" else 1

        def lose_receipt(route):
            nonlocal losses
            if route.request.method != "POST" or not losses:
                route.continue_()
                return
            losses -= 1
            if scenario == "intel-network-before-commit":
                route.abort()
                return
            if scenario == "intel-network-signin-page":
                route.fulfill(status=200, content_type="text/html", body="<p>Gateway sign-in required</p>")
                return
            response = route.fetch()
            assert response.status == 201, response.text()
            committed.append(response.json())
            if scenario == "intel-receipt-malformed":
                route.fulfill(status=201, content_type="application/json", body="{interrupted")
            elif scenario == "intel-receipt-gateway":
                route.fulfill(status=502, content_type="application/json", body='{"error":{"code":"GATEWAY_TIMEOUT","message":"Request interrupted"}}')
            elif scenario == "intel-receipt-refresh-failure":
                j.page.route("**/api/autopsy/sigma/rules", lambda r: r.abort(), times=1)
                route.fulfill(response=response)
            else:
                route.abort()

        j.page.route("**/api/autopsy/intelligence", lose_receipt)
        j.click("button", "حفظ", intel_area(j))
        expect(intel_area(j).get_by_role("alert").filter(visible=True)).to_be_visible()
        if scenario == "intel-receipt-malformed":
            error = intel_area(j).get_by_role("alert").filter(visible=True)
            result["interrupted_response_message"] = error.inner_text()
            intel_area(j).screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-recovery-message.png"))
            expect(error).to_have_text(j.text("تعذر قراءة الرد. أعد المحاولة."))
        assert len(intel_items(j)) == (0 if scenario in {"intel-network-before-commit", "intel-network-signin-page"} else 1)
        if scenario == "intel-receipt-repeat":
            j.click("button", "حفظ", intel_area(j))
            expect(intel_area(j).get_by_role("alert").filter(visible=True)).to_be_visible()
            assert len(committed) == 2 and committed[0] == committed[1]
        if scenario == "intel-receipt-refresh-failure":
            expect(intel_area(j).get_by_role("alert").filter(visible=True)).to_have_text(j.text("حُفظ المصدر. تعذر تحديث القائمة؛ أعد المحاولة."))
        if scenario == "intel-receipt-reload":
            stored = j.page.evaluate("Object.entries(sessionStorage).filter(([key])=>key.startsWith('socify:intel-import:'))")
            assert len(stored) == 1 and "192.0.2.48" not in stored[0][1]
            j.page.once("dialog", lambda d: d.accept())
            j.page.reload()
            j.settle()
            intel_draft(j)
        if scenario == "intel-receipt-already-active":
            analyst.nav("مكتبة التحليل المحلي")
            analyst.click("button", "تفعيل الإصدار")
            assert intel_items(analyst)[0]["active"]
        if permissions:
            change_author_role(manager, "analyst")
            if scenario == "intel-receipt-invalid-session-response":

                def invalid_session_body(route):
                    response = route.fetch()
                    assert response.status == 401
                    route.fulfill(response=response, body="{interrupted")

                j.page.route("**/api/autopsy/intelligence", invalid_session_body, times=1)
            assert save(j).status == 401
            recovery = j.page.get_by_role("dialog", name=j.text("تجديد الجلسة"), exact=True)
            expect(recovery).to_be_visible()
            change_author_role(manager, "soc_manager")
            with j.page.context.expect_page() as opened:
                recovery.get_by_role("link", name=j.text("تسجيل الدخول"), exact=True).click()
            login = opened.value
            login.locator("input[name=email]").fill("analyst@socify.local")
            login.locator("input[name=password]").fill(DEMO_LOGIN_VALUE)
            login.locator("button[type=submit]").click()
            login.wait_for_url("**/cases")
            j.click("button", "متابعة العمل", recovery)
            login.close()
        if scenario == "intel-receipt-changed-content":
            intel_area(j).locator("input[type=file]").set_input_files(
                {
                    "name": "corrected.json",
                    "mimeType": "application/json",
                    "buffer": json.dumps([{"type": "ip", "value": "192.0.2.49", "verdict": "suspicious"}]).encode(),
                }
            )
            assert save(j).status == 409
            assert len(intel_items(j)) == 1
            intel_area(j).locator("input[name=version]").fill("2")
        elif scenario == "intel-receipt-new-version":
            intel_area(j).locator("input[name=version]").fill("2")
        before = intel_items(j)
        retried = save(j)
        assert retried.status == 201, retried.text()
        items = intel_items(j)
        if scenario in {"intel-receipt-new-version", "intel-receipt-changed-content"}:
            assert len(items) == 2 and retried.json()["id"] != committed[0]["id"]
        elif scenario in {"intel-network-before-commit", "intel-network-signin-page"}:
            assert len(items) == 1
        else:
            assert items == before and retried.json()["id"] == committed[0]["id"]
        if scenario == "intel-receipt-already-active":
            assert items[0]["active"]
        expect(intel_area(j).locator("input[name=name]")).to_have_value("")
        expect(intel_area(j).get_by_role("alert").filter(visible=True)).to_have_count(0)
        listed = j.page.locator("section.panel").filter(has=j.page.get_by_role("heading", name=j.text("إصدارات مصادر TI وGeoIP"), exact=True))
        listed.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-published.png"))
        result["outcome"] = "Recovered the intended source import without duplicates; preserved activation and version boundaries where applicable"
        evidence_images(j, result)
