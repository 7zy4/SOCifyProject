"""Regressions from a UI-only first-use review; these are not new participants."""

import json
import os
from pathlib import Path

import pytest
from playwright.sync_api import expect

from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_detection_workflow_journeys import open_detection
from tests.e2e.test_review_workflow import review_session

ARTIFACTS = Path("artifacts/usability_campaign/blind-review/alert-repair")


def import_alert(j):
    j.click("link", "السجلات والأدلة")
    raw = json.dumps(
        [
            {
                "title": "Retained encoded command",
                "hostname": "REVIEW-HOST",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -EncodedCommand YQ==",
                "timestamp": "2026-11-02T02:20:00Z",
            }
        ]
    ).encode()
    j.page.locator("input[name=file]").set_input_files({"name": "review.json", "mimeType": "application/json", "buffer": raw})
    j.click("button", "استيراد وفحص فوري")
    return j.page.evaluate("id=>api(`/api/cases/${id}/alerts`)", j.case_id)["items"][0]


def open_review(j):
    j.click("button", "تفاصيل ومراجعة")
    return j.page.get_by_role("dialog")


def fill_review(j, dialog, reason):
    dialog.locator("input[name=verdict]").fill(j.page.evaluate("autopsyLabel('undetermined')"))
    dialog.locator("input[name=attack_outcome]").fill(j.page.evaluate("autopsyLabel('unknown')"))
    dialog.locator("textarea[name=reason]").fill(reason)


def shot(j, name, language):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    phase = os.environ.get("SOCIFY_ALERT_REVIEW_CAPTURE", "after")
    j.page.screenshot(path=str(ARTIFACTS / f"{phase}-{name}-{language}.png"), full_page=True)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_monitoring_review_link_reaches_alert_review(app, language):
    with review_session(app, language, "review-alert-destination") as (j, _manager, result):
        import_alert(j)
        j.click("link", "مراجعة التنبيهات")
        j.page.locator("[data-alert-toggle]").first.click()
        j.click("link", "مراجعة التنبيه")
        shot(j, "destination", language)
        expect(j.page.get_by_role("button", name=j.text("تفاصيل ومراجعة"), exact=True)).to_be_visible()
        result["outcomes"] = ["Review alert opens the actual alert review controls without a second navigation guess"]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_saved_alert_review_closes_and_reopens_with_current_version(app, language):
    with review_session(app, language, "review-alert-save-feedback") as (j, _manager, result):
        alert = import_alert(j)
        open_detection(j)
        for index, reason in enumerate(("Execution is unverified; request host telemetry.", "Account owner validation is still outstanding."), 1):
            dialog = open_review(j)
            if index == 2:
                expect(dialog.locator("textarea[name=reason]")).to_have_value("Execution is unverified; request host telemetry.")
            fill_review(j, dialog, reason)
            with j.page.expect_response(lambda response: response.request.method == "PATCH" and response.url.endswith(f"/alerts/{alert['id']}")) as response:
                j.click("button", "حفظ", dialog)
            assert response.value.ok, response.value.text()
            saved = j.page.evaluate("id=>api(`/api/cases/${id}/alerts`)", j.case_id)["items"][0]
            assert saved["review"]["reason"] == reason
            assert saved["review_version"] == alert["review_version"] + index
            shot(j, f"saved-{index}", language)
            expect(dialog).not_to_be_visible()
            expect(j.page.get_by_role("button", name=j.text("تفاصيل ومراجعة"), exact=True)).to_be_focused()
        assert_accessible(j.page)
        j.page.set_viewport_size({"width": 390, "height": 1000})
        assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        shot(j, "saved-mobile", language)
        result["outcomes"] = [
            "Both reasons persisted",
            "Successful save dismisses stale form",
            "Keyboard focus returns to refreshed review action",
            "Reopening uses current review version",
        ]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_stale_colleague_review_keeps_unsaved_reason_and_cannot_overwrite(app, language):
    with review_session(app, language, "review-alert-concurrent-save") as (j, manager, result):
        alert = import_alert(j)
        open_detection(j)
        dialog = open_review(j)
        fill_review(j, dialog, "Analyst draft must survive a rejected stale write.")
        manager.login("manager@socify.local")
        manager.case_url, manager.case_id = j.case_url, j.case_id
        open_detection(manager)
        other = open_review(manager)
        fill_review(manager, other, "Lead checked account ownership; session telemetry is pending.")
        manager.click("button", "حفظ", other)
        expect(other).not_to_be_visible()
        with j.page.expect_response(lambda response: response.request.method == "PATCH" and response.url.endswith(f"/alerts/{alert['id']}")) as rejected:
            j.click("button", "حفظ", dialog)
        assert rejected.value.status == 409
        expect(dialog).to_be_visible()
        expect(dialog.get_by_role("alert")).to_be_visible()
        expect(dialog.locator("textarea[name=reason]")).to_have_value("Analyst draft must survive a rejected stale write.")
        current = j.page.evaluate("id=>api(`/api/cases/${id}/alerts`)", j.case_id)["items"][0]
        assert current["review"]["reason"] == "Lead checked account ownership; session telemetry is pending."
        assert current["review_version"] == alert["review_version"] + 1
        shot(j, "conflict-preserved", language)
        result["outcomes"] = ["Concurrent stale save rejected", "Unsaved analyst reason retained", "Colleague decision unchanged"]
