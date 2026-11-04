"""Adverse-condition regressions for alert review; not additional user participants."""

import json
from pathlib import Path

import pytest
from playwright.sync_api import expect

import tests.e2e.test_review_workflow as sessions
from tests.e2e.test_alert_review_feedback import fill_review, import_alert, open_review
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_detection_workflow_journeys import open_detection

ARTIFACTS = Path("artifacts/usability_campaign/ci-assessment-current/alert-review-independent/after")


def capture(journey, name, language):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    journey.page.screenshot(path=str(ARTIFACTS / f"{name}-{language}.png"), full_page=True)


def stored_review(journey):
    return journey.page.evaluate("id=>api('/api/cases/'+id+'/alerts')", journey.case_id)["items"][0]


def review_button(journey):
    return journey.page.get_by_role("button", name=journey.text("تفاصيل ومراجعة"), exact=True)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_pending_alert_save_freezes_fields_and_cannot_be_dismissed(app, monkeypatch, language):
    monkeypatch.setattr(sessions, "ARTIFACTS", ARTIFACTS)
    with sessions.review_session(app, language, "pending-alert-save-protected") as (j, _manager, result):
        result["kind"] = "independent adverse-condition regression; excluded from participant counts"
        alert = import_alert(j)
        open_detection(j)
        dialog = open_review(j)
        reason = "Retain the submitted review while the response is pending."
        fill_review(j, dialog, reason)
        held = []
        j.page.route(f"**/api/cases/{j.case_id}/alerts/{alert['id']}", lambda route: held.append(route))
        dialog.get_by_role("button", name=j.text("حفظ"), exact=True).click()
        expect(dialog.locator("textarea[name=reason]")).to_be_disabled()
        assert len(held) == 1
        route = held.pop()
        try:
            assert dialog.locator("input,textarea,select,button").evaluate_all("(nodes) => nodes.every(node=>node.disabled)")
            expect(dialog.get_by_role("button", name=j.text("إغلاق"), exact=True)).to_be_disabled()
            j.page.keyboard.press("Escape")
            expect(dialog).to_be_visible()
            expect(dialog.locator("textarea[name=reason]")).to_have_value(reason)
            capture(j, "pending-frozen", language)
        finally:
            route.continue_()
        expect(dialog).not_to_be_visible()
        expect(review_button(j)).to_be_focused()
        saved = stored_review(j)
        assert saved["review"]["reason"] == reason
        assert saved["review_version"] == alert["review_version"] + 1
        result["outcomes"] = ["No editable fields during pending write", "Escape cannot discard in-flight review", "One retained decision and restored focus"]
        capture(j, "pending-completed", language)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_committed_alert_review_recovers_with_get_only_retry(app, monkeypatch, language):
    monkeypatch.setattr(sessions, "ARTIFACTS", ARTIFACTS)
    with sessions.review_session(app, language, "committed-alert-refresh-recovered") as (j, _manager, result):
        result["kind"] = "independent adverse-condition regression; excluded from participant counts"
        alert = import_alert(j)
        open_detection(j)
        dialog = open_review(j)
        reason = "Committed review remains saved while display recovery is retried."
        fill_review(j, dialog, reason)
        requests = []
        j.page.on("request", lambda request: requests.append((request.method, request.url)))
        reads = []

        def fail_twice(route):
            reads.append(route.request.method)
            if len(reads) <= 2:
                route.fulfill(
                    status=503,
                    content_type="application/json",
                    body=json.dumps({"error": {"code": "SERVICE_UNAVAILABLE", "message": "Controlled refresh read failure"}}),
                )
            else:
                route.continue_()

        j.page.route(f"**/api/cases/{j.case_id}", fail_twice)
        dialog.get_by_role("button", name=j.text("حفظ"), exact=True).click()
        expect(dialog).not_to_be_visible()
        status = j.page.get_by_role("status").filter(has_text=j.text("حُفظ قرار التنبيه؛ تعذر تحديث العرض."))
        expect(status).to_be_visible()
        expect(j.page.get_by_role("alert")).to_be_visible()
        expect(j.page.locator("#workspace")).to_have_attribute("aria-busy", "false")
        retry = j.page.get_by_role("button", name=j.text("إعادة المحاولة"), exact=True)
        expect(retry).to_be_focused()
        saved = stored_review(j)
        assert saved["review"]["reason"] == reason
        assert saved["review_version"] == alert["review_version"] + 1
        capture(j, "committed-refresh-failed", language)
        j.click("button", "إعادة المحاولة")
        expect(status).to_be_visible()
        expect(retry).to_be_focused()
        assert reads == ["GET", "GET"]
        j.click("button", "إعادة المحاولة")
        expect(review_button(j)).to_be_focused()
        assert reads == ["GET", "GET", "GET"]
        patches = [entry for entry in requests if entry[0] == "PATCH" and entry[1].endswith(f"/alerts/{alert['id']}")]
        assert len(patches) == 1
        assert stored_review(j)["review_version"] == saved["review_version"]
        reopened = open_review(j)
        expect(reopened.locator("textarea[name=reason]")).to_have_value(reason)
        j.click("button", "إغلاق", reopened)
        assert_accessible(j.page)
        capture(j, "committed-refresh-recovered", language)
        result["outcomes"] = [
            "Committed-write feedback remains visible",
            "Repeated read failures have retry and focus",
            "Recovery issued GET only",
            "No duplicate review version",
            "Current reason survives reopening",
        ]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_failed_alert_write_preserves_editable_draft_and_retry_commits_once(app, monkeypatch, language):
    monkeypatch.setattr(sessions, "ARTIFACTS", ARTIFACTS)
    with sessions.review_session(app, language, "failed-alert-write-draft-recovered") as (j, _manager, result):
        result["kind"] = "independent adverse-condition regression; excluded from participant counts"
        alert = import_alert(j)
        open_detection(j)
        dialog = open_review(j)
        reason = "Unsaved analyst draft must survive a failed write."
        fill_review(j, dialog, reason)
        writes = []

        def fail_first(route):
            writes.append(route.request.post_data_json)
            if len(writes) == 1:
                route.fulfill(
                    status=503,
                    content_type="application/json",
                    body=json.dumps({"error": {"code": "SERVICE_UNAVAILABLE", "message": "Controlled write rejection"}}),
                )
            else:
                route.continue_()

        j.page.route(f"**/api/cases/{j.case_id}/alerts/{alert['id']}", fail_first)
        j.click("button", "حفظ", dialog)
        expect(dialog).to_be_visible()
        expect(dialog.get_by_role("alert")).to_be_visible()
        expect(dialog.locator("textarea[name=reason]")).to_be_enabled()
        expect(dialog.locator("textarea[name=reason]")).to_have_value(reason)
        expect(dialog.get_by_role("button", name=j.text("حفظ"), exact=True)).to_be_enabled()
        expect(dialog.get_by_role("button", name=j.text("إغلاق"), exact=True)).to_be_enabled()
        unchanged = stored_review(j)
        assert unchanged["review_version"] == alert["review_version"]
        assert unchanged["review"] == alert["review"]
        capture(j, "write-rejected-draft-retained", language)
        updated = reason + " Additional evidence is still required."
        dialog.locator("textarea[name=reason]").fill(updated)
        j.click("button", "حفظ", dialog)
        expect(dialog).not_to_be_visible()
        expect(review_button(j)).to_be_focused()
        saved = stored_review(j)
        assert len(writes) == 2
        assert saved["review"]["reason"] == updated
        assert saved["review_version"] == alert["review_version"] + 1
        assert writes[0]["version"] == writes[1]["version"] == alert["review_version"]
        result["outcomes"] = [
            "Failed write leaves editable draft and visible error",
            "No state changed on rejection",
            "Explicit retry saved edited reason exactly once",
        ]
        capture(j, "write-retry-completed", language)
