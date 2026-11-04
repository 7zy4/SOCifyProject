"""Alert review disclosure regressions; no added journeys or human participants."""

import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import expect

import tests.e2e.test_review_workflow as sessions
from tests.e2e.test_alert_review_feedback import fill_review, import_alert, open_review
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_detection_workflow_journeys import open_detection

ARTIFACTS = Path("artifacts/usability_campaign/blind-review/alert-details")


def fingerprints():
    return {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in ("static/autopsy_operations.js", "static/soc-insights.js")}


def capture(journey, dialog, folder, result, stage):
    for width in (1440, 390):
        journey.page.set_viewport_size({"width": width, "height": 1000})
        bounds = dialog.evaluate("""dialog => {
            const box = el => {const r=el.getBoundingClientRect();return {left:r.left,right:r.right,width:r.width,scrollWidth:el.scrollWidth,clientWidth:el.clientWidth};};
            return {viewport:innerWidth,dialog:box(dialog),elements:[...dialog.querySelectorAll('form,table,summary,input,textarea,select,button')]
                .filter(el=>el.getClientRects().length).map(el=>({tag:el.tagName,name:el.name||el.textContent.slice(0,60),...box(el)}))};
        }""")
        path = folder / f"{stage}-{width}-{result['language']}.png"
        dialog.screenshot(path=str(path), animations="disabled")
        result.setdefault("layouts", []).append({"stage": stage, "width": width, "bounds": bounds, "screenshot": str(path)})
        assert bounds["dialog"]["left"] >= 0 and bounds["dialog"]["right"] <= width
        for element in bounds["elements"]:
            assert element["left"] >= bounds["dialog"]["left"] - 1 and element["right"] <= bounds["dialog"]["right"] + 1, element
        assert bounds["dialog"]["scrollWidth"] <= bounds["dialog"]["clientWidth"] + 1
        assert_accessible(journey.page)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_review_starts_with_decision_and_discloses_one_correct_evidence_table(app, monkeypatch, language):
    phase = os.environ.get("SOCIFY_ALERT_DETAILS_PHASE", "after")
    folder = ARTIFACTS / phase
    monkeypatch.setattr(sessions, "ARTIFACTS", folder)
    with sessions.review_session(app, language, "alert-review-readable-details") as (j, _manager, result):
        result.update(kind="UX regression; excluded from journey and participant counts", human_participants=0, clean_round_claim=False)
        result["fingerprints_before"] = fingerprints()
        alert = import_alert(j)
        case = j.state()
        open_detection(j)
        requests = []
        j.page.on("request", lambda request: requests.append({"method": request.method, "path": urlsplit(request.url).path}))
        dialog = open_review(j)
        expect(dialog).to_have_attribute("aria-label", j.text("مراجعة التنبيه"))
        result["initial_visible_text"] = dialog.inner_text()
        result["initial_pre_count"] = dialog.locator("pre").count()
        dialog.screenshot(path=str(folder / f"initial-1440-{language}.png"), animations="disabled")
        # Original evidence may be raw text inside the dossier; review metadata must not be.
        assert dialog.locator("pre").count() == 0, "PRODUCT: the initial review exposes raw evidence/trace/review JSON instead of a decision form"
        expect(dialog.get_by_label(j.text("قرار المحلل") + " *", exact=True)).to_be_visible()
        expect(dialog.get_by_label(j.text("سبب القرار") + " *", exact=True)).to_be_visible()
        expect(dialog.get_by_role("button", name=j.text("حفظ"), exact=True)).to_be_visible()
        disclosure = dialog.locator("details").filter(has=j.page.locator("summary", has_text=j.text("تفاصيل التنبيه")))
        expect(disclosure).not_to_have_attribute("open", "")
        assert not any(request["path"].endswith("/dossier") for request in requests)
        fill_review(j, dialog, "Host execution remains unverified; retain the evidence and request telemetry.")
        await_reason = dialog.locator("textarea[name=reason]").input_value()
        reason = dialog.locator("textarea[name=reason]")
        expect(reason).to_have_attribute("dir", "auto")
        assert reason.evaluate("el=>getComputedStyle(el).direction") == "ltr"
        reason.fill("لم يتأكد التنفيذ على الجهاز؛ يلزم التحقق من أدلة إضافية.")
        assert reason.evaluate("el=>getComputedStyle(el).direction") == "rtl"
        reason.fill(await_reason)
        capture(j, dialog, folder, result, "decision")
        summary = disclosure.locator("summary")
        summary.focus()
        summary.press("Enter")
        dossier = dialog.locator(".dossier-view")
        expect(dossier).to_be_visible()
        expect(dossier.locator("table")).to_have_count(1)
        text = dossier.inner_text()
        assert "undefined" not in text and "NaN" not in text and "ليس رقم" not in text
        assert case["title"] in text and case["reference"] in text
        assignee = next(member["name"] for member in case["members"] if member["user_id"] == case["assignee"])
        assert assignee in text
        count_row = dossier.get_by_role("rowheader", name="السجلات المرتبطة" if language == "ar" else "Linked events", exact=True).locator("..")
        assert count_row.locator("td").inner_text().strip() in {"1", "١"}
        original = dossier.get_by_role("rowheader", name=j.text("السجل الأصلي"), exact=True).locator("..").locator("pre")
        retained = json.loads(original.inner_text())
        assert retained["hostname"] == "REVIEW-HOST" and retained["command_line"] == "powershell.exe -EncodedCommand YQ=="
        assert dialog.locator("pre").count() == dossier.locator("pre").count()
        expect(dialog.locator("textarea[name=reason]")).to_have_value(await_reason)
        capture(j, dialog, folder, result, "details")
        # Open/close disclosure without duplicated fetches, rendering or writes.
        for _ in range(2):
            summary.focus()
            summary.press("Enter")
            expect(disclosure).not_to_have_attribute("open", "")
            summary.press("Enter")
            expect(dossier).to_be_visible()
        expect(dossier.locator("table")).to_have_count(1)
        assert sum(request["path"].endswith("/dossier") for request in requests) == 1
        assert all(request["method"] == "GET" for request in requests), requests
        # The decision remains editable and keyboard save preserves the existing save/refresh behavior.
        reason = dialog.locator("textarea[name=reason]")
        reason.focus()
        expect(reason).to_be_focused()
        position = reason.bounding_box()
        assert position and 0 <= position["y"] < 1000 and position["y"] + position["height"] <= 1000
        save = dialog.get_by_role("button", name=j.text("حفظ"), exact=True)
        save.focus()
        save.press("Enter")
        expect(dialog).not_to_be_visible()
        j.settle()
        stored = j.page.evaluate("id=>api(`/api/cases/${id}/alerts`)", j.case_id)["items"][0]
        assert stored["review"]["reason"] == await_reason and stored["review_version"] == alert["review_version"] + 1
        assert sum(request["method"] == "PATCH" for request in requests) == 1
        expect(j.page.locator(f'[data-alert-review-id="{alert["id"]}"]')).to_be_focused()
        result["requests"] = requests
        result["stored_review"] = stored["review"]
        result["fingerprints_after"] = fingerprints()
        assert result["fingerprints_before"] == result["fingerprints_after"]
        result["outcomes"] = [
            "Localized decision visible immediately",
            "One lazy evidence table with real case, owner and count",
            "Original evidence retained",
            "No writes from disclosure",
            "Keyboard decision save unchanged",
            "390/1440 control bounds and axe checked",
        ]
