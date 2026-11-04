"""Regression of the blind analyst handoff, not another participant or scenario."""

import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import expect

from tests.e2e import test_review_workflow as review_module
from tests.e2e.test_review_workflow import review_session

ARTIFACTS = Path("artifacts/usability_campaign/blind-review/assessment-repair/browser")
SOURCE_LIMIT = "The export contains authentication decisions only; no endpoint execution or session activity is included."
REASON = "Five failures followed by accepted authentication warrant validation. Malicious intent and attack outcome remain undetermined; request account-owner, MFA and VPN session evidence."
BOOKMARK = "Accepted authentication is not proof of compromise. No containment or endpoint execution performed. Collect and validate MFA and session evidence before response."
ANSWERS = {
    "incident_classification": "undetermined_pending_evidence",
    "initial_vector": "identity_vpn_login",
    "triage_verdict": "undetermined_pending_evidence",
    "impact_scope": "scope_under_assessment",
    "data_exposure": "none_observed",
    "file_and_email_assessment": "no_files_involved",
    "containment_status": "not_performed_pending_evidence",
    "recommended_next_step": "collect_and_validate_evidence",
    "urgency_level": "high_p2",
}


def vpn_events():
    rows = []
    for index in range(6):
        successful = index == 5
        rows.append(
            {
                "external_id": f"vpn-auth-{index + 1:03d}",
                "source": "vpn-gateway-export",
                "timestamp": f"2026-11-04T02:{50 + (18 + 20 * index) // 60:02d}:{(18 + 20 * index) % 60:02d}.405110Z",
                "event_type": "successful_login" if successful else "failed_login",
                "title": "VPN authentication accepted" if successful else "VPN authentication rejected",
                "category": "authentication",
                "severity": "medium",
                "hostname": "VPN-GATEWAY",
                "source_ip": "198.51.100.50",
                "destination_ip": "10.20.0.10",
                "username": "huda",
                "action": "login",
                "outcome": "success" if successful else "failed",
                "description": SOURCE_LIMIT,
            }
        )
    return ("\n".join(json.dumps(row) for row in rows) + "\n").encode()


def capture(page, folder, name, result):
    for width in (1440, 390):
        page.set_viewport_size({"width": width, "height": 1000})
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), f"Report overflow at {width}px"
        path = folder / f"{name}-{width}.png"
        page.screenshot(path=str(path), full_page=True, animations="disabled")
        result.setdefault("screenshots", []).append(str(path))
    page.set_viewport_size({"width": 1440, "height": 1000})


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_pending_evidence_handoff_keeps_reasoning_and_source_limits(app, monkeypatch, language):
    folder = ARTIFACTS / f"{language}-{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}"
    folder.mkdir(parents=True)
    monkeypatch.setattr(review_module, "ARTIFACTS", folder)
    with review_session(app, language, "pending-evidence-repair", create_case=False) as (j, _manager, result):
        result.update(
            purpose="A04/A05 regression of the existing blind-review task; not a new scenario",
            counted_as_new_scenario=False,
            human_participants=0,
            original_blind_review_modified=False,
            native_report_export_claim=False,
            setup="Isolated app fixture. Case, upload, assessment, bookmark and quick preview use visible UI controls.",
        )
        j.click("button", "إنشاء قضية")
        dialog = j.page.get_by_role("dialog")
        dialog.locator("input[name=title]").fill("VPN evidence awaiting validation")
        dialog.locator("textarea[name=objective]").fill("Review authentication evidence and prepare a bounded handoff without assuming compromise.")
        j.click("button", "حفظ", dialog)
        j.case_id = int(urlsplit(j.page.url).path.split("/")[-1])
        j.click("link", "السجلات والأدلة")
        j.page.locator("input[name=file]").set_input_files({"name": "vpn-auth.jsonl", "mimeType": "application/x-ndjson", "buffer": vpn_events()})
        j.click("button", "استيراد وفحص فوري")
        expect(j.page.get_by_role("cell", name="VPN authentication accepted", exact=True)).to_be_visible()
        j.click("link", "التحليل")
        j.click("link", "الكشف")
        alert_row = j.page.get_by_role("row").filter(has_text="[SOCify] Brute Force Authentication Burst")
        j.click("button", "تفاصيل ومراجعة", alert_row)
        dialog = j.page.get_by_role("dialog")
        dialog.locator("textarea[name=reason]").fill(REASON)
        j.click("button", "حفظ", dialog)
        if dialog.is_visible():
            j.click("button", "إغلاق", dialog)
        j.click("link", "التحقيق والخط الزمني")
        row = j.page.locator("li").filter(has=j.page.get_by_role("heading", name="VPN authentication accepted", exact=True))
        j.click("button", "تمييز السجل وإضافة ملاحظة", row)
        dialog = j.page.get_by_role("dialog")
        dialog.locator("input[name=title]").fill("Accepted authentication needs validation")
        dialog.locator("textarea[name=notes]").fill(BOOKMARK)
        j.click("button", "حفظ", dialog)
        expect(dialog).not_to_be_visible()
        j.click("link", "التقارير والمراجعة")
        for name, value in ANSWERS.items():
            j.page.locator(f'select[name="{name}"]').select_option(value)
        j.page.locator("input[name=executive_note]").fill(
            "Five failures then accepted authentication. Evidence remains insufficient to confirm compromise; no containment performed."
        )
        j.click("button", "حفظ إجابات التقرير")
        for name, value in ANSWERS.items():
            expect(j.page.locator(f'select[name="{name}"]')).to_have_value(value)
        capture(j.page, folder, "saved-assessment", result)
        with j.page.expect_popup() as popup:
            j.page.get_by_role("link", name=j.text("فتح التقرير"), exact=True).click()
        preview = popup.value
        preview.wait_for_load_state("networkidle")
        expect(preview.locator("main")).to_contain_text(REASON)
        expect(preview.locator("main")).to_contain_text(BOOKMARK)
        expect(preview.locator("main")).to_contain_text(SOURCE_LIMIT)
        expect(preview.get_by_text("Bounded summary", exact=False)).to_have_count(0)
        expected_choices = {
            "ar": ["لم يتحدد التصنيف بعد", "غير محدد بانتظار أدلة إضافية", "لم يُنفذ احتواء بانتظار الأدلة", "جمع الأدلة والتحقق منها قبل اتخاذ قرار الاستجابة"],
            "en": [
                "Classification Pending Evidence",
                "Undetermined — Awaiting Evidence",
                "No Containment Performed — Awaiting Evidence",
                "Collect and Validate Evidence Before Response",
            ],
        }
        for label in expected_choices[language]:
            expect(preview.locator("main")).to_contain_text(label)
        expect(preview.locator("main")).not_to_contain_text("Unauthorized Access / Brute Force")
        expect(preview.locator("main")).not_to_contain_text("وصول غير مصرح / تخمين كلمات مرور")
        capture(preview, folder, "quick-preview", result)
        (folder / "quick-preview.txt").write_text(preview.locator("main").inner_text(), encoding="utf-8")
        result["outcomes"] = [
            "saved truthful pending-evidence assessment",
            "shared bookmark and alert rationale appear in quick preview",
            "source evidence limits retained",
            "no native export attempted",
        ]
        preview.close()
