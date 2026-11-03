"""Complete post-closure work using the real isolated report service."""

import json
import sys
from pathlib import Path

import pytest
from playwright.sync_api import expect

from scripts.local_services import local_worker_services
from tests.e2e.test_batch_boundary_journeys import upload_logs
from tests.e2e.test_followup_handoff_journeys import edit, evidence_images, manager_case, set_status
from tests.e2e.test_investigation_link_journeys import choose, corrective_dialog, records
from tests.e2e.test_report_recovery_journeys import report, report_path
from tests.e2e.test_review_workflow import review_session


def prepare(j):
    j.click("link", "التقارير والمراجعة")
    j.click("button", "إعداد تقرير جديد")
    pdf_link(j).wait_for(timeout=60000)
    return report_path(j)


def pdf_link(j):
    label = "تنزيل PDF" if j.page.evaluate("SOCifyLocale.language") == "ar" else "Download PDF"
    return j.page.locator(".report-revision").first.get_by_role("link", name=label, exact=True)


def approve(manager):
    manager.click("button", "مراجعة واعتماد النسخة", manager.page.locator(".report-revision").first)
    manager.click("button", "حفظ", manager.page.get_by_role("dialog"))
    expect(manager.page.locator(".report-revision").first.locator(".report-status")).to_have_text(manager.text("معتمد") + " · " + manager.text("جاهز للتنزيل"))


@pytest.mark.e2e
@pytest.mark.skipif(sys.platform == "win32", reason="Requires the isolated native report service")
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", ["corrective-native-closed-report", "corrective-native-stale-report-review"])
def test_closed_investigation_can_publish_actual_corrective_followup_and_preserve_the_approved_report(app, language, scenario):
    title = "Review the identity approval procedure"
    with local_worker_services(app.config), review_session(app, language, scenario) as (j, manager, result):
        upload_logs(j, "retained-approval.json", "Service owner approved the maintenance activity")
        j.assessment("Approved maintenance verified against retained evidence; no compromise established.")
        j.click("link", "التحقيق والخط الزمني")
        j.record("root_cause", {"category": "other", "conclusion": "Retained approval explains the observed activity", "evidence_id": "retained-approval.json"})
        j.click("link", "الاستجابة والتصعيد")
        j.record(
            "response",
            {
                "title": "Confirm authorized activity",
                "phase": "validation",
                "status": "not_applicable",
                "details": "Containment is not needed for the approved maintenance.",
            },
        )
        dialog = corrective_dialog(j)
        choose(j, dialog, "root_cause_id", "Retained approval explains the observed activity")
        j.click("button", "حفظ", dialog)
        j.transition("awaiting_review")
        while j.page.get_by_role("button", name=j.text("إكمال المهمة"), exact=True).count():
            j.page.get_by_role("button", name=j.text("إكمال المهمة"), exact=True).first.click()
            j.settle()
        assert all(task["status"] in {"completed", "reviewed"} for task in j.state()["tasks"] if task["required"])
        original_path = prepare(j)
        manager_case(j, manager)
        manager.click("link", "التقارير والمراجعة")
        approve(manager)
        original = report(manager, original_path)
        original_url = pdf_link(manager).get_attribute("href")
        with manager.page.expect_download() as download:
            manager.page.locator(f'a[href="{original_url}"]').first.click()
        original_bytes = Path(download.value.path()).read_bytes()
        assert original_bytes.startswith(b"%PDF-")
        manager.decision("closed", "The complete report and retained maintenance evidence were independently reviewed.")
        assert manager.state()["status"] == "closed"

        j.nav("الأداء")
        j.page.locator(".insight-counter").filter(has_text=j.text("أغلقت خلال الفترة")).click()
        j.settle()
        j.page.locator(f"#performance-cases a[href='/cases/{j.case_id}']").click()
        j.settle()
        j.click("link", "الاستجابة والتصعيد")
        dialog = edit(j, title)
        validation = "The closed investigation corrective procedure was independently verified"
        set_status(j, dialog, "validated", validation)
        j.click("button", "حفظ", dialog)
        assert records(j, "corrective")[0]["payload"]["status"] == "validated"
        assert j.state()["status"] == "closed"
        followup_path = prepare(j)
        followup = report(j, followup_path)
        assert validation in json.dumps(followup["payload"])
        assert validation not in json.dumps(original["payload"])
        manager.page.reload()
        manager.settle()
        if scenario.endswith("stale-report-review"):
            manager.click("button", "مراجعة واعتماد النسخة", manager.page.locator(".report-revision").first)
            j.click("link", "الاستجابة والتصعيد")
            dialog = edit(j, title)
            validation = "Additional retained verification reconciled before final independent approval"
            set_status(j, dialog, "validated", validation)
            j.click("button", "حفظ", dialog)
            dialog = manager.page.get_by_role("dialog")
            manager.click("button", "حفظ", dialog)
            expect(dialog.locator("form > [role=alert]")).to_be_visible()
            assert report(j, followup_path)["state"] == "draft"
            assert report(j, followup_path)["payload"] == followup["payload"]
            followup_path = prepare(j)
            manager.page.reload()
            manager.settle()
        approve(manager)
        final = report(manager, followup_path)
        assert final["state"] == "approved" and len(final["formats"]) == 5
        assert validation in json.dumps(final["payload"])
        assert manager.state()["status"] == "closed"
        retained = report(manager, original_path)
        assert retained["payload"] == original["payload"] and retained["sha256"] == original["sha256"] and retained["state"] == "approved"
        with manager.page.expect_download() as download:
            manager.page.locator(f'a[href="{original_url}"]').first.click()
        assert Path(download.value.path()).read_bytes() == original_bytes
        result["outcomes"] = [
            scenario,
            "native report independently approved and investigation closed through UI",
            "corrective follow-up and new native report approved while retaining closed status",
            "original approved snapshot and downloaded PDF unchanged",
        ]
        result["original_report_hash"] = original["sha256"]
        result["followup_report_hash"] = final["sha256"]
        evidence_images(manager, result)
