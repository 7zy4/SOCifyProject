"""Read and prepare reports under the sharing choice and access currently granted."""

import json

import pytest
from playwright.sync_api import expect

from tests.e2e.test_assignment_handoff_journeys import role_permission
from tests.e2e.test_batch_boundary_journeys import restrict_batch, upload_logs
from tests.e2e.test_report_recovery_journeys import report, report_path, screenshots
from tests.e2e.test_review_workflow import review_session

FULL = "كامل للاستخدام الداخلي المصرح"
REDACTED = "منقح: بيانات إحصائية وحالة فقط"


def select_profile(j, label):
    choice = j.page.locator('input[name="profile"]')
    choice.fill(j.text(label))
    choice.press("ArrowDown")
    j.page.get_by_role("option", name=j.text(label), exact=True).click()
    expect(choice).to_have_value(j.text(label))


def open_preview(j, card=None):
    card = card if card is not None else j.page.locator(".report-revision").first
    card.locator(":scope > details").filter(has=j.page.get_by_text(j.text("عرض بيانات النسخة للمراجعة"), exact=True)).locator(":scope > summary").click()
    return card.locator(".report-preview")


def manager_case(j, manager, tab="reports"):
    manager.login("manager@socify.local")
    manager.page.goto(j.case_url + "?tab=" + tab)
    manager.settle()


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "report-sharing-reload",
        "report-sharing-language",
        "report-sharing-case-isolation",
        "report-redacted-preview-without-download",
        "report-sharing-card-identity",
        "report-preview-background-continuity",
    ],
)
def test_reviewer_can_keep_sharing_scope_and_read_retained_report(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        upload_logs(j, "sharing-review.json", "Confidential identity review record")
        j.click("link", "التقارير والمراجعة")
        if scenario.startswith("report-sharing-") and scenario != "report-sharing-card-identity":
            select_profile(j, REDACTED)
            if scenario == "report-sharing-reload":
                j.page.reload()
                j.settle()
            elif scenario == "report-sharing-language":
                j.page.locator("[data-language-toggle]").click()
                j.settle()
            else:
                original_id, original_url = j.case_id, j.case_url
                j.nav("إدارة القضايا")
                j.create_case()
                j.click("link", "التقارير والمراجعة")
                expect(j.page.locator('input[name="profile"]')).to_have_value(j.text(FULL))
                j.case_id, j.case_url = original_id, original_url
                j.page.goto(original_url + "?tab=reports")
                j.settle()
            expect(j.page.locator('input[name="profile"]')).to_have_value(j.text(REDACTED))
            j.click("button", "إعداد تقرير جديد")
            retained = report(j, report_path(j))
            assert retained["payload"]["profile"] == "metadata_only_v1"
            assert "Confidential identity review record" not in json.dumps(retained["payload"])
        elif scenario == "report-redacted-preview-without-download":
            manager_case(j, manager)
            role_permission(manager, "evidence.download", False)
            j.page.reload()
            j.settle()
            expect(j.page.locator('input[name="profile"]')).to_have_value(j.text(REDACTED))
            j.click("button", "إعداد تقرير جديد")
            preview = open_preview(j)
            expect(preview.get_by_text(j.text(REDACTED), exact=True)).to_be_visible()
            retained = report(j, report_path(j))
            assert retained["payload"]["profile"] == "metadata_only_v1"
            assert "Confidential identity review record" not in json.dumps(retained["payload"])
        elif scenario == "report-sharing-card-identity":
            j.click("button", "إعداد تقرير جديد")
            select_profile(j, REDACTED)
            j.click("button", "إعداد تقرير جديد")
            cards = j.page.locator(".report-revision")
            expect(cards).to_have_count(2)
            expect(cards.nth(0).locator(".report-sharing")).to_have_text(j.text(REDACTED))
            expect(cards.nth(1).locator(".report-sharing")).to_have_text(j.text(FULL))
            assert report(j, report_path(j))["payload"]["profile"] == "metadata_only_v1"
        else:
            j.click("button", "إعداد تقرير جديد")
            before = report(j, report_path(j))
            preview = open_preview(j)
            imports = preview.locator(":scope > dl > dt").filter(has_text=j.text("الأصول المستوردة وإصدارات المعالجة")).locator("+ dd > details")
            imports.locator(":scope > summary").click()
            expect(imports).to_contain_text("sharing-review.json")
            imports.scroll_into_view_if_needed()
            reading_position = j.page.evaluate("window.scrollY")
            manager_case(j, manager)
            manager.click("button", "إلغاء المعالجة", manager.page.locator(".report-revision"))
            expect(j.page.locator(".report-status")).to_contain_text(j.text("أُلغيت المعالجة"), timeout=15000)
            preview = j.page.locator(".report-preview")
            expect(preview).to_be_visible()
            expect(preview.get_by_text("sharing-review.json", exact=False).first).to_be_visible()
            assert abs(j.page.evaluate("window.scrollY") - reading_position) <= 16
            assert report(j, report_path(j))["payload"] == before["payload"]
        screenshots(j, scenario, language)
        result["outcomes"] = [scenario, "interface actions", "retained sharing scope independently checked"]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "report-sharing-invalid-correction",
        "report-sharing-stale-permission",
        "report-full-preview-permission-loss",
        "report-preview-scope-withdrawn",
        "report-preview-scope-restored",
        "report-private-note-exclusion",
    ],
)
def test_report_reader_recovers_without_exposing_unshared_material(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        upload_logs(j, "sharing-review.json", "Confidential identity review record")
        j.click("link", "التقارير والمراجعة")
        if scenario in {"report-sharing-invalid-correction", "report-sharing-stale-permission"}:
            if scenario == "report-sharing-stale-permission":
                manager_case(j, manager)
                role_permission(manager, "evidence.download", False)
            else:
                j.page.locator('input[name="profile"]').fill("Unknown sharing policy")
            j.click("button", "إعداد تقرير جديد")
            panel = j.page.locator("section.panel").filter(has=j.page.get_by_role("heading", name=j.text("التقارير والمراجعة"), exact=True))
            expect(panel.get_by_role("alert")).to_be_visible()
            assert j.state()["reports"] == []
            if scenario == "report-sharing-stale-permission":
                j.page.reload()
                j.settle()
            select_profile(j, REDACTED)
            j.click("button", "إعداد تقرير جديد")
            expect(panel.get_by_role("alert")).to_have_count(0)
            assert report(j, report_path(j))["payload"]["profile"] == "metadata_only_v1"
        elif scenario == "report-full-preview-permission-loss":
            j.click("button", "إعداد تقرير جديد")
            original_path = report_path(j)
            original_hash = report(j, original_path)["sha256"]
            open_preview(j)
            manager_case(j, manager)
            role_permission(manager, "evidence.download", False)
            j.page.reload()
            j.settle()
            expect(j.page.locator(".report-preview")).to_have_count(0)
            assert "payload" not in report(j, original_path)
            j.click("button", "إعداد تقرير جديد")
            preview = open_preview(j)
            expect(preview.get_by_text(j.text(REDACTED), exact=True)).to_be_visible()
            assert report(j, original_path)["sha256"] == original_hash
        elif scenario.startswith("report-preview-scope-"):
            j.click("button", "إعداد تقرير جديد")
            path = report_path(j)
            original = report(j, path)
            analyst_name = j.page.evaluate("state.user.name")
            manager_case(j, manager, "logs")
            upload_logs(manager, "sensitive-sharing.json", "Separately restricted retained identity")
            restrict_batch(manager, "sensitive-sharing.json")
            j.page.reload()
            j.settle()
            expect(j.page.locator(".report-revision")).to_have_count(0)
            expect(j.page.locator("main")).not_to_contain_text("Separately restricted retained identity")
            expect(j.page.get_by_role("heading", name=j.text("ربط SIEM مباشر بالقضية"), exact=True)).to_have_count(0)
            # Reopen the previously saved report address as a reader would; never write through the API.
            response = j.page.goto(j.base + path)
            assert response.status == 403
            assert "Confidential identity review record" not in j.page.locator("body").inner_text()
            if scenario.endswith("restored"):
                restrict_batch(manager, "sensitive-sharing.json", analyst_name)
            j.page.goto(j.case_url + "?tab=reports")
            j.settle()
            if scenario.endswith("restored"):
                open_preview(j)
                recovered = report(j, path)
                assert recovered["payload"] == original["payload"] and recovered["sha256"] == original["sha256"]
                expect(j.page.locator(".report-preview")).to_be_visible()
            else:
                expect(j.page.locator(".report-revision")).to_have_count(0)
        else:
            j.click("link", "التحقيق والخط الزمني")
            for visibility, title in [("private", "Private author assessment"), ("team", "Shared review conclusion")]:
                j.record(
                    "war_room",
                    {
                        "title": title,
                        "body": title + " supported by the retained evidence.",
                        "visibility": j.page.evaluate("value => autopsyLabel(value)", visibility),
                    },
                )
            j.click("link", "التقارير والمراجعة")
            j.click("button", "إعداد تقرير جديد")
            payload = report(j, report_path(j))["payload"]
            assert "Private author assessment" not in json.dumps(payload)
            assert "Shared review conclusion" in json.dumps(payload)
            preview = open_preview(j)
            records = preview.locator(":scope > dl > dt").filter(has_text=j.text("سجلات التحقيق")).locator("+ dd > details")
            records.locator(":scope > summary").click()
            group = records.locator(":scope > dl > dd > details")
            group.locator(":scope > summary").click()
            entry = group.locator(":scope > dl > dd > details")
            entry.locator(":scope > summary").click()
            entry.locator(":scope > dl > dd > details > summary").click()
            expect(records).to_contain_text("Shared review conclusion")
            expect(records).not_to_contain_text("Private author assessment")
        screenshots(j, scenario, language)
        result["outcomes"] = [scenario, "report access reflects present permission", "prior snapshot is never rewritten"]
