"""Use retained reports through cancellation, an actual unavailable service, and recovery."""

import secrets
import sys
import tempfile
import time
from pathlib import Path

import pytest
from playwright.sync_api import expect

from scripts.local_services import local_worker_services
from tests.e2e.test_batch_boundary_journeys import upload_logs
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_review_workflow import ARTIFACTS, review_session

RETRYING = "إعداد التقرير متوقف مؤقتًا. ستتم إعادة المحاولة تلقائيًا."
UNAVAILABLE = "تعذر إعداد التقرير حاليًا. بيانات التحقيق محفوظة."
EXHAUSTED = "انتهت محاولات الإعداد. يمكنك طلب تقرير جديد لاحقًا."


def report_path(journey):
    identifier = journey.state()["reports"][0]["id"]
    return f"/api/cases/{journey.case_id}/reports/{identifier}"


def report(journey, path):
    return journey.page.evaluate("path => api(path)", path)


def wait_for_service_failure(journey, path, *, terminal=False):
    deadline = time.monotonic() + 40
    expected = "failed" if terminal else "queued"
    while time.monotonic() < deadline:
        job = report(journey, path)["job"]
        if job["error_code"] == "ANALYSIS_UNAVAILABLE" and job["state"] == expected:
            return job
        journey.page.wait_for_timeout(250)
    raise AssertionError(f"Worker did not reach the expected {expected} failure state: {job}")


def absent_service(environment):
    # Real socket connection failure; no worker result, database state or network response is mocked.
    path = Path(tempfile.gettempdir()) / f"socify-absent-{secrets.token_hex(6)}.sock"
    assert not path.exists()
    environment.setenv("SOCIFY_ANALYSIS_SOCKET", str(path))


def screenshots(journey, scenario, language):
    assert_accessible(journey.page)
    for width in (390, 1440):
        journey.page.set_viewport_size({"width": width, "height": 1000})
        assert journey.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        journey.page.evaluate("window.scrollTo({top: 0, behavior: 'instant'})")
        journey.page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-{width}.png"), full_page=True)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "report-service-retry-feedback",
        "report-service-retries-exhausted",
        "report-cancel-retry-snapshot",
        "report-stale-retry-snapshot",
        "report-profile-background-change",
    ],
)
def test_report_user_can_understand_and_control_interrupted_work(app, monkeypatch, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        upload_logs(j, "review.json", "Retained records for the investigation report")
        j.assessment("Identity evidence retained for independent review.", escalate=False)
        j.click("button", "إعداد تقرير جديد")
        path = report_path(j)
        before = report(j, path)
        if scenario.startswith("report-service-"):
            with monkeypatch.context() as environment:
                absent_service(environment)
                with local_worker_services(app.config):
                    terminal = scenario == "report-service-retries-exhausted"
                    wait_for_service_failure(j, path, terminal=terminal)
                    result["observed_worker_state"] = report(j, path)["job"]
                    issue = j.page.locator(".report-issue")
                    try:
                        expect(issue).to_contain_text(j.text(UNAVAILABLE if terminal else RETRYING), timeout=12000)
                    except AssertionError:
                        result["refresh_diagnostic"] = j.page.evaluate("""() => ({
                          dirty: SOCifyDrafts.hasChanges(workspace),
                          profile: document.querySelector('input[name=profile]')?.value,
                          reports: document.querySelectorAll('.report-revision').length,
                          timer: autopsyReportTimer,
                          status: document.querySelector('.report-status')?.textContent,
                          busy: workspace.getAttribute('aria-busy')
                        })""")
                        raise
                    expect(j.page.locator(".report-revision")).not_to_contain_text("ANALYSIS_UNAVAILABLE")
                    if terminal:
                        expect(issue).to_contain_text(j.text(EXHAUSTED))
                        expect(j.page.get_by_role("button", name=j.text("إعادة المحاولة"), exact=True)).to_have_count(0)
                        expect(j.page.get_by_role("button", name=j.text("إعداد تقرير جديد"), exact=True)).to_be_enabled()
                    else:
                        j.click("button", "إلغاء المعالجة")
                        expect(j.page.locator(".report-status")).to_contain_text(j.text("أُلغيت المعالجة"))
                        expect(j.page.locator(".report-issue")).to_have_count(0)
            after = report(j, path)
            assert after["payload"] == before["payload"] and after["sha256"] == before["sha256"]
            assert after["formats"] == [] and len(j.state()["reports"]) == 1
            expect(j.page.get_by_role("button", name=j.text("مراجعة واعتماد النسخة"), exact=True)).to_have_count(0)
            result["outcomes"] = ["actual unavailable analysis service", scenario, "retained snapshot unchanged", "no fabricated file or approval"]

        elif scenario == "report-profile-background-change":
            profile = j.page.locator("input[name=profile]")
            label = j.text("منقح: بيانات إحصائية وحالة فقط")
            profile.fill(label)
            manager.login("manager@socify.local")
            manager.page.goto(j.case_url + "?tab=reports")
            manager.settle()
            manager.click("button", "إلغاء المعالجة")
            expect(j.page.locator(".report-status")).to_contain_text(j.text("أُلغيت المعالجة"), timeout=12000)
            expect(profile).to_have_value(label)
            j.click("button", "إعداد تقرير جديد")
            current = report(j, report_path(j))
            assert current["payload"]["profile"] == "metadata_only_v1"
            assert current["payload"].get("evidence") is None
            assert report(j, path)["payload"] == before["payload"]
            result["outcomes"] = [
                "background report update retained the selected redaction policy",
                "next report contains metadata only",
                "earlier snapshot unchanged",
            ]

        else:
            j.click("button", "إلغاء المعالجة")
            cancelled = report(j, path)
            assert cancelled["job"]["state"] == "cancelled" and cancelled["formats"] == []
            if scenario == "report-stale-retry-snapshot":
                j.assessment("New evidence changed the investigation conclusion after cancellation.", escalate=False)
                expect(j.page.locator(".report-revision")).to_contain_text(j.text("تغيرت القضية بعد إعداد هذا التقرير"))
            j.click("button", "إعادة المحاولة")
            after = report(j, path)
            assert after["job"]["state"] == "queued" and after["job"]["id"] == before["job"]["id"]
            assert after["payload"] == before["payload"] and after["sha256"] == before["sha256"]
            assert len(j.state()["reports"]) == 1 and after["formats"] == []
            if scenario == "report-stale-retry-snapshot":
                assert after["source_version"] < j.state()["version"]
                expect(j.page.get_by_role("button", name=j.text("مراجعة واعتماد النسخة"), exact=True)).to_have_count(0)
                j.click("button", "إعداد تقرير جديد")
                fresh = report(j, report_path(j))
                assert fresh["source_version"] == j.state()["version"]
                assert fresh["payload"]["investigation_assessment"]["executive_note"] == "New evidence changed the investigation conclusion after cancellation."
            result["outcomes"] = [
                scenario,
                "explicit retry reused its job and immutable snapshot",
                "no extra report created by retry",
                "queued work is not represented as a finished download",
            ]
        screenshots(j, scenario, language)


@pytest.mark.e2e
@pytest.mark.skipif(sys.platform != "linux", reason="The completed recovery requires the real isolated Linux renderer")
@pytest.mark.parametrize("language", ["ar", "en"])
def test_native_service_recovery_finishes_the_same_report_and_allows_independent_review(app, monkeypatch, language):
    scenario = "report-native-service-recovery"
    with review_session(app, language, scenario) as (j, manager, result):
        upload_logs(j, "recovery.json", "Evidence retained while report generation is unavailable")
        j.click("link", "التقارير والمراجعة")
        j.click("button", "إعداد تقرير جديد")
        path = report_path(j)
        before = report(j, path)
        with monkeypatch.context() as environment:
            absent_service(environment)
            with local_worker_services(app.config):
                wait_for_service_failure(j, path)
                expect(j.page.locator(".report-issue")).to_contain_text(j.text(RETRYING), timeout=10000)
        with local_worker_services(app.config):
            pdf = "تنزيل PDF" if language == "ar" else "Download PDF"
            j.page.get_by_role("link", name=pdf, exact=True).wait_for(timeout=90000)
            after = report(j, path)
            assert after["job"]["id"] == before["job"]["id"] and after["job"]["state"] == "completed"
            assert after["payload"] == before["payload"] and after["sha256"] == before["sha256"]
            assert set(after["formats"]) == {"json", "html", "md", "docx", "pdf"}
            assert len(j.state()["reports"]) == 1
            expect(j.page.locator(".report-issue")).to_have_count(0)
            manager.login("manager@socify.local")
            manager.page.goto(j.case_url + "?tab=reports")
            manager.settle()
            manager.click("button", "مراجعة واعتماد النسخة")
            manager.click("button", "حفظ", manager.page.get_by_role("dialog"))
            assert report(manager, path)["state"] == "approved"
            with manager.page.expect_download() as downloaded:
                manager.page.get_by_role("link", name=pdf, exact=True).click()
            assert Path(downloaded.value.path()).read_bytes().startswith(b"%PDF-")
        screenshots(manager, scenario, language)
        result["outcomes"] = [
            "actual missing analysis service recovered using the real native renderer",
            "same job and snapshot produced all five formats",
            "independent manager approved and downloaded actual PDF",
            "no simulated successful response",
        ]
