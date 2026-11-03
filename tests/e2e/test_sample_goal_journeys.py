"""Investigate retained files using interface actions and independent read-only evidence."""

import base64
import hashlib
import io
import json
import sys
import time
import zipfile

import pytest
from playwright.sync_api import expect

from scripts.local_services import local_worker_services
from socify.autopsy_static_analysis import validate_yara
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_report_recovery_journeys import absent_service, screenshots
from tests.e2e.test_review_workflow import review_session

CONTENT = b"Retained maintenance note. Scheduled work completed."
RETRYING = "التحليل متوقف مؤقتًا. ستتم إعادة المحاولة تلقائيًا."
FAILED = "تعذر إكمال التحليل. العينة محفوظة."


def files(j):
    j.nav("تحليل الأدلة")
    j.page.get_by_role("link", name="الملفات والبريد" if j.page.locator("html").get_attribute("lang") == "ar" else "Files & email", exact=True).click()
    j.settle()


def upload(j, content=CONTENT, name="maintenance.txt", *, quarantine=False):
    j.page.locator("input[name=sample]").set_input_files({"name": name, "mimeType": "application/octet-stream", "buffer": content})
    if quarantine:
        j.click("button", "حجر العينة")
    else:
        j.page.get_by_role("button", name="فحص الملف" if j.page.locator("html").get_attribute("lang") == "ar" else "Inspect file", exact=True).click()
        j.settle()


def analyses(j):
    return j.page.evaluate("id => api(`/api/cases/${id}/records?kind=analysis&limit=100`)", j.case_id)["items"]


def samples(j):
    return j.page.evaluate("id => api(`/api/cases/${id}/samples`)", j.case_id)["items"]


def start_analysis(j):
    with j.page.expect_response(lambda response: response.request.method == "POST" and response.url.endswith("/analyze")) as queued:
        j.click("button", "تحليل ساكن محلي")
    assert queued.value.ok
    return queued.value.json()["id"]


def read_job(j, identifier):
    return j.page.evaluate("p => api(p)", f"/api/cases/{j.case_id}/jobs/{identifier}")


def wait_failure(j, identifier, *, exhausted=False):
    deadline = time.monotonic() + 45
    expected = "failed" if exhausted else "queued"
    while time.monotonic() < deadline:
        job = read_job(j, identifier)
        if job["state"] == expected and job["error_code"] == "ANALYSIS_UNAVAILABLE":
            return job
        j.page.wait_for_timeout(250)
    raise AssertionError(f"Expected actual unavailable-service failure: {job}")


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "file-readable-summary",
        "file-repeated-inspection",
        "file-existing-inspection",
        "file-empty-recovery",
        "file-worker-retry-feedback",
        "file-worker-exhausted",
    ],
)
def test_sample_user_reads_results_and_recovers_from_failure(app, monkeypatch, language, scenario):
    with review_session(app, language, scenario) as (j, _manager, result):
        files(j)
        if scenario.startswith("file-worker-"):
            upload(j, quarantine=True)
            identifier = start_analysis(j)
            with monkeypatch.context() as environment:
                absent_service(environment)
                with local_worker_services(app.config):
                    exhausted = scenario == "file-worker-exhausted"
                    job = wait_failure(j, identifier, exhausted=exhausted)
                    result["observed_job"] = job
                    expect(j.page.get_by_role("dialog")).to_contain_text(j.text(FAILED if exhausted else RETRYING), timeout=10000)
                    expect(j.page.get_by_role("dialog")).not_to_contain_text("ANALYSIS_UNAVAILABLE")
                    if not exhausted:
                        j.click("button", "إلغاء المعالجة", j.page.get_by_role("dialog"))
                        assert read_job(j, identifier)["state"] == "cancelled"
                    assert analyses(j) == [] and len(samples(j)) == 1
            j.click("button", "إغلاق", j.page.get_by_role("dialog"))
            expect(j.page.locator(".sample-job-state")).to_contain_text(j.text("تعذرت المعالجة" if exhausted else "أُلغيت المعالجة"))
        elif scenario == "file-empty-recovery":
            upload(j, b"")
            expect(j.page.locator(".sample-upload [role=alert]")).to_be_visible()
            assert samples(j) == [] and analyses(j) == []
            upload(j)
            expect(j.page.get_by_role("dialog")).to_be_visible()
            j.click("button", "إغلاق", j.page.get_by_role("dialog"))
            assert len(samples(j)) == len(analyses(j)) == 1
        else:
            upload(j)
            dialog = j.page.get_by_role("dialog")
            expect(dialog).to_be_visible()
            if scenario == "file-readable-summary":
                expect(dialog).not_to_contain_text("low_signal_static_only")
                expect(dialog).to_contain_text(j.text("لا مؤشرات بارزة في الفحص الساكن"))
            j.click("button", "إغلاق", dialog)
            before = analyses(j)
            version = j.state()["version"]
            if scenario == "file-repeated-inspection":
                upload(j)
                j.click("button", "إغلاق", j.page.get_by_role("dialog"))
                assert analyses(j) == before and j.state()["version"] == version
            elif scenario == "file-existing-inspection":
                j.click("button", "فحص أولي فوري")
                assert analyses(j) == before and j.state()["version"] == version
                expect(j.page.get_by_role("dialog").locator(".sample-result")).to_be_visible()
                j.click("button", "إغلاق", j.page.get_by_role("dialog"))
        assert_accessible(j.page)
        screenshots(j, scenario, language)
        result["outcomes"] = [scenario, "interface actions", "independent retained-record verification"]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "file-double-extension",
        "file-pdf-active-content",
        "file-archive-macro",
        "file-observables-no-network",
        "file-new-content-same-name",
        "file-renamed-type",
        "file-quarantine-repeat",
        "file-oversized-recovery",
        "file-case-isolation",
        "file-worker-cancel-resume",
        "file-worker-reload-status",
        "file-rule-selection-retained",
    ],
)
def test_retained_file_edge_conditions(app, database, user_ids, language, scenario):
    if scenario == "file-rule-selection-retained":
        source = 'rule Retained_Marker { strings: $a = "RETAINED_MARKER" condition: $a }'
        validation = validate_yara(
            {"rules": source, "fixtures": {"positive": [base64.b64encode(b"RETAINED_MARKER").decode()], "negative": [base64.b64encode(CONTENT).decode()]}}
        )
        assert validation["valid"]
        workspace = database.execute("SELECT workspace_id FROM users WHERE id=?", (user_ids["analyst"],)).fetchone()[0]
        database.execute(
            "INSERT INTO autopsy_yara_packs(workspace_id,name,version,source,license,origin,sha256,validation,created_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                workspace,
                "Retained marker",
                1,
                source,
                "Internal",
                "Existing package fixture",
                hashlib.sha256(source.encode()).hexdigest(),
                json.dumps(validation),
                user_ids["analyst"],
                "2026-11-03T00:00:00Z",
            ),
        )
    with review_session(app, language, scenario) as (j, _manager, result):
        files(j)
        if scenario.startswith("file-worker-"):
            upload(j, quarantine=True)
            identifier = start_analysis(j)
            dialog = j.page.get_by_role("dialog")
            if scenario == "file-worker-cancel-resume":
                j.click("button", "إلغاء المعالجة", dialog)
                assert read_job(j, identifier)["state"] == "cancelled"
                j.click("button", "إعادة المحاولة", dialog)
                assert read_job(j, identifier)["state"] == "queued"
            j.click("button", "إغلاق", dialog)
            j.page.reload()
            j.settle()
            expect(j.page.locator(".sample-job-state")).to_contain_text(j.text("بانتظار المعالجة"))
            assert samples(j)[0]["last_job"]["id"] == identifier
            j.page.set_viewport_size({"width": 390, "height": 1000})
            control = j.page.locator(".sample-job").get_by_role("button", name=j.text("إلغاء المعالجة"), exact=True).bounding_box()
            assert control["x"] >= 0 and control["x"] + control["width"] <= 390
            j.click("button", "إلغاء المعالجة", j.page.locator(".sample-job"))
            assert read_job(j, identifier)["state"] == "cancelled" and analyses(j) == []
        elif scenario == "file-quarantine-repeat":
            upload(j, quarantine=True)
            before = samples(j)
            upload(j, quarantine=True)
            assert samples(j) == before and analyses(j) == []
        elif scenario == "file-oversized-recovery":
            upload(j, b"x" * (10 * 1024 * 1024 + 1))
            expect(j.page.locator(".sample-upload [role=alert]")).to_be_visible()
            assert samples(j) == []
            upload(j)
            j.click("button", "إغلاق", j.page.get_by_role("dialog"))
            assert len(samples(j)) == 1
        elif scenario in {"file-new-content-same-name", "file-renamed-type", "file-case-isolation"}:
            content = b"MZ" + b"\x00" * 70 if scenario == "file-renamed-type" else CONTENT
            name = "invoice.exe" if scenario == "file-renamed-type" else "maintenance.txt"
            upload(j, content, name)
            j.click("button", "إغلاق", j.page.get_by_role("dialog"))
            before = analyses(j)[0]
            old_case = j.case_id
            if scenario == "file-case-isolation":
                j.nav("إدارة القضايا")
                j.create_case()
                files(j)
                assert samples(j) == []
            upload(
                j, content + b" Revised" if scenario == "file-new-content-same-name" else content, "invoice.pdf" if scenario == "file-renamed-type" else name
            )
            j.click("button", "إغلاق", j.page.get_by_role("dialog"))
            current = analyses(j)[0]
            assert current["id"] != before["id"]
            if scenario == "file-renamed-type":
                assert current["payload"]["extension_mismatch"] and not before["payload"]["extension_mismatch"]
                assert len(samples(j)) == 1
            elif scenario == "file-case-isolation":
                assert current["payload"]["sample_id"] != before["payload"]["sample_id"]
                assert j.page.evaluate("id=>api(`/api/cases/${id}/records?kind=analysis`)", old_case)["items"] == [before]
            else:
                assert current["payload"]["sha256"] != before["payload"]["sha256"] and len(samples(j)) == 2
        elif scenario == "file-rule-selection-retained":
            result["setup_note"] = "Pre-existing validated immutable package fixture; publication is not counted as a user task."
            choice = j.page.locator("input[name=yara_pack_id]")
            choice.fill("Retained marker")
            choice.press("ArrowDown")
            j.page.get_by_role("option").filter(has_text="Retained marker").click()
            upload(j, b"RETAINED_MARKER")
            expect(j.page.get_by_role("dialog")).to_contain_text("Retained_Marker")
            j.click("button", "إغلاق", j.page.get_by_role("dialog"))
            before = analyses(j)
            j.page.reload()
            j.settle()
            expect(j.page.locator("input[name=yara_pack_id]")).to_have_value("Retained marker")
            j.click("button", "فحص أولي فوري")
            expect(j.page.get_by_role("dialog")).to_contain_text("Retained_Marker")
            j.click("button", "إغلاق", j.page.get_by_role("dialog"))
            assert analyses(j) == before
        else:
            content, name = CONTENT, "review.txt"
            expected = None
            if scenario == "file-double-extension":
                content, name, expected = b"MZ" + b"\x00" * 70, "invoice.pdf.exe", "امتداد مزدوج مضلل"
            elif scenario == "file-pdf-active-content":
                content, name, expected = b"%PDF-1.7\n/JavaScript /OpenAction\n%%EOF", "invoice.pdf", "محتوى نشط داخل PDF"
            elif scenario == "file-archive-macro":
                archive = io.BytesIO()
                with zipfile.ZipFile(archive, "w") as container:
                    container.writestr("[Content_Types].xml", "<Types/>")
                    container.writestr("word/vbaProject.bin", b"AutoOpen WScript.Shell")
                content, name, expected = archive.getvalue(), "invoice.docm", "وحدات ماكرو داخل المستند"
            elif scenario == "file-observables-no-network":
                content = b"Retained https://example.test/review 198.51.100.30 analyst@example.test"
            requests = []
            j.page.on("request", lambda request: requests.append(request.url) if request.url.startswith("https://example.test/") else None)
            upload(j, content, name)
            dialog = j.page.get_by_role("dialog")
            if expected:
                expect(dialog).to_contain_text(j.text(expected))
            else:
                dialog.get_by_text(j.text("الروابط المرصودة"), exact=True).click()
                expect(dialog.locator(".sample-observables").first).to_contain_text("https://example.test/review")
                assert dialog.locator(".sample-observables a").count() == 0 and requests == []
            assert_accessible(j.page)
            j.click("button", "إغلاق", dialog)
        screenshots(j, scenario, language)
        result["outcomes"] = [scenario, "retained evidence verified independently"]


@pytest.mark.e2e
@pytest.mark.skipif(sys.platform != "linux", reason="Requires the actual isolated Linux analysis service")
@pytest.mark.parametrize("language", ["ar", "en"])
def test_sample_native_service_recovers_without_reuploading_or_fabricating_results(app, monkeypatch, language):
    scenario = "file-native-service-recovery"
    with review_session(app, language, scenario) as (j, _manager, result):
        files(j)
        upload(j, quarantine=True)
        retained = samples(j)[0]
        identifier = start_analysis(j)
        with monkeypatch.context() as environment:
            absent_service(environment)
            with local_worker_services(app.config):
                wait_failure(j, identifier)
                expect(j.page.get_by_role("dialog")).to_contain_text(j.text(RETRYING), timeout=10000)
        with local_worker_services(app.config):
            j.page.get_by_role("dialog").get_by_role("button", name=j.text("عرض النتيجة"), exact=True).click(timeout=90000)
            expect(j.page.get_by_role("dialog").locator(".sample-result")).to_contain_text(retained["sha256"])
            assert read_job(j, identifier)["state"] == "completed"
            assert len(samples(j)) == 1 and len(analyses(j)) == 1
            assert analyses(j)[0]["payload"]["sha256"] == retained["sha256"]
        j.click("button", "إغلاق", j.page.get_by_role("dialog"))
        screenshots(j, scenario, language)
        result["outcomes"] = ["actual native service restored", "same sample and job completed", "no fabricated analysis"]
