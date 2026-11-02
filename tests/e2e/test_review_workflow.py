"""End-user review journeys: every state change is performed through the interface."""

import json
import re
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

from scripts.local_services import local_worker_services
from tests.e2e.test_browser import assert_accessible, launch_browser

ANSWERS = {
    "incident_classification": "benign_activity",
    "initial_vector": "endpoint_process_activity",
    "triage_verdict": "benign_true_positive",
    "impact_scope": "no_compromise_blocked",
    "data_exposure": "none_observed",
    "file_and_email_assessment": "no_files_involved",
    "containment_status": "no_action_needed",
    "recommended_next_step": "close_after_manager_review",
    "urgency_level": "informational_p4",
}
ARTIFACTS = Path("artifacts/review-journeys")


class ReviewJourney:
    def __init__(self, page, base, steps):
        self.page, self.base, self.steps = page, base, steps

    def text(self, text):
        return self.page.evaluate("s => SOCifyLocale.text(s)", text)

    def settle(self):
        self.page.wait_for_load_state("networkidle")
        if self.page.locator("#workspace").count():
            self.page.locator('#workspace[aria-busy="false"]').wait_for()

    def click(self, role, name, within=None):
        self.steps.append({"action": "activate", "label": name})
        (within or self.page).get_by_role(role, name=self.text(name), exact=True).click()
        self.settle()

    def login(self, email):
        self.page.goto(self.base + "/login")
        self.page.locator("input[name=email]").fill(email)
        self.page.locator("input[name=password]").fill(DEMO_LOGIN_VALUE)
        self.page.locator("button[type=submit]").click()
        self.page.wait_for_url("**/cases")
        self.settle()

    def nav(self, name):
        menu = self.page.get_by_role("button", name=self.text("فتح القائمة"), exact=True)
        if menu.count() and menu.is_visible() and not self.page.locator("#primary-nav").is_visible():
            menu.click()
        self.click("link", name, self.page.locator("#primary-nav"))

    def create_case(self):
        self.click("button", "إنشاء قضية")
        dialog = self.page.get_by_role("dialog")
        dialog.locator("input[name=title]").fill("Authorized maintenance investigation")
        self.click("button", "حفظ", dialog)
        self.page.wait_for_url("**/cases/*")
        self.case_id = int(re.search(r"/cases/(\d+)", self.page.url)[1])
        self.case_url = self.page.url

    def assessment(self, note, escalate=True):
        self.click("link", "التقارير والمراجعة")
        for name, value in ANSWERS.items():
            self.page.locator(f'select[name="{name}"]').select_option(value)
        self.page.locator("input[name=executive_note]").fill(note)
        self.click("button", "حفظ وتصعيد مباشر للمدير" if escalate else "حفظ إجابات التقرير")

    def decision(self, decision, comment):
        self.page.locator("select[name=decision]").select_option(decision)
        self.page.locator("input[name=comment]").fill(comment)
        self.click("button", "اعتماد قرار المدير")

    def transition(self, target):
        self.click("link", "الملخص والمسؤوليات")
        section = self.page.locator("section.panel").filter(has=self.page.get_by_role("heading", name=self.text("حالة القضية"), exact=True))
        label = self.page.evaluate("value => autopsyLabel(value)", target)
        section.locator("input[name=status]").fill(label)
        section.locator("[name=reason]").fill("Evidence reviewed; documented case lifecycle decision")
        self.click("button", "حفظ", section)

    def record(self, kind, values):
        name = self.page.evaluate("kind => SOCifyLocale.template`إضافة ${autopsyLabel(kind)}`", kind)
        self.page.get_by_role("button", name=name, exact=True).click()
        dialog = self.page.get_by_role("dialog")
        for key, value in values.items():
            if key == "evidence_id":
                dialog.locator("input[name=evidence_id]").press("ArrowDown")
                dialog.get_by_role("option").filter(has_text=value).first.click()
                continue
            if key in {"phase", "status", "category"}:
                value = self.page.evaluate("value => autopsyLabel(value)", value)
            dialog.locator(f'[name="{key}"]').fill(value)
        self.click("button", "حفظ", dialog)
        expect(dialog).not_to_be_visible()

    def state(self):
        # Read-only verification; never complete a task via API.
        return self.page.evaluate("id => api(`/api/cases/${id}`)", self.case_id)


@contextmanager
def review_session(app, language, name):
    app.config.update(LEGACY_TRAINING_TESTS=False, ALLOW_REGISTRATION=False, WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    result = {"scenario": name, "language": language, "kind": "simulated interface journey", "status": "failed", "steps": [], "browser_errors": []}
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            pages = []
            for _ in range(2):
                page = browser.new_page(locale="ar-SA" if language == "ar" else "en-US", viewport={"width": 1440, "height": 1000})
                page.set_default_timeout(15000)
                page.add_init_script(path="node_modules/axe-core/axe.min.js")
                page.on("pageerror", lambda error: result["browser_errors"].append(str(error)))
                pages.append(page)
            analyst, manager = [ReviewJourney(page, f"http://127.0.0.1:{server.server_port}", result["steps"]) for page in pages]
            try:
                analyst.login("analyst@socify.local")
                analyst.create_case()
                manager.case_id = analyst.case_id
                yield analyst, manager, result
                assert not result["browser_errors"], result["browser_errors"]
                result["status"] = "completed"
            except Exception as error:
                result["error"] = str(error)
                raise
            finally:
                for who, page in zip(("analyst", "manager"), pages, strict=True):
                    if page.url != "about:blank":
                        page.screenshot(path=str(ARTIFACTS / f"{name}-{language}-{who}.png"), full_page=True)
                        result[who + "_visible_text"] = page.locator("main").inner_text()
                (ARTIFACTS / f"{name}-{language}.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
                browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)


def open_manager_review(manager):
    manager.login("manager@socify.local")
    manager.nav("التقارير")
    manager.page.locator("a.case-link").filter(has_text="Authorized maintenance investigation").click()
    manager.settle()


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_followup_is_visible_and_stale_review_cannot_overwrite_the_analyst(app, language):
    with review_session(app, language, "followup-and-concurrent-review") as (analyst, manager, result):
        analyst.assessment("Scheduled maintenance confirmed by service owner")
        open_manager_review(manager)
        before = manager.state()
        manager.decision("closed", "Reviewed; close when complete")
        expect(manager.page.locator(".closure-requirements")).to_have_attribute("open", "")
        expect(manager.page.get_by_role("alert")).to_contain_text(manager.text("أكمل متطلبات الإغلاق"))
        assert manager.state()["status"] == "escalated" and manager.state()["version"] == before["version"]
        assert manager.page.locator(".closure-requirements a").count() >= 4
        manager.page.screenshot(path=str(ARTIFACTS / f"closure-requirements-{language}.png"), full_page=True)
        feedback = "Verify the maintenance approval and retain the process evidence."
        manager.decision("needs_followup", feedback)
        analyst.page.reload()
        analyst.settle()
        expect(analyst.page.locator("main")).to_contain_text(feedback)
        analyst.page.locator("input[name=executive_note]").fill("Approval CHG-204 verified; process evidence retained.")
        analyst.click("button", "حفظ وتصعيد مباشر للمدير")
        manager.decision("approved", "Stale review must not replace the newer work")
        conflict = manager.page.evaluate("() => SOCifyLocale.error('CASE_VERSION_CONFLICT', 'تغيرت القضية؛ حدّث قبل الاعتماد')")
        expect(manager.page.get_by_role("alert")).to_contain_text(conflict)
        expect(manager.page.locator("input[name=comment]")).to_have_value("Stale review must not replace the newer work")
        manager.page.reload()
        manager.settle()
        expect(manager.page.locator("input[name=executive_note]")).to_have_value("Approval CHG-204 verified; process evidence retained.")
        manager.decision("approved", "The additional evidence answers the review request.")
        analyst.page.reload()
        analyst.settle()
        expect(analyst.page.locator("main")).to_contain_text("The additional evidence answers the review request.")
        for journey in (analyst, manager):
            assert_accessible(journey.page)
            for width in (390, 768, 1440):
                journey.page.set_viewport_size({"width": width, "height": 1000})
                assert journey.page.evaluate("document.documentElement.scrollWidth <= innerWidth"), width
        result["outcomes"] = [
            "incomplete close safely rejected",
            "manager follow-up visible to analyst",
            "stale approval rejected without losing comment",
            "new evidence independently reviewed",
        ]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_removed_assessment_note_stays_removed_after_escalation(app, language):
    with review_session(app, language, "remove-outdated-assessment") as (analyst, _manager, result):
        old_note = "Initial assumption withdrawn after reviewing the retained evidence."
        analyst.assessment(old_note, escalate=False)
        analyst.page.locator("input[name=executive_note]").fill("")
        analyst.click("button", "حفظ وتصعيد مباشر للمدير")
        analyst.page.reload()
        analyst.settle()
        expect(analyst.page.locator("input[name=executive_note]")).to_have_value("")
        with analyst.page.expect_popup() as popup:
            analyst.page.get_by_role("link", name=analyst.text("فتح التقرير"), exact=True).click()
        popup.value.wait_for_load_state("networkidle")
        expect(popup.value.locator("main")).not_to_contain_text(old_note)
        popup.value.close()
        result["outcomes"] = ["cleared assessment remains empty after reload", "withdrawn statement absent from printable report"]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_complete_review_closes_alert_and_reopening_preserves_report(app, language):
    app.config.update(LEGACY_TRAINING_TESTS=False)
    download_pdf = "تنزيل PDF" if language == "ar" else "Download PDF"
    with local_worker_services(app.config), review_session(app, language, "complete-case-closure") as (analyst, manager, result):
        analyst.click("link", "السجلات والأدلة")
        content = [
            {
                "title": "Scheduled maintenance",
                "hostname": "APP-SRV01",
                "command_line": "powershell.exe -EncodedCommand YQ==",
                "timestamp": "2026-11-02T02:20:00Z",
            }
        ]
        analyst.page.locator("input[name=file]").set_input_files(
            {"name": "maintenance.json", "mimeType": "application/json", "buffer": json.dumps(content).encode()}
        )
        analyst.click("button", "استيراد وفحص فوري")
        analyst.page.get_by_role("link", name=analyst.text("مراجعة التنبيهات"), exact=True).wait_for()
        analyst.assessment("Service owner confirmed approved maintenance; no compromise established.")
        analyst.click("link", "التحقيق والخط الزمني")
        analyst.record(
            "root_cause",
            {
                "category": "other",
                "conclusion": "Approved maintenance explains the encoded command; no broader compromise evidenced.",
                "evidence_id": "maintenance.json",
            },
        )
        analyst.click("link", "الاستجابة والتصعيد")
        analyst.record(
            "response",
            {
                "title": "Validate authorized activity",
                "phase": "validation",
                "status": "not_applicable",
                "details": "Containment is not applicable to the verified maintenance operation.",
            },
        )
        analyst.transition("awaiting_review")
        while analyst.page.get_by_role("button", name=analyst.text("إكمال المهمة"), exact=True).count():
            analyst.page.get_by_role("button", name=analyst.text("إكمال المهمة"), exact=True).first.click()
            analyst.settle()
        analyst.click("link", "التقارير والمراجعة")
        analyst.click("button", "إعداد تقرير جديد")
        analyst.page.get_by_role("link", name=download_pdf, exact=True).wait_for(timeout=60000)
        open_manager_review(manager)
        manager.click("button", "مراجعة واعتماد النسخة")
        manager.click("button", "حفظ", manager.page.get_by_role("dialog"))
        with manager.page.expect_download() as download:
            manager.page.get_by_role("link", name=download_pdf, exact=True).click()
        report_bytes = Path(download.value.path()).read_bytes()
        assert report_bytes.startswith(b"%PDF-")
        report_url = manager.page.get_by_role("link", name=download_pdf, exact=True).get_attribute("href")
        manager.decision("closed", "All retained evidence and the complete report were reviewed.")
        closed = manager.state()
        assert closed["status"] == "closed" and closed["closed_at"]
        assert manager.page.locator("select[name=decision]").count() == 0
        analyst.page.reload()
        analyst.settle()
        expect(analyst.page.locator("select[name=triage_verdict]")).to_be_disabled()
        assert not analyst.page.get_by_role("button", name=analyst.text("حفظ إجابات التقرير"), exact=True).count()
        manager.nav("المراقبة")
        manager.page.get_by_role("link").filter(has_text=manager.text("التنبيهات المغلقة")).click()
        manager.settle()
        manager.page.get_by_label(manager.text("بحث التنبيهات"), exact=True).fill(closed["reference"])
        manager.click("button", "تطبيق")
        expect(manager.page.locator("[data-alert-row]")).to_have_count(1)
        manager.page.locator("[data-alert-toggle]").click()
        manager.settle()
        expect(manager.page.locator(".dossier-view")).to_contain_text("APP-SRV01")
        manager.page.screenshot(path=str(ARTIFACTS / f"closed-alert-{language}.png"), full_page=True)
        manager.nav("إدارة القضايا")
        manager.page.get_by_label(manager.text("بحث"), exact=True).fill(closed["reference"])
        manager.click("button", "بحث")
        manager.click("link", "فتح القضية")
        manager.transition("reopened")
        assert manager.state()["status"] == "reopened" and manager.state()["closed_at"] is None
        manager.click("link", "التقارير والمراجعة")
        with manager.page.expect_download() as download:
            manager.page.locator(f'a[href="{report_url}"]').first.click()
        assert Path(download.value.path()).read_bytes() == report_bytes
        assert_accessible(manager.page)
        result["outcomes"] = [
            "retained import produced an alert",
            "complete native PDF independently approved",
            "closed alert visible",
            "closed case read only",
            "reopened case retains identical prior report",
        ]
