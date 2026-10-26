import hashlib
import json
import shutil
import threading
from pathlib import Path

import pytest
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from scripts.local_services import local_worker_services


@pytest.mark.e2e
def test_case_first_operational_browser_with_csrf_and_mobile_layout(app):
    app.config.update(LEGACY_TRAINING_TESTS=False, ALLOW_REGISTRATION=False, WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=shutil.which("chromium"))
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            page.add_init_script(path=str(Path("node_modules/axe-core/axe.min.js").resolve()))
            page.goto(f"http://127.0.0.1:{server.server_port}/login")
            page.locator("input[name=email]").fill("analyst@socify.local")
            page.locator("input[name=password]").fill("Training-Safe-Password-2026!")
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/cases")
            assert page.locator("#primary-nav a[href='/lab']").count() == 0
            page.get_by_role("button", name="إنشاء قضية", exact=True).click()
            dialog = page.get_by_role("dialog")
            dialog.locator("input[name=title]").fill("Browser autopsy case")
            dialog.locator("input[name=reason]").fill("مراجعة تنبيه")
            dialog.locator("textarea[name=objective]").fill("Verify impact using retained evidence")
            dialog.get_by_role("button", name="حفظ", exact=True).click()
            page.wait_for_url("**/cases/*")
            page.get_by_role("heading", name="Browser autopsy case", exact=True).first.wait_for()
            assert page.locator("textarea[name=objective]").input_value() == "Verify impact using retained evidence"
            page.get_by_role("link", name="الأصول والمؤشرات", exact=True).click()
            page.get_by_role("button", name="إضافة الأصول والأجهزة", exact=True).click()
            dialog = page.get_by_role("dialog")
            dialog.locator("input[name=name]").fill("Internal web defender")
            dialog.locator("input[name=type]").fill("خادم ويب")
            dialog.locator("input[name=role]").fill("مدافع أو هدف")
            dialog.get_by_role("button", name="حفظ", exact=True).click()
            page.get_by_role("heading", name="Internal web defender", exact=True).wait_for()
            violations = page.evaluate("async () => (await axe.run(document)).violations.filter(item => ['serious', 'critical'].includes(item.impact))")
            assert not violations, [(item["id"], item["nodes"]) for item in violations]
            for width in (360, 390, 768, 1440):
                page.set_viewport_size({"width": width, "height": 1000})
                assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), width
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.e2e
def test_manager_procedure_library_and_report_worker_browser(app):
    app.config.update(LEGACY_TRAINING_TESTS=False, ALLOW_REGISTRATION=False, WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with local_worker_services(app.config), sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=shutil.which("chromium"))
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.add_init_script(path=str(Path("node_modules/axe-core/axe.min.js").resolve()))
            page.goto(f"http://127.0.0.1:{server.server_port}/login")
            page.locator("input[name=email]").fill("manager@socify.local")
            page.locator("input[name=password]").fill("Training-Safe-Password-2026!")
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/cases")
            page.get_by_role("link", name="كتيبات الاستجابة", exact=True).click()
            page.get_by_role("button", name="إضافة القوالب الإرشادية للمراجعة").click()
            page.get_by_role("button", name="اعتماد ونشر هذا الإصدار").first.wait_for()
            page.get_by_role("button", name="اعتماد ونشر هذا الإصدار").first.click()
            page.get_by_role("link", name="القضايا", exact=True).click()
            page.get_by_role("button", name="إنشاء قضية", exact=True).click()
            dialog = page.get_by_role("dialog")
            dialog.locator("input[name=title]").fill("Browser report review")
            dialog.locator("input[name=reason]").fill("مراجعة تنبيه")
            dialog.locator("textarea[name=objective]").fill("Check locally generated report artifacts and review controls")
            dialog.get_by_role("button", name="حفظ", exact=True).click()
            page.wait_for_url("**/cases/*")
            page.get_by_role("link", name="التقارير والمراجعة", exact=True).click()
            page.get_by_role("button", name="إعداد تقرير جديد", exact=True).click()
            page.get_by_role("link", name="تنزيل PDF", exact=True).wait_for(timeout=60000)
            assert page.get_by_role("link", name="تنزيل DOCX", exact=True).count() == 1
            with page.expect_download() as download:
                page.get_by_role("link", name="تنزيل PDF", exact=True).click()
            assert Path(download.value.path()).read_bytes().startswith(b"%PDF-")
            violations = page.evaluate("async () => (await axe.run(document)).violations.filter(item => ['serious', 'critical'].includes(item.impact))")
            assert not violations, [(item["id"], item["nodes"]) for item in violations]
            for width in (360, 768, 1440, 1920):
                page.set_viewport_size({"width": width, "height": 1000})
                assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), width
            assert errors == []
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.e2e
def test_local_sample_manual_reputation_and_team_assignment_browser(app):
    app.config.update(LEGACY_TRAINING_TESTS=False, ALLOW_REGISTRATION=False, WTF_CSRF_ENABLED=True)
    with app.app_context():
        from socify.db import get_db

        get_db().execute(
            "INSERT INTO users(email, password_hash, name, role, workspace_id, is_active) SELECT 'browser-l2@example.test', password_hash, 'L2 Browser Responder', 'l2_responder', 1, 1 FROM users WHERE role = 'analyst' LIMIT 1"
        )
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with local_worker_services(app.config), sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=shutil.which("chromium"))
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.add_init_script(path=str(Path("node_modules/axe-core/axe.min.js").resolve()))
            page.goto(f"http://127.0.0.1:{server.server_port}/login")
            page.locator("input[name=email]").fill("manager@socify.local")
            page.locator("input[name=password]").fill("Training-Safe-Password-2026!")
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/cases")
            page.get_by_role("button", name="إنشاء قضية", exact=True).click()
            dialog = page.get_by_role("dialog")
            dialog.locator("input[name=title]").fill("Browser forensic evidence")
            dialog.locator("input[name=reason]").fill("مراجعة تنبيه")
            dialog.locator("textarea[name=objective]").fill("Local samples, manually imported reputation, and team log assignments")
            dialog.get_by_role("button", name="حفظ", exact=True).click()
            page.wait_for_url("**/cases/*")
            page.get_by_role("heading", name="Browser forensic evidence", exact=True).first.wait_for()
            case_id = int(page.url.rsplit("/", 1)[1])
            case = page.evaluate("caseId => api(`/api/cases/${caseId}`)", case_id)
            page.evaluate(
                "caseId => api(`/api/cases/${caseId}/imports`, {method:'POST', body:{filename:'browser-assigned.jsonl',content:'{\"title\":\"Browser assignment log\"}\\n'}})",
                case_id,
            )
            page.get_by_role("link", name="الأصول والمؤشرات", exact=True).click()
            content = b"Synthetic EICAR-STANDARD-ANTIVIRUS-TEST-FILE marker"
            digest = hashlib.sha256(content).hexdigest()
            page.locator("input[name=sample]").set_input_files({"name": "browser-sample.bin", "mimeType": "application/octet-stream", "buffer": content})
            page.get_by_role("button", name="حجر العينة", exact=True).click()
            page.get_by_role("button", name="تحليل ساكن محلي", exact=True).wait_for()
            page.get_by_role("button", name="تحليل ساكن محلي", exact=True).click()
            page.get_by_text("SOCify local static analysis/1", exact=True).wait_for(timeout=40000)
            assert page.get_by_text("never executed", exact=True).count() == 1
            report = {
                "data": {
                    "id": digest,
                    "type": "file",
                    "attributes": {"sha256": digest, "last_analysis_date": 1790000000, "last_analysis_stats": {"malicious": 1, "undetected": 2}},
                }
            }
            page.locator("input[name=subject]").fill(f"عينة: browser-sample.bin · {digest}")
            page.locator("input[name=vt_report]").set_input_files(
                {"name": "manual-vt.json", "mimeType": "application/json", "buffer": json.dumps(report).encode()}
            )
            page.get_by_role("button", name="استيراد نتيجة الفحص", exact=True).click()
            page.get_by_text("VirusTotal v3 manual import", exact=True).wait_for()
            page.get_by_role("link", name="الفريق", exact=True).click()
            choice = page.locator("input[name=case_id]")
            choice.fill(f"{case['reference']} · Browser forensic evidence")
            choice.press("Tab")
            page.locator("input[name=job_id]").wait_for()
            page.locator("input[name=job_id]").fill("browser-assigned.jsonl · 1 سجل")
            page.locator("input[name=assignee]").fill("L2 Browser Responder · مستجيب L2")
            page.locator("textarea[name=instructions]").fill("Record shared team findings")
            page.locator("form").filter(has=page.locator("textarea[name=instructions]")).get_by_role("button", name="حفظ", exact=True).click()
            page.get_by_role("cell", name="Record shared team findings", exact=True).wait_for()
            page.get_by_role("link", name="Browser forensic evidence", exact=True).click()
            page.get_by_role("link", name="التحقيق والخط الزمني", exact=True).click()
            page.get_by_role("heading", name="Browser assignment log", exact=True).wait_for()
            assert page.get_by_text("وقت الحدث غير معروف؛ لا يُستبدل بوقت الاستيراد", exact=False).count() == 1
            page.get_by_role("button", name="تمييز السجل وإضافة ملاحظة", exact=True).click()
            dialog = page.get_by_role("dialog")
            dialog.locator("input[name=title]").fill("Important shared evidence")
            dialog.locator("textarea[name=notes]").fill("Investigators should examine this retained record")
            dialog.get_by_role("button", name="حفظ", exact=True).click()
            page.get_by_role("heading", name="علامات السجلات المهمة · Important shared evidence", exact=True).wait_for()
            assert "Investigators should examine this retained record" in page.locator(".autopsy-timeline").inner_text()
            page.locator("input[name=attack_search]").fill("T1059")
            previous_choices = page.locator("input[name=technique_id]").get_attribute("list")
            assert previous_choices
            with page.expect_response(lambda response: response.url.endswith("/attack?q=T1059") and response.request.method == "GET") as search:
                page.get_by_role("button", name="بحث التقنيات", exact=True).click()
            assert search.value.status == 200
            page.locator(f'datalist[id="{previous_choices}"]').wait_for(state="detached")
            page.locator("input[name=technique_id]").fill("T1059 · Command and Scripting Interpreter")
            page.locator("input[name=assessment]").fill("مقترح")
            page.locator("textarea[name=reason]").fill("Retain as a hypothesis until command execution evidence is found")
            with page.expect_response(lambda response: response.url.endswith("/attack") and response.request.method == "POST") as annotation:
                page.locator("form").filter(has=page.locator("input[name=assessment]")).get_by_role("button", name="حفظ", exact=True).click()
            assert annotation.value.status == 201
            page.get_by_role("cell", name="T1059", exact=True).wait_for()
            violations = page.evaluate("async () => (await axe.run(document)).violations.filter(item => ['serious', 'critical'].includes(item.impact))")
            assert not violations, [(item["id"], item["nodes"]) for item in violations]
            page.set_viewport_size({"width": 360, "height": 1000})
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            assert errors == []
            page.get_by_role("link", name="الفريق", exact=True).click()
            page.locator("input[name=email]").fill("invited-investigator@example.test")
            page.locator("input[name=role]").fill("محقق")
            page.locator("form").filter(has=page.locator("input[name=email]")).get_by_role("button", name="حفظ", exact=True).click()
            invite = page.get_by_role("dialog").locator("input[readonly]")
            invite.wait_for()
            invitation_url = invite.input_value()
            assert "#invitation_token=" in invitation_url and "?invitation_token=" not in invitation_url
            join = browser.new_page()
            join.goto(invitation_url)
            assert len(join.locator("input[name=invitation_token]").input_value()) >= 32
            assert "invitation_token" not in join.url
            join.locator("input[name=name]").fill("Invited investigator")
            join.locator("input[name=email]").fill("invited-investigator@example.test")
            join.locator("input[name=password]").fill("Training-Safe-Password-2026!")
            join.get_by_role("button", name="إنشاء الحساب", exact=True).click()
            join.wait_for_url("**/login")
            join.locator("input[name=email]").fill("invited-investigator@example.test")
            join.locator("input[name=password]").fill("Training-Safe-Password-2026!")
            join.get_by_role("button", name="دخول إلى المنصة", exact=True).click()
            join.wait_for_url("**/cases")
            join.get_by_text("لا توجد قضايا في النطاق المصرح", exact=True).wait_for()
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.e2e
def test_case_import_preview_commit_and_export_browser(app):
    app.config.update(LEGACY_TRAINING_TESTS=False, ALLOW_REGISTRATION=False, WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=shutil.which("chromium"))
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            page.add_init_script(path=str(Path("node_modules/axe-core/axe.min.js").resolve()))
            page.goto(f"http://127.0.0.1:{server.server_port}/login")
            page.locator("input[name=email]").fill("analyst@socify.local")
            page.locator("input[name=password]").fill("Training-Safe-Password-2026!")
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/cases")
            page.get_by_role("button", name="إنشاء قضية", exact=True).click()
            dialog = page.get_by_role("dialog")
            dialog.locator("input[name=title]").fill("Browser import investigation")
            dialog.locator("input[name=reason]").fill("مراجعة تنبيه")
            dialog.locator("textarea[name=objective]").fill("Preserve and inspect the original log evidence")
            dialog.get_by_role("button", name="حفظ", exact=True).click()
            page.wait_for_url("**/cases/*")
            page.get_by_role("link", name="السجلات والأدلة", exact=True).click()
            raw = b'{"title":"Browser linked log","event_time":"2026-10-24T12:00:00Z","source_ip":"192.0.2.20"}\n'
            page.locator("input[type=file]").set_input_files({"name": "browser-evidence.jsonl", "mimeType": "application/x-ndjson", "buffer": raw})
            page.get_by_role("button", name="معاينة السجلات والبصمة", exact=True).click()
            page.locator("pre").filter(has_text="Browser linked log").wait_for()
            page.get_by_role("button", name="اعتماد الاستيراد", exact=True).click()
            page.get_by_role("cell", name="Browser linked log", exact=True).first.wait_for()
            with page.expect_download() as capture:
                page.get_by_role("link", name="تنزيل الأصل", exact=True).click()
            assert Path(capture.value.path()).read_bytes() == raw
            with page.expect_download() as capture:
                page.locator("a[href*='format=json&redacted=0']").click()
            data = json.loads(Path(capture.value.path()).read_text())
            assert data[0]["title"] == "Browser linked log"
            assert data[0]["source_ip"] == "192.0.2.20"
            violations = page.evaluate("async () => (await axe.run(document)).violations.filter(item => ['serious', 'critical'].includes(item.impact))")
            assert not violations, [(item["id"], item["nodes"]) for item in violations]
            page.set_viewport_size({"width": 390, "height": 1000})
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
