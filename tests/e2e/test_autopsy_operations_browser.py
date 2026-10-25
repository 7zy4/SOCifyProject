import json
import shutil
import threading
from pathlib import Path

import pytest
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from socify.security import totp_code


@pytest.mark.e2e
def test_local_intelligence_sigma_library_case_workflow_capsule_and_mfa_browser(app):
    app.config.update(LEGACY_TRAINING_TESTS=False, ALLOW_REGISTRATION=False, WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
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
            page.get_by_role("link", name="مكتبة التحليل المحلي", exact=True).click()
            feed = page.locator("section.panel").filter(has=page.get_by_role("heading", name="استيراد إصدار محلي جديد", exact=True))
            feed.locator("input[type=file]").set_input_files(
                {
                    "name": "intel.json",
                    "mimeType": "application/json",
                    "buffer": json.dumps([{"type": "ip", "value": "192.0.2.8", "verdict": "suspicious"}]).encode(),
                }
            )
            for name, value in (
                ("name", "Browser internal snapshot"),
                ("version", "1"),
                ("source", "Browser synthetic evidence"),
                ("license", "Synthetic test only"),
                ("format", "flat"),
            ):
                feed.locator(f"input[name={name}]").fill(value)
            feed.locator("input[name=expires_at]").fill("2030-01-01T12:00")
            feed.get_by_role("button", name="حفظ", exact=True).click()
            page.get_by_role("button", name="تفعيل الإصدار", exact=True).click()
            page.get_by_text("الإصدار المختار", exact=True).wait_for()
            sigma_panel = page.locator("section.panel").filter(has=page.get_by_role("heading", name="تحقق ونشر Sigma subset", exact=True))
            sigma = "title: Browser synthetic rule\nlogsource:\n  category: socify_normalized\ndetection:\n  selected:\n    title|contains: Browser suspicious\n  condition: selected\nlevel: high\n"
            sigma_panel.get_by_label("ملف Sigma", exact=True).set_input_files({"name": "rule.yml", "mimeType": "text/yaml", "buffer": sigma.encode()})
            sigma_panel.locator("input[type=file]").nth(1).set_input_files(
                {
                    "name": "fixtures.json",
                    "mimeType": "application/json",
                    "buffer": json.dumps({"positive": [{"title": "Browser suspicious log"}], "negative": [{"title": "Routine synthetic activity"}]}).encode(),
                }
            )
            sigma_panel.get_by_role("button", name="تحقق من الترجمة والاختبارات دون نشر").click()
            sigma_panel.get_by_text("اجتازت الأمثلة الإيجابية والسلبية.", exact=False).wait_for()
            sigma_panel.locator("input[name=reason]").fill("Reviewed synthetic browser fixtures")
            sigma_panel.get_by_role("button", name="حفظ", exact=True).click()
            page.get_by_role("cell", name="Browser synthetic rule", exact=True).wait_for()
            violations = page.evaluate("async () => (await axe.run(document)).violations.filter(item => ['serious', 'critical'].includes(item.impact))")
            assert not violations, violations
            case = page.evaluate(
                "async () => await api('/api/cases',{method:'POST',body:{title:'Browser integrated operations',reason:'alert_review',objective:'Verify linked local investigation workflow'}})"
            )
            case_id = case["id"]
            page.evaluate(
                "id => api(`/api/cases/${id}/imports`,{method:'POST',body:{filename:'browser.json',content:JSON.stringify([{title:'Browser suspicious log',source_ip:'192.0.2.8'}])}})",
                case_id,
            )
            page.goto(f"http://127.0.0.1:{server.server_port}/cases/{case_id}?tab=analysis")
            page.get_by_role("heading", name="الإثراء والكشف ومراجعة التنبيهات", exact=True).wait_for()
            assert page.get_by_role("cell", name="matched · suspicious", exact=True).count() == 1
            page.get_by_role("button", name="تفاصيل ومراجعة", exact=True).first.click()
            dialog = page.get_by_role("dialog")
            dialog.locator("input[name=verdict]").fill("إيجابي كاذب")
            dialog.locator("input[name=attack_outcome]").fill("فاشل أو محجوب")
            dialog.locator("textarea[name=reason]").fill("Authorized synthetic activity confirmed by retained fixture")
            dialog.get_by_role("button", name="حفظ", exact=True).click()
            dialog.get_by_role("button", name="إغلاق", exact=True).click()
            page.get_by_role("cell", name="إيجابي كاذب · فاشل أو محجوب", exact=True).wait_for()
            page.get_by_role("link", name="التحقيق والخط الزمني", exact=True).click()
            page.get_by_role("button", name="إضافة الأسباب الجذرية", exact=True).click()
            dialog = page.get_by_role("dialog")
            dialog.locator("input[name=category]").fill("غير معروف")
            dialog.locator("textarea[name=conclusion]").fill("Synthetic evidence does not establish initial access")
            dialog.get_by_role("button", name="إضافة سؤال لماذا", exact=True).click()
            dialog.get_by_role("button", name="إضافة سؤال لماذا", exact=True).click()
            whys = dialog.locator("fieldset.why-step")
            whys.nth(0).get_by_label("الإجابة", exact=True).fill("Initial hypothesis awaiting source collection")
            whys.nth(1).get_by_label("الإجابة", exact=True).fill("Branch hypothesis to verify against retained logs")
            whys.nth(1).locator("select[name=why_parent]").select_option(index=1)
            dialog.get_by_role("button", name="حفظ", exact=True).click()
            page.get_by_text("Branch hypothesis to verify", exact=False).wait_for()
            page.get_by_role("link", name="الاستجابة والتصعيد", exact=True).click()
            workflow = page.locator("section.panel").filter(has=page.get_by_role("heading", name="SLA وجمع الأدلة ومراجعة ما بعد الحادثة", exact=True))
            sla = workflow.locator("form").filter(has=page.locator("input[name=minutes]"))
            sla.locator("input[name=minutes]").fill("120")
            sla.locator("input[name=reason]").fill("Internal response target")
            sla.get_by_role("button", name="حفظ", exact=True).click()
            workflow.get_by_role("button", name="إيقاف SLA مؤقتًا", exact=True).wait_for()
            page.evaluate(
                "async id => { for (const status of ['investigating','awaiting_review']) { const c=await api(`/api/cases/${id}`); await api(`/api/cases/${id}/transitions`,{method:'POST',body:{version:c.version,status,reason:'Synthetic response workflow ready for review'}}); } }",
                case_id,
            )
            page.reload()
            page.get_by_role("button", name="إنشاء مسودة مراجعة ما بعد الحادثة", exact=True).click()
            page.get_by_role("button", name="مراجعة المسودة", exact=True).first.click()
            dialog = page.get_by_role("dialog")
            dialog.locator("textarea[name=lessons]").fill("Retain complete logs and verify hypotheses independently")
            dialog.locator("input[name=override_reason]").fill("Synthetic manager self-review exception documented")
            dialog.get_by_role("button", name="حفظ", exact=True).click()
            page.get_by_role("heading", name="مراجعة ما بعد الحادثة · reviewed", exact=True).wait_for()
            page.get_by_role("link", name="التقارير والمراجعة", exact=True).click()
            page.get_by_role("heading", name="حزم القضية والاستعادة والأرشيف", exact=True).wait_for()
            with page.expect_download() as download:
                page.get_by_role("link", name="تصدير حزمة الفريق", exact=True).click()
            assert Path(download.value.path()).read_bytes().startswith(b"PK")
            for width in (360, 390, 768, 1440):
                page.set_viewport_size({"width": width, "height": 1000})
                assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), width
            page.goto(f"http://127.0.0.1:{server.server_port}/profile")
            page.get_by_label("كلمة المرور الحالية لبدء الإعداد", exact=True).fill("Training-Safe-Password-2026!")
            page.get_by_role("button", name="بدء إعداد MFA", exact=True).click()
            dialog = page.get_by_role("dialog")
            secret = dialog.get_by_label("مفتاح إعداد المصادقة", exact=True).input_value()
            dialog.get_by_label("رمز التطبيق المحلي من ستة أرقام", exact=True).fill(totp_code(secret))
            dialog.get_by_role("button", name="تأكيد وتفعيل المصادقة", exact=True).click()
            page.get_by_label("رموز الاسترداد لمرة واحدة", exact=True).wait_for()
            page.get_by_role("dialog").get_by_role("button", name="إغلاق", exact=True).click()
            page.get_by_text("المصادقة متعددة العوامل مفعّلة", exact=False).wait_for()
            assert errors == []
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.e2e
def test_restricted_batch_browser_retains_case_navigation_without_indirect_disclosure(autopsy_case, app, client, login_as):
    base = f"/api/cases/{autopsy_case}"
    login_as("soc_manager")
    visible = client.post(base + "/imports", json={"filename": "visible.json", "content": '[{"title":"Visible assigned source"}]'})
    hidden = client.post(base + "/imports", json={"filename": "hidden.json", "content": '[{"title":"Hidden batch must never reach browser"}]'})
    assert visible.status_code == 201 and hidden.status_code == 201
    assert (
        client.put(
            base + f"/imports/{hidden.json['id']}/access", json={"restricted": True, "members": [], "reason": "Synthetic batch disclosure boundary"}
        ).status_code
        == 200
    )
    app.config["WTF_CSRF_ENABLED"] = True
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=shutil.which("chromium"))
            page = browser.new_page(viewport={"width": 390, "height": 900})
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(f"http://127.0.0.1:{server.server_port}/login")
            page.locator("input[name=email]").fill("analyst@socify.local")
            page.locator("input[name=password]").fill("Training-Safe-Password-2026!")
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/cases")
            response = page.goto(f"http://127.0.0.1:{server.server_port}/cases/{autopsy_case}?tab=analysis")
            assert response.status == 200
            page.get_by_text("نطاق دفعات محدد:", exact=False).wait_for()
            page.get_by_role("cell", name="Visible assigned source", exact=True).wait_for()
            assert page.get_by_text("Hidden batch must never reach browser", exact=False).count() == 0
            assert page.get_by_role("link", name="التقارير والمراجعة", exact=True).count() == 0
            assert page.get_by_role("link", name="الأصول والمؤشرات", exact=True).count() == 0
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            assert errors == []
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
