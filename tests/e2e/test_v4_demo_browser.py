"""Exercise the actual V4 policy and seeded workflows with CSRF and real isolated analysis."""

import json
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

from scripts.prepare_v4_demo import provision
from socify import create_app
from tests.e2e.test_browser import assert_accessible, launch_browser


@pytest.mark.e2e
def test_v4_real_demo_scope_review_roles_and_visual_matrix(tmp_path):
    directory = tmp_path / "demo"
    manifest = provision(directory)
    accounts = json.loads((directory / "accounts.json").read_text())
    keys = dict(line.split("=", 1) for line in (directory / "runtime.env").read_text().splitlines())
    app = create_app({"DATABASE": str(directory / "socify.db"), "ENV_NAME": "development", "DEMO_MODE": True, "SECRET_KEY": keys["SOCIFY_SECRET_KEY"], "CREDENTIAL_KEY": keys["SOCIFY_CREDENTIAL_KEY"]})
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    output = Path("work/v4-browser")
    output.mkdir(parents=True, exist_ok=True)
    primary, related, pending = [manifest[key] for key in ("primary_case", "related_case", "pending_case")]
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            page.add_init_script(path=str(Path("node_modules/axe-core/axe.min.js").resolve()))
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            root = f"http://127.0.0.1:{server.server_port}"

            def loaded():
                page.wait_for_function("() => document.querySelector('#workspace')?.getAttribute('aria-busy') === 'false'")
                assert page.get_by_text("تعذر تحميل مساحة العمل", exact=True).count() == 0
                assert page.get_by_text("Unable to load workspace", exact=True).count() == 0

            page.goto(root + "/login")
            page.locator("input[name=email]").fill(accounts[0]["email"])
            page.locator("input[name=password]").fill(accounts[0]["password"])
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/cases")
            loaded()
            expect(page.locator(".case-selection-card")).to_have_count(4)
            assert page.locator(".case-selection-locked input").is_disabled()
            page.screenshot(path=str(output / "cases-ar-dark.png"), full_page=True)
            assert_accessible(page)
            page.locator(f'.case-selection-card input[value="{primary}"]').check()
            page.locator(f'.case-selection-card input[value="{related}"]').check()
            page.get_by_role("button", name="بدء التحقيق بالنطاق المحدد", exact=True).click()
            page.wait_for_url(f"**/cases/{primary}")
            loaded()
            expect(page.locator("[data-investigation-context] option")).to_have_count(2)
            assert page.locator(".global-nav").count() == 0
            hrefs = page.locator("#primary-nav a").evaluate_all("items => items.map(item => item.getAttribute('href'))")
            assert len(hrefs) == len(set(hrefs))
            assert page.locator(".case-tabs a[href*='tab=logs'],.case-tabs a[href*='tab=reports'],.case-tabs a[href*='tab=analysis']").count() == 0
            routes = [f"/cases/{primary}", "/monitoring", *[f"/{tool}?case_id={primary}" for tool in ("log-management", "endpoint-security", "threat-intel", "email-security", "sandbox", "reports")]]
            for language in ("ar", "en"):
                page.evaluate("value => localStorage.setItem('socify-interface-language', value)", language)
                for theme in ("dark", "light"):
                    page.evaluate("value => localStorage.setItem('socify-interface-theme', value)", theme)
                    for route in routes:
                        page.goto(root + route)
                        loaded()
                        assert page.locator("html").get_attribute("lang") == language
                        assert page.locator("html").get_attribute("data-theme") == theme
                        assert_accessible(page)
                        assert "PRIVATE-UNRELATED-BACKUP" not in page.locator("#workspace").inner_text()
                        page.set_viewport_size({"width": 390, "height": 844})
                        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (language, theme, route)
                        assert_accessible(page)
                        if route.startswith("/sandbox"):
                            page.screenshot(path=str(output / f"sandbox-{language}-{theme}-mobile.png"), full_page=False)
                        page.set_viewport_size({"width": 1440, "height": 1000})
            page.evaluate("localStorage.setItem('socify-interface-language','ar');localStorage.setItem('socify-interface-theme','dark')")
            page.goto(root + f"/log-management?case_id={primary}")
            loaded()
            search = page.get_by_role("form", name="بحث سجلات القضية", exact=True)
            search.locator("input[name=q]").fill("198.51.100.42")
            search.get_by_role("button", name="بحث السجلات", exact=True).click()
            page.wait_for_url("**/log-management?**q=198.51.100.42**")
            loaded()
            expect(page.get_by_role("heading", name="مستكشف سجلات القضية", exact=True)).to_be_visible()
            page.get_by_role("form", name="بحث سجلات القضية", exact=True).locator("input[name=q]").fill("https://invoice-update.test/review")
            page.get_by_role("form", name="بحث سجلات القضية", exact=True).get_by_role("button", name="بحث السجلات", exact=True).click()
            page.wait_for_url(lambda value: parse_qs(urlparse(value).query).get("q") == ["https://invoice-update.test/review"])
            loaded()
            assert "Invoice" in page.locator("#workspace").inner_text()
            page.locator("[data-investigation-context] select").select_option(str(related))
            page.wait_for_url(f"**/cases/{related}")
            loaded()
            page.goto(root + f"/cases/{pending}")
            loaded()
            expect(page.locator("textarea[name=review_reason]")).to_be_visible()
            page.locator("textarea[name=review_reason]").fill("مراجعة المدير اكتملت؛ اعتماد طلب التجربة")
            page.get_by_role("button", name="حفظ قرار المدير", exact=True).click()
            page.get_by_role("button", name="بدء التحقيق في هذه القضية", exact=True).wait_for()
            page.locator("[data-account-switch]").click()
            page.get_by_role("dialog").get_by_role("button", name="عمر · محلل التجربة · محلل L1", exact=True).click()
            page.wait_for_url("**/cases")
            loaded()
            expect(page.locator(".case-selection-card")).to_have_count(3)
            assert page.locator("[data-investigation-context] select").count() == 0
            assert page.evaluate("async () => (await api('/api/investigation-selection')).case_ids.length") == 0
            page.goto(root + f"/cases/{manifest['unrelated_private_case']}")
            assert page.locator("body").inner_text().find("CASE_NOT_FOUND") >= 0
            page.goto(root + "/cases")
            loaded()
            page.locator("[data-account-switch]").click()
            page.get_by_role("dialog").get_by_role("button", name="سلمان · مراجع التجربة · مراجع", exact=True).click()
            page.wait_for_url("**/cases")
            loaded()
            page.locator(f'.case-selection-card input[value="{primary}"]').check()
            page.get_by_role("button", name="بدء التحقيق بالنطاق المحدد", exact=True).click()
            page.wait_for_url(f"**/cases/{primary}")
            loaded()
            page.goto(root + f"/sandbox?case_id={primary}")
            loaded()
            assert page.locator("input[type=file]").count() == 0
            assert page.get_by_role("button", name="إنشاء قضية", exact=True).count() == 0
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
