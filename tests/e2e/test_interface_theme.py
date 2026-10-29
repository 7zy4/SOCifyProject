"""Exercise theme preferences and operational surfaces using synthetic data."""

import threading
from pathlib import Path

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from tests.e2e.test_browser import assert_accessible, launch_browser


@pytest.mark.e2e
def test_theme_system_persistence_languages_and_operational_surfaces(app):
    app.config.update(LEGACY_TRAINING_TESTS=False, ALLOW_REGISTRATION=False, WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    screenshots = Path("work/interface-review")
    screenshots.mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={"width": 1440, "height": 1000}, color_scheme="dark")
            page.add_init_script(path=str(Path("node_modules/axe-core/axe.min.js").resolve()))
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            base = f"http://127.0.0.1:{server.server_port}"
            page.goto(base + "/")
            assert page.locator("html").get_attribute("data-theme") == "dark"
            assert page.locator("[data-theme-select]").input_value() == "dark"
            page.locator("[data-theme-select]").select_option("system")
            page.emulate_media(color_scheme="light")
            page.wait_for_function("() => document.documentElement.dataset.theme === 'light'")
            page.locator("[data-theme-select]").select_option("dark")
            page.reload()
            assert page.locator("html").get_attribute("data-theme") == "dark"
            page.goto(base + "/login")
            assert page.locator("html").get_attribute("data-theme") == "dark"
            page.get_by_label("البريد الإلكتروني", exact=True).fill("manager@socify.local")
            page.get_by_label("كلمة المرور", exact=True).fill(DEMO_LOGIN_VALUE)
            page.get_by_role("button", name="دخول إلى المنصة", exact=True).click()
            page.wait_for_url("**/cases")
            page.wait_for_function("() => document.querySelector('#workspace').getAttribute('aria-busy') === 'false'")
            case = page.evaluate("""async () => {
                const c = await api('/api/cases', {method:'POST', body:{
                    title:'تحقيق في نشاط تسجيل دخول مشتبه به', reason:'alert_review',
                    objective:'التحقق من نطاق النشاط وربط النتائج بالأدلة الأصلية', severity:'high'
                }});
                await api(`/api/cases/${c.id}/records/asset`, {method:'POST', body:{name:'بوابة الهوية',type:'identity_provider',role:'defender',address:'192.0.2.20'}});
                return c;
            }""")
            page.goto(base + f"/cases/{case['id']}")
            editor = page.locator("section.panel").filter(has=page.get_by_role("heading", name="سبب القضية وهدفها ونتيجتها", exact=True))
            editor.locator("summary").click()
            updated_objective = "التحقق من نطاق النشاط وتوثيق الاستنتاجات من الأدلة الأصلية"
            editor.locator("textarea[name=objective]").fill(updated_objective)
            editor.get_by_role("button", name="حفظ", exact=True).click()
            page.locator(".case-overview").get_by_text(updated_objective, exact=True).wait_for()
            routes = ["/cases", "/my-tasks", "/team", "/playbooks", "/analysis-library", "/profile"]
            routes += [
                "/monitoring",
                *[
                    f"/{section}?case_id={case['id']}"
                    for section in ("log-management", "endpoint-security", "threat-intel", "email-security", "sandbox", "reports")
                ],
            ]
            routes += [f"/cases/{case['id']}?tab={tab}" for tab in ("summary", "logs", "analysis", "investigation", "response", "activity", "reports")]
            for language in ("ar", "en"):
                page.evaluate("language => localStorage.setItem('socify-interface-language', language)", language)
                for theme in ("light", "dark"):
                    page.locator("[data-theme-select]").select_option(theme)
                    for route in routes:
                        page.set_viewport_size({"width": 1440, "height": 1000})
                        page.goto(base + route)
                        if page.locator("#workspace").count():
                            page.wait_for_function("() => document.querySelector('#workspace').getAttribute('aria-busy') === 'false'")
                        page.evaluate("document.fonts.ready")
                        assert page.locator("html").get_attribute("data-theme") == theme
                        assert page.locator("html").get_attribute("lang") == language
                        assert page.locator("html").get_attribute("dir") == ("rtl" if language == "ar" else "ltr")
                        assert page.evaluate("document.fonts.check('15px \"IBM Plex Sans Arabic\"', 'تحقيق')")
                        assert page.evaluate("document.fonts.check('15px \"IBM Plex Sans\"', 'Investigation')")
                        assert_accessible(page)
                        name = route.strip("/").replace("/", "-").replace("?tab=", "-") or "landing"
                        if route in ("/", "/login", "/cases") or "tab=summary" in route:
                            page.screenshot(path=str(screenshots / f"{name}-{language}-{theme}-desktop.png"), full_page=True)
                        for width in (390, 768, 1280):
                            page.set_viewport_size({"width": width, "height": 900})
                            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (route, language, theme, width)
                        page.set_viewport_size({"width": 390, "height": 844})
                        if route in ("/", "/login", "/cases") or "tab=summary" in route:
                            page.screenshot(path=str(screenshots / f"{name}-{language}-{theme}-mobile.png"), full_page=True)
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.e2e
def test_theme_control_works_when_browser_storage_is_unavailable(app):
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(color_scheme="dark")
            page.add_init_script("Storage.prototype.getItem = Storage.prototype.setItem = () => { throw new Error('Storage unavailable'); };")
            page.goto(f"http://127.0.0.1:{server.server_port}/login")
            assert page.locator("html").get_attribute("data-theme") == "dark"
            page.locator("[data-theme-select]").select_option("light")
            assert page.locator("html").get_attribute("data-theme") == "light"
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.e2e
def test_public_pages_theme_typography_and_responsive_layout(app):
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    screenshots = Path("work/interface-review")
    screenshots.mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            page.add_init_script(path=str(Path("node_modules/axe-core/axe.min.js").resolve()))
            base = f"http://127.0.0.1:{server.server_port}"
            page.goto(base + "/login")
            for language in ("ar", "en"):
                page.evaluate("language => localStorage.setItem('socify-interface-language', language)", language)
                for theme in ("light", "dark"):
                    page.locator("[data-theme-select]").select_option(theme)
                    for route, name in (("/", "landing"), ("/login", "login"), ("/register", "register")):
                        # The operational root intentionally redirects to sign-in/cases.
                        # Render the retained landing template in its supported legacy mode.
                        app.config["LEGACY_TRAINING_TESTS"] = route == "/"
                        page.set_viewport_size({"width": 1440, "height": 1000})
                        page.goto(base + route)
                        page.evaluate("document.fonts.ready")
                        assert page.locator("html").get_attribute("data-theme") == theme
                        assert_accessible(page)
                        page.screenshot(path=str(screenshots / f"{name}-{language}-{theme}-desktop.png"), full_page=True)
                        page.set_viewport_size({"width": 390, "height": 844})
                        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (route, language, theme)
                        page.screenshot(path=str(screenshots / f"{name}-{language}-{theme}-mobile.png"), full_page=True)
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.e2e
def test_operational_governance_routes_render_their_authorized_content(app):
    app.config.update(LEGACY_TRAINING_TESTS=False, WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page()
            base = f"http://127.0.0.1:{server.server_port}"
            page.goto(base + "/login")
            page.get_by_label("البريد الإلكتروني", exact=True).fill("admin@socify.local")
            page.get_by_label("كلمة المرور", exact=True).fill(DEMO_LOGIN_VALUE)
            page.get_by_role("button", name="دخول إلى المنصة", exact=True).click()
            page.wait_for_url("**/cases")
            for route, heading in (("audit", "سجل التدقيق"), ("admin", "الحوكمة والصلاحيات")):
                page.goto(base + "/" + route)
                page.locator('#workspace[aria-busy="false"]').wait_for()
                assert page.locator("#workspace .workspace-head h2").inner_text() == heading
                assert page.locator("#workspace table").count() >= 1
                assert page.locator(f'#primary-nav [data-section="{route}"]').is_visible()
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
