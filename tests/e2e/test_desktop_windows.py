import threading
from pathlib import Path

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

from tests.e2e.test_browser import assert_accessible, launch_browser


@pytest.mark.e2e
def test_reference_desktop_windows_live_data_and_controls(app):
    app.config.update(LEGACY_TRAINING_TESTS=False, ALLOW_REGISTRATION=False, WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    output = Path("work/reference/previews")
    output.mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={"width": 1600, "height": 1200}, color_scheme="dark")
            page.add_init_script("if (!localStorage.getItem('socify-interface-language')) localStorage.setItem('socify-interface-language','en')")
            page.add_init_script(path=str(Path("node_modules/axe-core/axe.min.js").resolve()))
            errors, old_brand_requests = [], []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on(
                "request", lambda request: old_brand_requests.append(request.url) if "socify-logo" in request.url or "socify-symbol" in request.url else None
            )
            root = f"http://127.0.0.1:{server.server_port}"
            page.goto(root + "/login")
            page.get_by_label("Email", exact=True).fill("manager@socify.local")
            page.get_by_label("Password", exact=True).fill(DEMO_LOGIN_VALUE)
            page.get_by_role("button", name="Sign in", exact=True).click()
            page.wait_for_url("**/cases")
            page.wait_for_function("() => document.querySelector('#workspace').getAttribute('aria-busy') === 'false'")
            case = page.evaluate("""async () => {
                await api('/api/cases',{method:'POST',body:{title:'Mail delivery investigation',reason:'forensic_review',objective:'Review the authorized message delivery evidence.'}});
                await api('/api/cases',{method:'POST',body:{title:'Internal endpoint review',reason:'alert_review',objective:'Document the reviewed endpoint activity.'}});
                const c = await api('/api/cases',{method:'POST',body:{
                    title:'Identity gateway access review',reason:'alert_review',severity:'high',
                    objective:'Establish the scope of the sign-in activity using retained gateway logs and documented response decisions.'
                }});
                await api(`/api/cases/${c.id}/records/asset`,{method:'POST',body:{name:'Identity gateway',type:'identity_provider',role:'defender',address:'192.0.2.20'}});
                await api(`/api/cases/${c.id}/imports`,{method:'POST',body:{filename:'identity-signins.json',content:JSON.stringify([{title:'Gateway sign-in observation',source:'identity-gateway',source_ip:'192.0.2.20',severity:'high',event_time:'2026-10-27T08:41:00Z'}])}});
                await api(`/api/cases/${c.id}/imports`,{method:'POST',body:{filename:'gateway-observations.json',content:JSON.stringify([{title:'Session review observation',source:'identity-gateway',severity:'medium',event_time:'2026-10-27T08:45:00Z'}])}});
                return c;
            }""")
            page.reload()
            page.wait_for_function("() => document.body.dataset.desktopReady === 'true'")
            expect(page.locator(".desktop-window")).to_have_count(5)
            expect(page.locator(".case-paper")).to_contain_text(case["reference"])
            expect(page.locator(".case-paper")).to_contain_text("Identity gateway access review")
            expect(page.locator(".terminal-output").last).not_to_be_empty()
            expected = {
                "workspace": (604, 316, 950, 711),
                "dossier": (292, 105, 507, 687),
                "activity": (108, 245, 540, 325),
                "directory": (69, 668, 553, 383),
                "properties": (949, 187, 489, 755),
            }
            for name, geometry in expected.items():
                bounds = page.locator(f"[data-window='{name}']").bounding_box()
                assert all(abs(bounds[key] - value) < 4 for key, value in zip(("x", "y", "width", "height"), geometry, strict=True)), (name, bounds)
            page.screenshot(path=str(output / "desktop-en-dark-1600.png"))
            assert_accessible(page)
            props = page.locator("[data-window=properties]")
            props.get_by_role("button", name="Minimize window", exact=True).click()
            expect(props).to_be_hidden()
            page.locator(".taskbar-windows").get_by_role("button", name="Case properties", exact=True).click()
            expect(props).to_be_visible()
            page.locator(".taskbar-windows").get_by_role("button", name="Investigation workspace", exact=True).click()
            workspace = page.locator("[data-window=workspace]")
            workspace.get_by_role("button", name="Maximize window", exact=True).click()
            assert workspace.bounding_box()["width"] >= 1580
            workspace.get_by_role("button", name="Table view", exact=True).click()
            expect(workspace.locator(".case-table")).to_be_visible()
            workspace.get_by_role("button", name="Folder view", exact=True).click()
            expect(workspace.locator(".case-folder-grid")).to_be_visible()
            workspace.get_by_role("button", name="Restore window", exact=True).click()
            assert abs(workspace.bounding_box()["x"] - 604) < 4
            page.locator(".taskbar-windows").get_by_role("button", name="Investigation file", exact=True).click()
            dossier = page.locator("[data-window=dossier]")
            before = dossier.bounding_box()
            bar = dossier.locator(".window-titlebar").bounding_box()
            page.mouse.move(bar["x"] + 100, bar["y"] + 15)
            page.mouse.down()
            page.mouse.move(bar["x"] + 145, bar["y"] + 45, steps=5)
            page.mouse.up()
            after = dossier.bounding_box()
            assert abs(after["x"] - before["x"] - 45) < 3
            assert abs(after["y"] - before["y"] - 30) < 3
            dossier.locator(".window-titlebar").focus()
            page.keyboard.press("ArrowRight")
            assert abs(dossier.bounding_box()["x"] - after["x"] - 16) < 3
            before_resize = dossier.bounding_box()
            resize = dossier.get_by_role("button", name="Resize window", exact=True).bounding_box()
            page.mouse.move(resize["x"] + 8, resize["y"] + 8)
            page.mouse.down()
            page.mouse.move(resize["x"] + 38, resize["y"] + 28, steps=4)
            page.mouse.up()
            assert dossier.bounding_box()["width"] > before_resize["width"] + 25
            dossier.get_by_role("button", name="Close window", exact=True).click()
            expect(dossier).to_be_hidden()
            page.locator(".taskbar-windows").get_by_role("button", name="Investigation file", exact=True).click()
            expect(dossier).to_contain_text(case["reference"])
            page.get_by_role("button", name="Reset desktop", exact=True).click()
            assert abs(dossier.bounding_box()["x"] - 292) < 4
            page.get_by_role("button", name="Focus workspace", exact=True).click()
            expect(page.locator(".desktop-window:visible")).to_have_count(1)
            page.keyboard.press("Escape")
            expect(page.locator(".desktop-window:visible")).to_have_count(5)
            page.locator("[data-theme-select]").select_option("light")
            assert_accessible(page)
            page.screenshot(path=str(output / "desktop-en-light-1600.png"))
            page.evaluate("localStorage.setItem('socify-interface-language','ar')")
            page.reload()
            page.wait_for_function("() => document.body.dataset.desktopReady === 'true'")
            assert page.locator("html").get_attribute("dir") == "rtl"
            page.locator("[data-theme-select]").select_option("dark")
            assert_accessible(page)
            page.screenshot(path=str(output / "desktop-ar-dark-1600.png"))
            page.set_viewport_size({"width": 390, "height": 844})
            expect(page.locator(".desktop-window:visible")).to_have_count(1)
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.screenshot(path=str(output / "desktop-ar-dark-mobile.png"))
            assert not errors
            assert not old_brand_requests
            assert page.locator("img").count() == 0
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
