"""An analyst triages alerts that arrived from a SIEM: dismiss one with a reason and turn another into a case."""

import hashlib
import hmac
import json
import threading
import time

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

from tests.e2e.browser_helpers import assert_accessible, launch_browser


def _receive(app, login_as, client):
    login_as("soc_manager")
    created = client.post("/api/intake/integrations", json={"kind": "generic", "name": "Lab SIEM", "auth_mode": "hmac"}).json
    alerts = {
        "alerts": [
            {
                "id": "lab-1",
                "title": "Brute force against VPN",
                "severity": "high",
                "time": "2026-11-20T07:00:00Z",
                "entities": {"ips": ["198.51.100.8"], "hosts": ["vpn-01"]},
                "mitre": ["T1110"],
            },
            {"id": "lab-2", "title": "Scheduled scanner noise", "severity": "low", "time": "2026-11-20T07:05:00Z"},
        ]
    }
    body = json.dumps(alerts).encode()
    stamp = str(int(time.time()))
    signature = hmac.new(created["hmac_secret"].encode(), stamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    response = client.post(created["item"]["endpoint"], data=body, headers={"X-SOCify-Timestamp": stamp, "X-SOCify-Signature": f"sha256={signature}"})
    assert response.status_code == 202, response.json


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_analyst_dismisses_noise_and_opens_a_case_from_an_incoming_alert(app, client, login_as, language):
    _receive(app, login_as, client)
    app.config.update(WTF_CSRF_ENABLED=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def text(ar, en):
        return ar if language == "ar" else en

    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(locale="ar-SA" if language == "ar" else "en-US", viewport={"width": 1440, "height": 1000})
            page.set_default_timeout(15000)
            page.add_init_script(path="node_modules/axe-core/axe.min.js")
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            base = f"http://127.0.0.1:{server.server_port}"
            page.goto(base + "/login")
            page.locator("#email").fill("analyst@socify.local")
            page.locator("#password").fill(DEMO_LOGIN_VALUE)
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/cases")
            page.goto(base + "/monitoring")
            page.locator(".channel-tabs").get_by_role("link", name=text("الوارد", "Intake"), exact=True).click()
            page.wait_for_url("**/monitoring?channel=intake")
            rows = page.locator(".intake-view tbody tr")
            expect(rows).to_have_count(2)
            for width in (390, 1440):
                page.set_viewport_size({"width": width, "height": 1000})
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                assert_accessible(page)
            rows.filter(has_text="Scheduled scanner noise").get_by_role("button", name=text("عرض التنبيه", "View alert"), exact=True).click()
            dialog = page.get_by_role("dialog")
            dialog.get_by_label(text("سبب الاستبعاد", "Reason for dismissal"), exact=True).fill("Approved weekly vulnerability scan")
            dialog.get_by_role("button", name=text("استبعاد التنبيه", "Dismiss alert"), exact=True).click()
            expect(page.locator(".intake-view tbody tr")).to_have_count(1)
            page.locator(".intake-view tbody tr").get_by_role("button", name=text("عرض التنبيه", "View alert"), exact=True).click()
            dialog = page.get_by_role("dialog")
            expect(dialog).to_contain_text("198.51.100.8")
            expect(dialog).to_contain_text("T1110")
            assert_accessible(page)
            dialog.get_by_role("button", name=text("إنشاء قضية من التنبيه", "Create a case from the alert"), exact=True).click()
            page.wait_for_url("**/cases/*")
            expect(page.get_by_role("heading", name="Brute force against VPN", exact=True)).to_be_visible()
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
