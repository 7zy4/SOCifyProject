"""An analyst triages alerts that arrived from a SIEM in place: search, take one, dismiss noise with a reason and turn another into a case."""

import hashlib
import hmac
import json
import re
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
            tab = page.locator(".channel-tabs").get_by_role("link", name=text("الوارد 2", "Intake 2"), exact=True)
            tab.click()
            page.wait_for_url("**/monitoring?channel=intake")
            surface = page.locator(".intake-view .monitoring-surface")
            rows = surface.locator("tbody tr[data-intake-row]")
            expect(rows).to_have_count(2)
            expect(page.locator(".intake-view h3")).to_have_count(0)
            surface.get_by_label(text("بحث", "Search"), exact=True).fill("scanner")
            surface.get_by_role("button", name=text("تطبيق", "Apply"), exact=True).click()
            expect(page).to_have_url(re.compile(r"[?&]q=scanner(&|$)"))
            expect(rows).to_have_count(1)
            for width in (390, 1440):
                page.set_viewport_size({"width": width, "height": 1000})
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                assert_accessible(page)
            noise = rows.filter(has_text="Scheduled scanner noise")
            noise.get_by_role("button", name="Scheduled scanner noise", exact=True).click()
            detail = surface.locator(".intake-detail")
            detail.get_by_role("button", name=text("أتولى الفرز", "Take for triage"), exact=True).click()
            expect(rows.first).to_contain_text(text("قيد الفرز", "Being triaged"))
            rows.first.get_by_role("button", name="Scheduled scanner noise", exact=True).click()
            expect(detail).to_contain_text(text("يتولاه", "Taken by"))
            detail.get_by_role("button", name=text("استبعاد", "Dismiss"), exact=True).click()
            detail.get_by_label(text("سبب الاستبعاد", "Reason for dismissal"), exact=True).fill("Approved weekly vulnerability scan")
            detail.get_by_role("button", name=text("استبعاد التنبيه", "Dismiss alert"), exact=True).click()
            expect(surface.locator(".empty")).to_be_visible()
            page.goto(base + "/monitoring?channel=intake")
            expect(rows).to_have_count(1)
            rows.first.get_by_role("button", name=text("تفاصيل التنبيه Brute force against VPN", "Alert details Brute force against VPN"), exact=True).click()
            expect(detail).to_contain_text("198.51.100.8")
            expect(detail).to_contain_text("T1110")
            assert_accessible(page)
            detail.get_by_role("button", name=text("إنشاء قضية", "Create case"), exact=True).click()
            page.wait_for_url("**/cases/*")
            expect(page.get_by_role("heading", name="Brute force against VPN", exact=True)).to_be_visible()
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.e2e
def test_the_intake_channel_opens_before_any_investigation_is_selected(app, client, login_as):
    # The production default asks for a selected investigation on case pages; incoming alerts come before any case.
    _receive(app, login_as, client)
    app.config.update(WTF_CSRF_ENABLED=True, REQUIRE_INVESTIGATION_SELECTION=True)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(locale="en-US", viewport={"width": 1440, "height": 1000})
            page.set_default_timeout(15000)
            base = f"http://127.0.0.1:{server.server_port}"
            page.goto(base + "/login")
            page.locator("#email").fill("analyst@socify.local")
            page.locator("#password").fill(DEMO_LOGIN_VALUE)
            page.locator("button[type=submit]").click()
            page.wait_for_url("**/cases")
            page.goto(base + "/monitoring")
            expect(page.locator(".empty")).to_contain_text("Choose a case")
            page.locator(".channel-tabs").get_by_role("link", name="Intake 2", exact=True).click()
            expect(page.locator(".intake-view tbody tr[data-intake-row]")).to_have_count(2)
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
