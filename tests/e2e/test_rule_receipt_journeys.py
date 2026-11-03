"""Recover a publication whose committed response never reached the author."""

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import expect

from tests.e2e.test_followup_handoff_journeys import evidence_images
from tests.e2e.test_review_workflow import ARTIFACTS, review_session
from tests.e2e.test_rule_authoring_journeys import area, attach, change_author_role, publish, rules, target


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "rule-created-receipt-lost",
        "rule-updated-receipt-lost",
        "rule-created-receipt-reload",
        "rule-updated-receipt-reload",
        "rule-receipt-malformed",
        "rule-receipt-error-status",
        "rule-receipt-repeated-loss",
        "rule-receipt-library-recovery",
        "rule-receipt-changed-intent",
        "rule-receipt-acknowledged-new-intent",
        "rule-receipt-storage-disabled",
        "rule-receipt-concurrent-update",
        "rule-receipt-permission-recovery",
        "rule-receipt-reload-conflict",
    ],
)
def test_author_retries_a_committed_publication(app, language, scenario):
    with review_session(app, language, scenario) as (analyst, manager, result):
        manager.login("manager@socify.local")
        if scenario in {"rule-receipt-concurrent-update", "rule-receipt-permission-recovery", "rule-receipt-reload-conflict"}:
            change_author_role(manager, "soc_manager")
            analyst.login("analyst@socify.local")
        j = analyst if scenario == "rule-receipt-permission-recovery" else manager
        j.nav("مكتبة التحليل المحلي")
        if scenario == "rule-receipt-storage-disabled":
            j.page.evaluate("Object.defineProperty(window, 'sessionStorage', {get() {throw new DOMException('Blocked', 'SecurityError')}})")
        before = rules(j)
        attach(j)
        updating = scenario in {"rule-updated-receipt-lost", "rule-updated-receipt-reload", "rule-receipt-concurrent-update", "rule-receipt-reload-conflict"}
        if updating:
            assert publish(j).status == 201
            attach(j, "Revised gateway")
            target(j)
        committed = []

        def lose_receipt(route):
            if scenario == "rule-receipt-reload-conflict":
                route.abort()
                return
            response = route.fetch()
            assert response.status == 201, response.text()
            committed.append(response.json())
            if scenario == "rule-receipt-malformed":
                route.fulfill(status=201, content_type="application/json", body="{interrupted")
            elif scenario == "rule-receipt-error-status":
                route.fulfill(status=502, content_type="application/json", body='{"error":{"code":"GATEWAY_TIMEOUT","message":"Request interrupted"}}')
            elif scenario == "rule-receipt-library-recovery":
                j.page.route("**/api/autopsy/intelligence", lambda request: request.abort(), times=1)
                route.fulfill(response=response)
            else:
                route.abort()

        j.page.route("**/api/autopsy/sigma/publish", lose_receipt, times=2 if scenario == "rule-receipt-repeated-loss" else 1)
        j.click("button", "حفظ", area(j))
        expect(area(j).get_by_role("alert").filter(visible=True)).to_be_visible()
        if scenario == "rule-receipt-library-recovery":
            expect(area(j).get_by_role("alert").filter(visible=True)).to_have_text(j.text("حُفظت القاعدة. تعذر تحديث القائمة؛ أعد المحاولة."))
            for width in (390, 1440):
                j.page.set_viewport_size({"width": width, "height": 1000})
                assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                area(j).screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-recovery-{width}.png"))
        assert len(committed) == (0 if scenario == "rule-receipt-reload-conflict" else 1)
        if scenario in {"rule-receipt-concurrent-update", "rule-receipt-reload-conflict"}:
            analyst.nav("مكتبة التحليل المحلي")
            attach(analyst, "Colleague gateway")
            target(analyst)
            colleague = publish(analyst)
            assert colleague.status == 201
        if scenario == "rule-receipt-repeated-loss":
            j.click("button", "حفظ", area(j))
            expect(area(j).get_by_role("alert").filter(visible=True)).to_be_visible()
            assert len(committed) == 2 and committed[0] == committed[1]
        if scenario == "rule-receipt-permission-recovery":
            change_author_role(manager, "analyst")
            assert publish(j).status == 401
            change_author_role(manager, "soc_manager")
            recovery = j.page.get_by_role("dialog", name=j.text("تجديد الجلسة"), exact=True)
            expect(recovery).to_be_visible()
            with j.page.context.expect_page() as opened:
                recovery.get_by_role("link", name=j.text("تسجيل الدخول"), exact=True).click()
            login = opened.value
            login.locator("input[name=email]").fill("analyst@socify.local")
            login.locator("input[name=password]").fill(DEMO_LOGIN_VALUE)
            login.locator("button[type=submit]").click()
            login.wait_for_url("**/cases")
            j.click("button", "متابعة العمل", recovery)
            login.close()
        if "reload" in scenario:
            stored = j.page.evaluate("Object.entries(sessionStorage).filter(([key])=>key.startsWith('socify:sigma:'))")
            assert len(stored) == 1
            assert "source" not in stored[0][1] and "fixtures" not in stored[0][1]
            j.page.once("dialog", lambda dialog: dialog.accept())
            j.page.reload()
            j.settle()
            attach(j, "Revised gateway" if updating else "Suspicious gateway")
            if updating:
                target(j)
        saved = rules(j)
        assert len(saved) == len(before) + 1
        if scenario == "rule-receipt-reload-conflict":
            conflict = publish(j)
            assert conflict.status == 409 and conflict.json()["error"]["code"] == "RULE_VERSION_CONFLICT"
            assert rules(j) == saved
            j.click("button", "تحميل القاعدة الحالية", area(j))
        if scenario == "rule-receipt-changed-intent":
            attach(j, "Distinct gateway")
        retried = publish(j)
        assert retried.status == 201, retried.text()
        if scenario == "rule-receipt-reload-conflict":
            assert retried.json()["id"] == colleague.json()["id"] and retried.json()["version"] == 3
        elif scenario == "rule-receipt-changed-intent":
            assert retried.json()["id"] != committed[0]["id"]
            assert len(rules(j)) == len(saved) + 1
        else:
            assert retried.json()["id"] == committed[0]["id"]
            assert retried.json()["version"] == committed[0]["version"]
            assert rules(j) == saved, "Retry created a second rule or publication"
        if scenario == "rule-receipt-acknowledged-new-intent":
            attach(j)
            intentional = publish(j)
            assert intentional.status == 201 and intentional.json()["id"] != retried.json()["id"]
            assert len(rules(j)) == len(saved) + 1
        expect(area(j).get_by_role("alert").filter(visible=True)).to_have_count(0)
        published = j.page.locator("section.panel").filter(has=j.page.get_by_role("heading", name=j.text("قواعد Sigma المنشورة"), exact=True))
        published.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-published.png"))
        result["outcome"] = {
            "rule-receipt-changed-intent": "Changed content created an intentional distinct publication and retained the preceding committed rule",
            "rule-receipt-acknowledged-new-intent": "An explicitly new publication after acknowledgement received its own rule identity",
            "rule-receipt-reload-conflict": "Reload preserved the pending operation's original base; a colleague's update was protected until explicit review and resubmission",
        }.get(scenario, "The committed publication was recovered once without duplicate rules or a false version conflict")
        evidence_images(j, result)
