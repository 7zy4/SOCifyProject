"""Publish a reviewed detection rule and recover without stale confirmation."""

import json
import time

import pytest
from conftest import DEMO_LOGIN_VALUE
from playwright.sync_api import expect

from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_followup_handoff_journeys import evidence_images
from tests.e2e.test_review_workflow import ARTIFACTS, review_session

TITLE = "Gateway identity detection"
REASON = "Reviewed gateway identity evidence and expected non-matches"
SUCCESS = "اجتازت الأمثلة الإيجابية والسلبية. التحقق لا يثبت تغطية جميع التهديدات."


def area(j):
    return j.page.locator("section.panel").filter(has=j.page.get_by_label(j.text("ملف Sigma"), exact=True))


def attach(j, phrase="Suspicious gateway", *, empty_positive=False, invalid_json=False):
    source = f"title: {TITLE}\nlogsource:\n  category: socify_normalized\ndetection:\n  selected:\n    title|contains: {phrase}\n  condition: selected\nlevel: high\n"
    scope = area(j)
    scope.locator("input[type=file]").nth(0).set_input_files({"name": "gateway.yml", "mimeType": "text/yaml", "buffer": source.encode()})
    fixtures = {"positive": [] if empty_positive else [{"title": phrase + " observed"}], "negative": [{"title": "Routine maintenance"}]}
    scope.locator("input[type=file]").nth(1).set_input_files(
        {"name": "examples.json", "mimeType": "application/json", "buffer": b"{broken" if invalid_json else json.dumps(fixtures).encode()}
    )
    scope.locator("input[name=reason]").fill(REASON)


def preview(j):
    return area(j).locator("[aria-live=polite]").first


def check(j):
    j.click("button", "تحقق من الترجمة والاختبارات دون نشر", area(j))


def rules(j):
    return j.page.evaluate("() => api('/api/autopsy/sigma/rules')")["items"]


def change_author_role(manager, role):
    manager.nav("الفريق")
    row = manager.page.locator("tr").filter(has=manager.page.get_by_role("cell", name="analyst@socify.local", exact=True))
    manager.click("button", "إدارة العضو", row)
    dialog = manager.page.get_by_role("dialog")
    form = dialog.locator("form").filter(has=manager.page.locator("input[name=role]"))
    form.locator("input[name=role]").fill(manager.page.evaluate("value => autopsyLabel(value)", role))
    manager.click("button", "حفظ", form)
    expect(dialog).not_to_be_visible()


def capture(j, result):
    assert_accessible(j.page)
    for width in (390, 1440):
        j.page.set_viewport_size({"width": width, "height": 1000})
        assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        assert preview(j).locator("table").evaluate("element => element.scrollWidth <= element.clientWidth + 1")
        preview(j).screenshot(path=str(ARTIFACTS / f"{result['scenario']}-{result['language']}-preview-{width}.png"))
    preview(j).screenshot(path=str(ARTIFACTS / f"{result['scenario']}-{result['language']}-preview.png"))


def wait_held(j, held):
    deadline = time.monotonic() + 10
    while not held and time.monotonic() < deadline:
        j.page.wait_for_timeout(50)
    assert held, "The actual response was not captured"


def publish(j):
    with j.page.expect_response(lambda r: r.url.endswith("/sigma/publish") and r.request.method == "POST") as response:
        j.click("button", "حفظ", area(j))
    return response.value


def target(j):
    choice = area(j).locator("input[name=rule_id]")
    choice.fill(TITLE)
    choice.press("ArrowDown")
    area(j).get_by_role("option").filter(has_text=TITLE).click()


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "rule-readable-preview",
        "rule-source-preview-reset",
        "rule-fixtures-preview-reset",
        "rule-late-preview-reset",
        "rule-empty-positive-recovery",
        "rule-json-recovery",
        "rule-update-existing",
        "rule-unknown-target-recovery",
        "rule-concurrent-update-recovery",
        "rule-late-current-rule-recovery",
        "rule-publication-network-recovery",
        "rule-author-permission-recovery",
        "rule-updated-detection",
    ],
)
def test_author_reaches_a_current_reviewed_rule(app, language, scenario):
    with review_session(app, language, scenario) as (analyst, manager, result):
        manager.login("manager@socify.local")
        manager.case_url = analyst.case_url
        manager.nav("مكتبة التحليل المحلي")
        j = manager
        if scenario in {"rule-concurrent-update-recovery", "rule-late-current-rule-recovery", "rule-author-permission-recovery"}:
            change_author_role(manager, "soc_manager")
            analyst.login("analyst@socify.local")
            manager.nav("مكتبة التحليل المحلي")
        if scenario == "rule-author-permission-recovery":
            analyst.page.reload()
            analyst.settle()
            analyst.nav("مكتبة التحليل المحلي")
            j = analyst
        before = rules(j)
        attach(j, empty_positive=scenario == "rule-empty-positive-recovery", invalid_json=scenario == "rule-json-recovery")
        if scenario == "rule-readable-preview":
            check(j)
            expect(preview(j).get_by_role("table")).to_be_visible()
            expect(preview(j)).to_contain_text(TITLE)
            expect(preview(j)).to_contain_text("Suspicious gateway")
            expect(preview(j).locator("pre")).to_have_count(0)
            assert rules(j) == before
        elif scenario in {"rule-source-preview-reset", "rule-fixtures-preview-reset"}:
            check(j)
            expect(preview(j)).to_contain_text(j.text(SUCCESS))
            if scenario == "rule-source-preview-reset":
                attach(j, "Revised gateway")
            else:
                area(j).locator("input[type=file]").nth(1).set_input_files(
                    {
                        "name": "changed.json",
                        "mimeType": "application/json",
                        "buffer": json.dumps({"positive": [{"title": "Suspicious gateway second"}], "negative": [{"title": "Ordinary access"}]}).encode(),
                    }
                )
            expect(preview(j)).not_to_contain_text(j.text(SUCCESS))
            check(j)
            expect(preview(j)).to_contain_text(j.text(SUCCESS))
        elif scenario == "rule-late-preview-reset":
            held = []

            def hold(route):
                held.append((route, route.fetch()))

            j.page.route("**/api/autopsy/sigma/compile", hold, times=1)
            area(j).get_by_role("button", name=j.text("تحقق من الترجمة والاختبارات دون نشر"), exact=True).click()
            wait_held(j, held)
            attach(j, "Revised gateway")
            held[0][0].fulfill(response=held[0][1])
            j.settle()
            expect(preview(j)).not_to_contain_text(j.text(SUCCESS))
            check(j)
            expect(preview(j)).to_contain_text("Revised gateway")
        elif scenario in {"rule-empty-positive-recovery", "rule-json-recovery"}:
            check(j)
            expect(area(j).get_by_role("alert").filter(visible=True)).to_be_visible()
            assert rules(j) == before
            expect(area(j).locator("input[name=reason]")).to_have_value(REASON)
            attach(j)
            check(j)
            expect(area(j).get_by_role("alert").filter(visible=True)).to_have_count(0)
        elif scenario in {
            "rule-update-existing",
            "rule-unknown-target-recovery",
            "rule-concurrent-update-recovery",
            "rule-late-current-rule-recovery",
            "rule-updated-detection",
        }:
            first = publish(j)
            assert first.status == 201, first.text()
            identifier = first.json()["id"]
            if scenario == "rule-updated-detection":
                from tests.e2e.test_detection_workflow_journeys import upload

                upload(j, 1, "original.json", prefix="Suspicious gateway")
                original_alerts = j.page.evaluate("id=>api(`/api/cases/${id}/alerts`)", j.case_id)["items"]
                assert len(original_alerts) == 1
                j.nav("مكتبة التحليل المحلي")
            if scenario in {"rule-concurrent-update-recovery", "rule-late-current-rule-recovery"}:
                analyst.page.reload()
                analyst.settle()
                analyst.nav("مكتبة التحليل المحلي")
                attach(analyst, "Final gateway")
                target(analyst)
            attach(j, "Revised gateway")
            if scenario == "rule-unknown-target-recovery":
                area(j).locator("input[name=rule_id]").fill("Unlisted gateway rule")
                j.click("button", "حفظ", area(j))
                expect(area(j).get_by_role("alert").filter(visible=True)).to_be_visible()
                assert len(rules(j)) == len(before) + 1
                assert next(item for item in rules(j) if item["id"] == identifier)["version"] == 1
            target(j)
            check(j)
            updated = publish(j)
            assert updated.status == 201 and updated.json()["id"] == identifier and updated.json()["version"] == 2
            assert len(rules(j)) == len(before) + 1
            if scenario in {"rule-concurrent-update-recovery", "rule-late-current-rule-recovery"}:
                conflict = publish(analyst)
                assert conflict.status == 409
                expect(area(analyst).locator("input[name=reason]")).to_have_value(REASON)
                expect(area(analyst).locator("input[type=file]").first).not_to_be_empty()
                if scenario == "rule-late-current-rule-recovery":
                    held = []

                    def hold_current(route):
                        held.append((route, route.fetch()))

                    analyst.page.route("**/api/autopsy/sigma/compile", hold_current, times=1)
                    area(analyst).get_by_role("button", name=analyst.text("تحميل القاعدة الحالية"), exact=True).click()
                    wait_held(analyst, held)
                    attach(analyst, "Final gateway")
                    held[0][0].fulfill(response=held[0][1])
                    analyst.settle()
                    expect(area(analyst).get_by_role("caption", name=analyst.text("القاعدة المنشورة حاليًا"), exact=True)).to_have_count(0)
                    assert publish(analyst).status == 409
                analyst.click("button", "تحميل القاعدة الحالية", area(analyst))
                expect(area(analyst)).to_contain_text("Revised gateway")
                check(analyst)
                final = publish(analyst)
                assert final.status == 201 and final.json()["version"] == 3 and final.json()["id"] == identifier
                j = analyst
            if scenario == "rule-updated-detection":
                upload(j, 1, "old-pattern.json", prefix="Suspicious gateway")
                assert len(j.page.evaluate("id=>api(`/api/cases/${id}/alerts`)", j.case_id)["items"]) == 1
                upload(j, 1, "new-pattern.json", prefix="Revised gateway")
                alerts = j.page.evaluate("id=>api(`/api/cases/${id}/alerts`)", j.case_id)["items"]
                assert len(alerts) == 2 and original_alerts[0] in alerts
                result["outcomes"] = ["updated rule only matched new intended input", "previous alert retained"]
                j.nav("مكتبة التحليل المحلي")
            attach(j, "Final gateway" if scenario in {"rule-concurrent-update-recovery", "rule-late-current-rule-recovery"} else "Revised gateway")
            target(j)
            check(j)
        elif scenario == "rule-publication-network-recovery":
            check(j)
            j.page.route("**/api/autopsy/sigma/publish", lambda route: route.abort(), times=1)
            j.click("button", "حفظ", area(j))
            expect(area(j).get_by_role("alert").filter(visible=True)).to_be_visible()
            assert rules(j) == before
            expect(area(j).locator("input[name=reason]")).to_have_value(REASON)
        elif scenario == "rule-author-permission-recovery":
            check(j)
            change_author_role(manager, "analyst")
            denied = publish(j)
            assert denied.status == 401
            assert rules(manager) == before
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
            expect(recovery).not_to_be_visible()
            login.close()
            expect(area(j).locator("input[name=reason]")).to_have_value(REASON)
            check(j)
        if scenario not in {
            "rule-update-existing",
            "rule-unknown-target-recovery",
            "rule-concurrent-update-recovery",
            "rule-late-current-rule-recovery",
            "rule-updated-detection",
        }:
            check(j)
            expect(preview(j)).to_contain_text(j.text(SUCCESS))
            capture(j, result)
            response = publish(j)
            assert response.status == 201, response.text()
            assert len(rules(j)) == len(before) + 1
        else:
            capture(j, result)
        evidence_images(j, result)
        result.setdefault("outcomes", []).extend([scenario, "explicit publication", "stored rule identity independently verified"])
