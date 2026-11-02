"""Observed case-scope tasks with real intake and interface-only business writes."""

import json
import re

import pytest
from playwright.sync_api import expect

from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_review_workflow import ARTIFACTS, ReviewJourney, review_session

PRIMARY = "Authorized maintenance investigation"
SECOND = "Email gateway correlation"


def approve(j):
    j.page.locator("textarea[name=review_reason]").fill("Investigation approved for the documented evidence and scope.")
    j.click("button", "حفظ قرار المدير")


def open_card(j, title):
    j.click("link", "فتح القضية", j.page.locator(".case-selection-card").filter(has_text=title))


def prepare_pair(j, manager):
    manager.login("manager@socify.local")
    open_card(manager, PRIMARY)
    approve(manager)
    manager.nav("إدارة القضايا")
    manager.click("button", "إنشاء قضية")
    dialog = manager.page.get_by_role("dialog")
    dialog.locator("input[name=title]").fill(SECOND)
    manager.click("button", "حفظ", dialog)
    second = int(re.search(r"/cases/(\d+)", manager.page.url)[1])
    approve(manager)
    manager.nav("إدارة القضايا")
    open_card(manager, PRIMARY)
    manager.click("button", "بدء التحقيق في هذه القضية")
    panel = manager.page.locator("section.panel").filter(has=manager.page.get_by_role("heading", name=manager.text("ربط قضية ذات صلة"), exact=True))
    panel.locator("summary").click()
    form = manager.page.locator("form").filter(has=manager.page.locator("[name=related_case_id]"))
    form.locator("[name=reason]").fill("The same identity activity appears in both retained sources.")
    return second, form


def search(j, query):
    form = j.page.get_by_role("form", name=j.text("بحث القضايا"))
    form.locator("[name=q]").fill(query)
    j.click("button", "بحث", form)


def upload(j, name, title):
    j.nav("إدارة السجلات")
    j.page.locator("input[name=file]").set_input_files(
        {
            "name": name,
            "mimeType": "application/json",
            "buffer": json.dumps([{"title": title, "hostname": name.upper(), "timestamp": "2026-11-02T10:00:00Z"}]).encode(),
        }
    )
    j.click("button", "استيراد وفحص فوري")
    expect(j.page.get_by_role("cell", name=title, exact=True)).to_be_visible()


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", ["scope-search-pair-selection", "scope-related-pair", "scope-relationship-wrong-target-recovery"])
def test_related_scope_goal(app, language, scenario):
    app.config.update(REQUIRE_CASE_APPROVAL=True, REQUIRE_INVESTIGATION_SELECTION=True, DEMO_MODE=False)
    with review_session(app, language, scenario) as (j, manager, result):
        second, form = prepare_pair(j, manager)
        note = form.locator("[name=reason]").input_value()
        if scenario == "scope-relationship-wrong-target-recovery":
            for invalid in [j.case_id, 999999]:
                form.locator("[name=related_case_id]").fill(str(invalid))
                manager.click("button", "حفظ", form)
                expect(form.locator("[name=reason]")).to_have_value(note)
                assert manager.page.evaluate("() => api('/api/cases')")["items"][0]["related_case_ids"] == []
            result["outcomes"] = ["self and unavailable target rejected without a partial relationship", "relationship reason preserved for correction"]
        form.locator("[name=related_case_id]").fill(str(second))
        manager.click("button", "حفظ", form)
        cases = manager.page.evaluate("() => api('/api/cases')")["items"]
        assert next(c for c in cases if c["id"] == j.case_id)["related_case_ids"] == [second]
        if scenario == "scope-relationship-wrong-target-recovery":
            expect(form.get_by_role("alert")).to_be_hidden()
            expect(manager.page.locator("#global-message")).to_have_class("global-message success")
            result["outcomes"].append("corrected approved target linked successfully")
            return
        page = manager.page.context.browser.new_page(locale="ar-SA" if language == "ar" else "en-US", viewport={"width": 1440, "height": 1000})
        page.on("pageerror", lambda error: result["browser_errors"].append(str(error)))
        page.add_init_script(path="node_modules/axe-core/axe.min.js")
        peer = ReviewJourney(page, j.base, result["steps"])
        peer.case_id = j.case_id
        try:
            peer.login("manager@socify.local")
            if scenario == "scope-search-pair-selection":
                search(peer, PRIMARY)
            page.get_by_role("checkbox", name=PRIMARY, exact=True).check()
            if scenario == "scope-search-pair-selection":
                search(peer, SECOND)
                # A selected case must remain identifiable when it leaves the result page.
                expect(page.locator("#workspace")).to_contain_text(PRIMARY)
            page.get_by_role("checkbox", name=SECOND, exact=True).check()
            assert_accessible(page)
            for width in [390, 1440]:
                page.set_viewport_size({"width": width, "height": 1000})
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), width
                page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-selection-{width}.png"), full_page=True)
            peer.click("button", "بدء التحقيق بالنطاق المحدد")
            assert page.evaluate("() => api('/api/investigation-selection')")["case_ids"] == [j.case_id, second]
            upload(peer, "identity-scope.json", "Identity evidence only")
            page.get_by_role("combobox", name=peer.text("القضية النشطة")).select_option(str(second))
            peer.settle()
            peer.case_id = second
            upload(peer, "email-scope.json", "Email evidence only")
            expect(page.get_by_role("cell", name="Identity evidence only", exact=True)).to_have_count(0)
            page.get_by_role("combobox", name=peer.text("القضية النشطة")).select_option(str(j.case_id))
            peer.settle()
            peer.nav("إدارة السجلات")
            expect(page.get_by_role("cell", name="Identity evidence only", exact=True)).to_be_visible()
            expect(page.get_by_role("cell", name="Email evidence only", exact=True)).to_have_count(0)
            for width in [390, 1440]:
                page.set_viewport_size({"width": width, "height": 1000})
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), width
            result["outcomes"] = [
                "both related cases selected explicitly",
                "case identity survives search" if scenario == "scope-search-pair-selection" else "related case pair available",
                "separate uploaded evidence retained while switching between cases",
            ]
        finally:
            page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-scope.png"), full_page=True)
            result["scope_visible_text"] = page.locator("main").inner_text()
            page.close()


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", ["scope-empty-search-resume", "scope-remove-hidden-selection"])
def test_hidden_case_selection_recovery(app, language, scenario):
    app.config.update(REQUIRE_CASE_APPROVAL=True, REQUIRE_INVESTIGATION_SELECTION=True, DEMO_MODE=False)
    with review_session(app, language, scenario) as (j, manager, result):
        second, _form = prepare_pair(j, manager)
        page = manager.page.context.browser.new_page(locale="ar-SA" if language == "ar" else "en-US", viewport={"width": 390, "height": 1000})
        page.on("pageerror", lambda error: result["browser_errors"].append(str(error)))
        page.add_init_script(path="node_modules/axe-core/axe.min.js")
        peer = ReviewJourney(page, j.base, result["steps"])
        try:
            peer.login("manager@socify.local")
            page.get_by_role("checkbox", name=PRIMARY, exact=True).check()
            search(peer, "No matching investigation")
            selected = page.get_by_role("list", name=peer.text("القضايا المختارة"))
            expect(selected).to_contain_text(PRIMARY)
            expect(page.get_by_role("checkbox")).to_have_count(0)
            expect(page.get_by_role("button", name=peer.text("بدء التحقيق بالنطاق المحدد"), exact=True)).to_be_enabled()
            expected_case = j.case_id
            if scenario == "scope-remove-hidden-selection":
                selected.get_by_role("button", name=peer.text("إلغاء الاختيار") + ": " + PRIMARY, exact=True).click()
                expect(selected).to_be_hidden()
                expect(page.get_by_role("button", name=peer.text("بدء التحقيق بالنطاق المحدد"), exact=True)).to_be_disabled()
                search(peer, SECOND)
                page.get_by_role("checkbox", name=SECOND, exact=True).check()
                expected_case = second
            for width in [390, 1440]:
                page.set_viewport_size({"width": width, "height": 1000})
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), width
                page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-selection-{width}.png"), full_page=True)
            assert_accessible(page)
            peer.click("button", "بدء التحقيق بالنطاق المحدد")
            assert page.evaluate("() => api('/api/investigation-selection')")["case_ids"] == [expected_case]
            upload(peer, "retained-selection.json", "Explicitly selected case evidence")
            assert page.evaluate("id => api(`/api/cases/${id}/logs`)", expected_case)["total"] == 1
            result["outcomes"] = [
                "empty results retain selected case identity",
                "hidden selection removed and replaced by an unrelated case"
                if scenario == "scope-remove-hidden-selection"
                else "investigation starts from retained selection despite empty results",
                "evidence imported into the selected case",
            ]
        finally:
            page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-scope.png"), full_page=True)
            result["scope_visible_text"] = page.locator("main").inner_text()
            page.close()
