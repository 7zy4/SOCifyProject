"""Keep independent library drafts while another reviewed item is saved."""

import json

import pytest
from playwright.sync_api import expect

from tests.e2e.test_followup_handoff_journeys import evidence_images
from tests.e2e.test_review_workflow import review_session
from tests.e2e.test_rule_authoring_journeys import REASON, TITLE, area, attach, check, publish, rules, wait_held


def yara_area(j):
    return j.page.locator("section.panel").filter(has=j.page.get_by_label(j.text("ملف قواعد YARA"), exact=True))


def yara_draft(j):
    scope = yara_area(j)
    scope.get_by_label(j.text("ملف قواعد YARA"), exact=True).set_input_files(
        {"name": "retained.yar", "mimeType": "text/plain", "buffer": b'rule Retained_Test { strings: $a = "AUTHORIZED_REVIEW" condition: $a }'}
    )
    scope.get_by_label(j.text("أمثلة YARA الاصطناعية"), exact=True).set_input_files(
        {
            "name": "examples.json",
            "mimeType": "application/json",
            "buffer": json.dumps({"positive": ["QVVUSE9SSVpFRF9SRVZJRVc="], "negative": ["QmVuaWdu"]}).encode(),
        }
    )
    for key, value in {
        "name": "Retained file review rules",
        "version": "1",
        "origin": "Internal evidence review",
        "license": "Authorized internal use",
    }.items():
        scope.locator(f"input[name={key}]").fill(value)


def assert_yara_draft(j):
    scope = yara_area(j)
    expect(scope.locator("input[name=name]")).to_have_value("Retained file review rules")
    assert scope.get_by_label(j.text("ملف قواعد YARA"), exact=True).evaluate("e=>e.files[0]?.name") == "retained.yar"
    assert scope.get_by_label(j.text("أمثلة YARA الاصطناعية"), exact=True).evaluate("e=>e.files[0]?.name") == "examples.json"


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", ["library-yara-draft-before-sigma", "library-yara-draft-during-sigma"])
def test_author_retains_unpublished_file_rules_while_publishing_a_log_rule(app, language, scenario):
    with review_session(app, language, scenario) as (analyst, j, result):
        j.login("manager@socify.local")
        j.nav("مكتبة التحليل المحلي")
        attach(j)
        check(j)
        if scenario.endswith("before-sigma"):
            yara_draft(j)
        held = []

        def intercept(route):
            response = route.fetch()
            assert response.status == 201
            held.append((route, response))

        j.page.route("**/api/autopsy/sigma/publish", intercept, times=1)
        area(j).get_by_role("button", name=j.text("حفظ"), exact=True).click()
        wait_held(j, held)
        # The old integrated test's wait is already satisfied by the preview.
        expect(area(j).get_by_role("cell", name=TITLE, exact=True)).to_be_visible()
        result["publication_confirmation_still_pending"] = True
        try:
            if scenario.endswith("during-sigma"):
                yara_draft(j)
        finally:
            held[0][0].fulfill(response=held[0][1])
            j.settle()
        assert len(rules(j)) == 1
        assert_yara_draft(j)
        if scenario.endswith("during-sigma"):
            assert yara_area(j).locator("input[name=license]").evaluate("e=>e===document.activeElement")
        result["outcomes"] = ["Published the reviewed log rule while retaining the independent file-rule draft and selected files; no YARA compilation claim"]
        evidence_images(j, result)


def intel_area(j):
    return j.page.locator("section.panel").filter(has=j.page.get_by_label(j.text("حزمة TI المحلية"), exact=True))


def intel_draft(j, invalid=False):
    scope = intel_area(j)
    scope.locator("input[type=file]").set_input_files(
        {
            "name": "reviewed-intel.json",
            "mimeType": "application/json",
            "buffer": b"{broken" if invalid else json.dumps([{"type": "ip", "value": "192.0.2.48", "verdict": "suspicious"}]).encode(),
        }
    )
    for key, value in {
        "name": "Reviewed gateway indicators",
        "version": "1",
        "source": "Authorized internal review",
        "license": "Internal use",
        "format": "flat",
        "expires_at": "2030-01-01T12:00",
    }.items():
        scope.locator(f"input[name={key}]").fill(value)


def assert_sigma_draft(j):
    expect(area(j).locator("input[name=reason]")).to_have_value(REASON)
    assert area(j).get_by_label(j.text("ملف Sigma"), exact=True).evaluate("e=>e.files[0]?.name") == "gateway.yml"


def intel_items(j):
    return j.page.evaluate("()=>api('/api/autopsy/intelligence')")["items"]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "library-sigma-before-intel",
        "library-sigma-during-intel",
        "library-sigma-intel-invalid-recovery",
        "library-yara-before-intel",
        "library-multiple-drafts-activation",
        "library-intel-draft-on-sigma",
        "library-intel-pending-fields",
    ],
)
def test_author_saves_intelligence_without_losing_other_work(app, language, scenario):
    with review_session(app, language, scenario) as (analyst, j, result):
        j.login("manager@socify.local")
        j.nav("مكتبة التحليل المحلي")
        sigma = scenario in {"library-sigma-before-intel", "library-sigma-during-intel", "library-sigma-intel-invalid-recovery", "library-intel-draft-on-sigma"}
        if sigma and scenario != "library-sigma-during-intel":
            attach(j)
        if scenario == "library-yara-before-intel":
            yara_draft(j)
        intel_draft(j, invalid=scenario == "library-sigma-intel-invalid-recovery")
        if scenario == "library-intel-draft-on-sigma":
            assert publish(j).status == 201
            expect(intel_area(j).locator("input[name=name]")).to_have_value("Reviewed gateway indicators")
            assert intel_area(j).locator("input[type=file]").evaluate("e=>e.files[0]?.name") == "reviewed-intel.json"
        if scenario == "library-sigma-intel-invalid-recovery":
            j.click("button", "حفظ", intel_area(j))
            expect(intel_area(j).get_by_role("alert").filter(visible=True)).to_be_visible()
            assert_sigma_draft(j)
            intel_draft(j)
        held = []

        def hold(route):
            response = route.fetch()
            assert response.status == 201, response.text()
            held.append((route, response))

        if scenario in {"library-sigma-during-intel", "library-intel-pending-fields"}:
            j.page.route("**/api/autopsy/intelligence", hold, times=1)
            intel_area(j).get_by_role("button", name=j.text("حفظ"), exact=True).click()
            wait_held(j, held)
            try:
                if scenario == "library-sigma-during-intel":
                    attach(j)
                else:
                    expect(intel_area(j).locator("input[name=name]")).to_be_disabled()
                    expect(intel_area(j).locator("input[type=file]")).to_be_disabled()
            finally:
                held[0][0].fulfill(response=held[0][1])
                j.settle()
        else:
            j.click("button", "حفظ", intel_area(j))
        assert len(intel_items(j)) == 1
        expect(intel_area(j).locator("input[name=name]")).to_have_value("")
        if scenario == "library-multiple-drafts-activation":
            attach(j)
            yara_draft(j)
            j.click("button", "تفعيل الإصدار")
            assert intel_items(j)[0]["active"]
            assert_sigma_draft(j)
            assert_yara_draft(j)
            assert publish(j).status == 201
            assert_yara_draft(j)
        elif sigma and scenario != "library-intel-draft-on-sigma":
            assert_sigma_draft(j)
            assert publish(j).status == 201
        elif scenario == "library-yara-before-intel":
            assert_yara_draft(j)
        result["outcomes"] = [
            "Saved the requested intelligence source through the UI and retained independent library work; invalid-input recovery and pending controls checked where applicable"
        ]
        evidence_images(j, result)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_late_library_refresh_keeps_both_completed_publications_visible(app, language):
    with review_session(app, language, "library-parallel-late-refresh") as (analyst, j, result):
        j.login("manager@socify.local")
        j.nav("مكتبة التحليل المحلي")
        attach(j)
        intel_draft(j)
        waiting_post = []
        waiting_get = []

        def hold_intel(route):
            if route.request.method == "POST":
                waiting_post.append(route)
            elif not waiting_get:
                response = route.fetch()
                waiting_get.append((route, response))
            else:
                route.continue_()

        j.page.route("**/api/autopsy/intelligence", hold_intel)
        intel_area(j).get_by_role("button", name=j.text("حفظ"), exact=True).click()
        wait_held(j, waiting_post)
        area(j).get_by_role("button", name=j.text("حفظ"), exact=True).click()
        wait_held(j, waiting_get)
        response = waiting_post[0].fetch()
        assert response.status == 201
        waiting_post[0].fulfill(response=response)
        # The newer refresh finishes while the earlier list response remains held.
        expect(j.page.get_by_role("cell", name="Reviewed gateway indicators", exact=True)).to_be_visible()
        waiting_get[0][0].fulfill(response=waiting_get[0][1])
        j.settle()
        j.page.unroute("**/api/autopsy/intelligence", hold_intel)
        assert len(intel_items(j)) == len(rules(j)) == 1
        expect(j.page.get_by_role("cell", name="Reviewed gateway indicators", exact=True)).to_be_visible()
        expect(area(j).locator("input[name=reason]")).to_have_value("")
        expect(intel_area(j).locator("input[name=name]")).to_have_value("")
        result["outcomes"] = ["Two independent real publications remain visible despite out-of-order refresh responses; no duplicate items"]
        evidence_images(j, result)
