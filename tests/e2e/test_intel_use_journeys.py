"""Use a recovered source in an investigation, including a colleague's newer source."""

import json

import pytest
from playwright.sync_api import expect

from tests.e2e.test_followup_handoff_journeys import evidence_images, manager_case
from tests.e2e.test_intel_receipt_journeys import PATH, save
from tests.e2e.test_library_draft_journeys import intel_area, intel_draft, intel_items
from tests.e2e.test_review_workflow import ARTIFACTS, review_session
from tests.e2e.test_rule_authoring_journeys import change_author_role
from tests.e2e.test_watchlist_intelligence_journeys import IP, inspect_enrichment, observable, upload


def source(j, verdict, version):
    intel_draft(j)
    scope = intel_area(j)
    scope.locator("input[name=version]").fill(version)
    scope.locator("input[type=file]").set_input_files(
        {
            "name": "reviewed-indicators.json",
            "mimeType": "application/json",
            "buffer": json.dumps([{"type": "ip", "value": IP, "verdict": verdict, "confidence": 80}]).encode(),
        }
    )


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", ["intel-recovery-investigation", "intel-recovery-colleague-source"])
def test_analyst_uses_the_current_source_after_import_recovery(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        manager_case(j, manager)
        if scenario == "intel-recovery-colleague-source":
            change_author_role(manager, "soc_manager")
            j.login("analyst@socify.local")
        upload(j)
        assert observable(j)["enrichment"]["status"] == "not_configured"
        manager.nav("مكتبة التحليل المحلي")
        source(manager, "malicious", "1")
        committed = []

        def interrupt(route):
            response = route.fetch()
            assert response.status == 201
            committed.append(response.json())
            route.abort()

        manager.page.route("**" + PATH, interrupt, times=1)
        manager.click("button", "حفظ", intel_area(manager))
        expect(intel_area(manager).get_by_role("alert").filter(visible=True)).to_be_visible()
        if scenario == "intel-recovery-colleague-source":
            j.nav("مكتبة التحليل المحلي")
            source(j, "benign", "2")
            assert save(j).status == 201
            listed = j.page.locator("section.panel").filter(has=j.page.get_by_role("heading", name=j.text("إصدارات مصادر TI وGeoIP"), exact=True))
            j.click("button", "تفعيل الإصدار", listed.locator("tbody tr").first)
        recovered = save(manager)
        assert recovered.status == 201 and recovered.json()["id"] == committed[0]["id"]
        if scenario == "intel-recovery-investigation":
            manager.click("button", "تفعيل الإصدار")
        items = intel_items(manager)
        active = [item for item in items if item["active"]]
        assert len(active) == 1 and active[0]["version"] == ("2" if scenario == "intel-recovery-colleague-source" else "1")
        j.nav("استخبارات التهديدات")
        if scenario == "intel-recovery-colleague-source":
            j.page.locator(".case-selector-list").get_by_role("link").filter(has_text="Authorized maintenance investigation").click()
            j.settle()
        dialog = inspect_enrichment(j)
        j.click("button", "إثراء محلي بالإصدارات الحالية", dialog)
        value = observable(j)
        expected = "benign" if scenario == "intel-recovery-colleague-source" else "malicious"
        assert value["enrichment"]["verdict"] == expected
        assert len(value["enrichment"]["matches"]) == 1
        dialog = inspect_enrichment(j)
        expect(dialog).to_contain_text("Authorized internal review")
        expect(dialog).to_contain_text(IP)
        for width in [390, 1440]:
            j.page.set_viewport_size({"width": width, "height": 1000})
            assert dialog.evaluate("el=>el.scrollWidth<=el.clientWidth")
            dialog.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-enrichment-{width}.png"))
        j.page.keyboard.press("Escape")
        result["outcomes"] = [
            "Recovered the source once, retained the intended currently active version, and explicitly refreshed the investigation assessment from that source"
        ]
        evidence_images(j, result)
