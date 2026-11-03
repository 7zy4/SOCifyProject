"""Use observed indicators, retained sources, and watchlist decisions as an analyst."""

import json

import pytest
from playwright.sync_api import expect

from tests.e2e.test_assignment_handoff_journeys import role_permission
from tests.e2e.test_batch_boundary_journeys import restrict_batch
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_case_continuity_journeys import panel
from tests.e2e.test_followup_handoff_journeys import evidence_images, manager_case
from tests.e2e.test_report_recovery_journeys import report, report_path
from tests.e2e.test_review_workflow import ARTIFACTS, review_session

WATCHLIST = "قائمة مراقبة الإيميلات والـ IPs المشبوهة (Watchlist)"
SCAN = "فحص سجلات القضية مقابل قائمة المراقبة الآن"
IP = "203.0.113.55"
NOTE = "Retained gateway indicator requiring review"


def upload(j, suffix="initial"):
    j.page.goto(j.case_url + "?tab=logs")
    j.settle()
    records = [{"title": f"Retained VPN session {suffix}", "source_ip": IP, "hostname": "gateway.example.test", "timestamp": "2026-11-02T09:00:00Z"}]
    j.page.locator("input[name=file]").set_input_files({"name": f"watch-{suffix}.json", "mimeType": "application/json", "buffer": json.dumps(records).encode()})
    j.click("button", "استيراد وفحص فوري")
    expect(j.page.get_by_role("cell", name=f"Retained VPN session {suffix}", exact=True)).to_be_visible()


def watch(j):
    return panel(j, WATCHLIST)


def watch_row(j, value=IP):
    return watch(j).locator("tr").filter(has=j.page.get_by_role("cell", name=value, exact=True))


def fill_watch(j, value=IP, kind="ip"):
    form = watch(j).get_by_role("form", name=j.text("إضافة مؤشر لقائمة المراقبة"), exact=True)
    form.locator("select[name=indicator_type]").select_option(kind)
    form.locator("input[name=value]").fill(value)
    form.locator("input[name=note]").fill(NOTE)
    return form


def add_watch(j, value=IP):
    form = fill_watch(j, value)
    j.click("button", "إضافة لقائمة المراقبة", form)
    expect(watch_row(j)).to_be_visible()


def state(j):
    return j.page.evaluate("id=>Promise.all([api('/api/watchlist'),api(`/api/cases/${id}/alerts`)])", j.case_id)


def observed(j):
    return panel(j, "الإثراء المحلي").locator("tr").filter(has=j.page.get_by_role("cell", name=IP, exact=True))


def observable(j):
    return next(item for item in j.page.evaluate("id=>api(`/api/cases/${id}/observables`)", j.case_id)["items"] if item["value"] == IP)


def bundle(manager, name, verdict="malicious", value=IP, activate=True):
    manager.nav("مكتبة التحليل المحلي")
    form = panel(manager, "استيراد إصدار محلي جديد").locator("form")
    for key, text in {"name": name, "version": "1", "source": name + " source", "license": "Internal review data", "expires_at": "2030-01-01T00:00"}.items():
        form.locator(f"input[name={key}]").fill(text)
    form.locator("input[name=format]").fill("flat")
    form.locator("input[type=file]").set_input_files(
        {
            "name": name + ".json",
            "mimeType": "application/json",
            "buffer": json.dumps([{"type": "ip", "value": value, "verdict": verdict, "confidence": 80}]).encode(),
        }
    )
    manager.click("button", "حفظ", form)
    row = panel(manager, "إصدارات مصادر TI وGeoIP").locator("tr").filter(has=manager.page.get_by_role("cell", name=name, exact=True))
    expect(row).to_be_visible()
    if activate:
        manager.click("button", "تفعيل الإصدار", row)


def inspect_enrichment(j):
    j.click("button", "تفاصيل الإثراء", observed(j))
    return j.page.get_by_role("dialog")


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "watchlist-reload-scan",
        "watchlist-visible-scan-count",
        "watchlist-repeat-scan",
        "watchlist-disable-reactivate",
        "watchlist-normalized-duplicate",
        "watchlist-invalid-recovery",
        "watchlist-permission-recovery",
        "watchlist-scope-restoration",
        "intel-no-source-unknown",
        "intel-unmatched-unknown",
        "intel-activation-refresh",
        "intel-conflicting-sources",
    ],
)
def test_analyst_can_interpret_and_act_on_retained_indicators(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        manager_case(j, manager)
        if scenario == "intel-unmatched-unknown":
            bundle(manager, "Unrelated source", value="198.51.100.8")
        elif scenario == "intel-conflicting-sources":
            bundle(manager, "Gateway malicious assessment")
            bundle(manager, "Gateway benign assessment", verdict="benign")
        upload(manager if scenario == "watchlist-scope-restoration" else j)
        j.nav("استخبارات التهديدات")
        if scenario.startswith("watchlist-"):
            if scenario == "watchlist-invalid-recovery":
                form = fill_watch(j, "203.0.113.0/99", "cidr")
                j.click("button", "إضافة لقائمة المراقبة", form)
                expect(j.page.locator("#global-message")).to_be_visible()
                expect(form.locator("input[name=note]")).to_have_value(NOTE)
                form.locator("input[name=value]").fill("203.0.113.0/24")
                j.click("button", "إضافة لقائمة المراقبة", form)
                expect(watch_row(j, "203.0.113.0/24")).to_be_visible()
            elif scenario == "watchlist-permission-recovery":
                form = fill_watch(j)
                role_permission(manager, "cases.update", False)
                j.click("button", "إضافة لقائمة المراقبة", form)
                expect(j.page.locator("#global-message")).to_be_visible()
                expect(form.locator("input[name=note]")).to_have_value(NOTE)
                assert state(manager)[0]["items"] == []
                role_permission(manager, "cases.update", True)
                j.click("button", "إضافة لقائمة المراقبة", form)
                expect(watch_row(j)).to_be_visible()
            else:
                add_watch(j)
                if scenario == "watchlist-normalized-duplicate":
                    add_watch(j, "::ffff:203.0.113.55")
                    assert len(state(j)[0]["items"]) == 1
                    expect(watch_row(j)).to_have_count(1)
                else:
                    if scenario == "watchlist-reload-scan":
                        j.page.reload()
                        j.settle()
                        expect(watch(j).get_by_role("button", name=j.text(SCAN), exact=True)).to_be_visible()
                    if scenario == "watchlist-scope-restoration":
                        restrict_batch(manager, "watch-initial.json")
                        j.click("button", SCAN, watch(j))
                        expect(j.page.locator("#global-message")).to_be_visible()
                        assert state(manager)[1]["items"] == []
                        restrict_batch(manager, "watch-initial.json", j.page.evaluate("state.user.name"))
                    if scenario == "watchlist-visible-scan-count":
                        fill_watch(j, "198.51.100.8")
                    j.click("button", SCAN, watch(j))
                    initial_watch, initial_alerts = state(j)
                    assert initial_watch["items"][0]["hits_count"] == 1
                    assert len(initial_alerts["items"]) == 1
                    if scenario == "watchlist-visible-scan-count":
                        numeral = j.page.evaluate("new Intl.NumberFormat(SOCifyLocale.language==='ar'?'ar':'en').format(1)")
                        expect(watch_row(j).get_by_role("cell").nth(3)).to_have_text(numeral)
                        expect(watch(j).locator("input[name=value]")).to_have_value("198.51.100.8")
                        expect(watch(j).locator("input[name=note]")).to_have_value(NOTE)
                    elif scenario == "watchlist-repeat-scan":
                        j.click("button", SCAN, watch(j))
                        assert state(j) == [initial_watch, initial_alerts]
                    elif scenario == "watchlist-disable-reactivate":
                        j.click("button", "إيقاف", watch_row(j))
                        upload(j, "later")
                        assert len(state(j)[1]["items"]) == 1
                        j.nav("استخبارات التهديدات")
                        expect(watch_row(j)).to_contain_text(j.text("متوقف"))
                        j.click("button", "تفعيل", watch_row(j))
                        j.click("button", SCAN, watch(j))
                        assert len(state(j)[1]["items"]) == 2
                        assert state(j)[0]["items"][0]["hits_count"] == 2
                        j.click("button", SCAN, watch(j))
                        assert len(state(j)[1]["items"]) == 2
        else:
            if scenario == "intel-activation-refresh":
                assert observable(j)["enrichment"]["status"] == "not_configured"
                bundle(manager, "Reviewed gateway indicator")
                # The analyst refreshes the retained assessment explicitly.
                dialog = inspect_enrichment(j)
                j.click("button", "إثراء محلي بالإصدارات الحالية", dialog)
                assert observable(j)["enrichment"]["verdict"] == "malicious"
            value = observable(j)
            if scenario in {"intel-no-source-unknown", "intel-unmatched-unknown"}:
                assert value["enrichment"]["verdict"] == "unknown"
                assert value["enrichment"]["status"] == ("not_configured" if scenario == "intel-no-source-unknown" else "no_match")
                expect(observed(j)).to_contain_text(j.page.evaluate("autopsyLabel('unknown')"))
            dialog = inspect_enrichment(j)
            expect(dialog.get_by_role("table").first).to_be_visible()
            expect(dialog).to_contain_text(IP)
            if scenario == "intel-conflicting-sources":
                assert {m["verdict"] for m in value["enrichment"]["matches"]} == {"malicious", "benign"}
                expect(dialog).to_contain_text("Gateway malicious assessment source")
                expect(dialog).to_contain_text("Gateway benign assessment source")
                expect(dialog).to_contain_text(j.text("نتائج متعارضة"))
                second_source = dialog.get_by_role("table").filter(has=j.page.locator("caption", has_text="Gateway benign assessment"))
                second_source.scroll_into_view_if_needed()
                expect(second_source).to_be_visible()
                second_source.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-second-source.png"))
                dialog.evaluate("el=>el.scrollTo({top:0,behavior:'instant'})")
            assert_accessible(j.page)
            j.page.set_viewport_size({"width": 390, "height": 1000})
            assert dialog.evaluate("el=>el.scrollWidth<=el.clientWidth")
            dialog.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-detail-mobile.png"))
            j.page.set_viewport_size({"width": 1440, "height": 1000})
            dialog.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-detail.png"))
            j.page.keyboard.press("Escape")
            if scenario == "intel-activation-refresh":
                j.page.goto(j.case_url + "?tab=reports")
                j.settle()
                j.click("button", "إعداد تقرير جديد")
                snapshot = report(j, report_path(j))
                assert "Reviewed gateway indicator source" in json.dumps(snapshot["payload"])
                result["report_state"] = snapshot["job"]["state"]
        result["outcomes"] = [scenario, "user actions and retained state checked", "no external reputation request or device execution"]
        evidence_images(j, result)
        if scenario.startswith("watchlist-"):
            watch(j).screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-target.png"))
