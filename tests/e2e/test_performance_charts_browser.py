"""Chart acceptance on explicitly prepared, isolated investigation histories."""

from datetime import timedelta
from pathlib import Path

import pytest
from playwright.sync_api import expect

from socify.timeutils import utc_now
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_performance_goal_journeys import counter, delivery, period
from tests.e2e.test_review_workflow import review_session

ARTIFACTS = Path("artifacts/performance-charts")


def stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def prepare_history(j, manager, database, result):
    """Set up historical state, never count these fixtures as UI task completions."""
    now = utc_now().replace(hour=8, minute=0, second=0, microsecond=0)
    database.execute("UPDATE incident_cases SET created_at=?,severity='critical' WHERE id=?", (stamp(now - timedelta(days=2)), j.case_id))
    cases = manager.page.evaluate(
        """async () => {
            const cases=[];
            for (const title of ['Endpoint response review','Email delivery review','Retained identity investigation','Access policy review'])
                cases.push(await api('/api/cases',{method:'POST',body:{title}}));
            return cases;
        }"""
    )
    for item, days, hours, budget in zip(cases[:3], (5, 4, 60), (1, 3, 58 * 24 + 1), (60, 60, 60 * 24 * 60), strict=True):
        created = now - timedelta(days=days)
        database.execute("UPDATE incident_cases SET created_at=? WHERE id=?", (stamp(created), item["id"]))
        manager.page.evaluate(
            """async ({id,minutes}) => {
                const state=await api(`/api/cases/${id}`);
                await api(`/api/cases/${id}/sla`,{method:'POST',body:{version:state.version,minutes,calendar:{mode:'24x7',timezone:'UTC'},reason:'Agreed investigation response target'}});
            }""",
            {"id": item["id"], "minutes": budget},
        )
        if item == cases[0]:
            manager.page.evaluate(
                """async ({id,start}) => {
                    await api(`/api/cases/${id}/imports`,{method:'POST',body:{filename:'response-history.json',content:JSON.stringify([{title:'Endpoint response evidence',timestamp:start,hostname:'REVIEW-ENDPOINT'}])}});
                    const evidence=(await api(`/api/cases/${id}`)).evidence[0].id;
                    for (const [phase,minutes] of [['detection',0],['acknowledgement',10],['containment',20],['recovery',40]])
                        await api(`/api/cases/${id}/records/response`,{method:'POST',body:{title:phase,phase,status:'succeeded',performed_by:state.user.id,performed_at:new Date(Date.parse(start)+minutes*60000).toISOString(),evidence_id:evidence,details:'Verified response milestone in retained investigation history'}});
                }""",
                {"id": item["id"], "start": stamp(created)},
            )
        database.execute("UPDATE incident_cases SET status='closed',closed_at=? WHERE id=?", (stamp(created + timedelta(hours=hours)), item["id"]))
    database.execute("UPDATE incident_cases SET created_at=?,severity='high' WHERE id=?", (stamp(now - timedelta(days=3)), cases[3]["id"]))
    result["kind"] = "interface acceptance on prepared synthetic histories"
    result["setup_only_records"] = {"cases": 5, "closed": 3, "note": "Authenticated API setup and historical timestamps; not five users or UI completions"}


def appearance(j, language, theme):
    if j.page.locator("html").get_attribute("lang") != language:
        j.page.locator("[data-language-toggle]").click()
        j.settle()
    j.page.locator(f'[data-theme-option="{theme}"]').click()
    expect(j.page.locator("html")).to_have_attribute("data-theme", theme)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("theme", ["dark", "light"])
def test_performance_charts_support_comparison_scope_and_keyboard(app, database, language, theme):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with review_session(app, language, f"performance-charts-{theme}") as (j, manager, result):
        manager.login("manager@socify.local")
        prepare_history(j, manager, database, result)
        appearance(manager, language, theme)
        manager.nav("الأداء")
        period(manager, "7")
        page = manager.page
        expected_percent = page.evaluate("() => new Intl.NumberFormat(SOCifyLocale.language,{style:'percent',maximumFractionDigits:0}).format(.5)")
        expect(page.locator("[data-completion-value]")).to_have_text(expected_percent)
        expected_speed = page.evaluate("() => new Intl.NumberFormat(SOCifyLocale.language,{style:'percent',maximumFractionDigits:0}).format(.667)")
        expect(page.locator("[data-speed-value]")).to_have_text(expected_speed)
        assert counter(manager, "قضايا نشطة") == 2 and counter(manager, "أغلقت خلال الفترة") == 3
        assert page.locator(".performance-trend-bucket").count() == 8
        assert page.locator(".performance-duration-track span").count() == 4
        for motion, width in (("no-preference", 1440), ("no-preference", 390), ("reduce", 1440), ("reduce", 390)):
            page.emulate_media(reduced_motion=motion)
            page.set_viewport_size({"width": width, "height": 1000 if width == 1440 else 844})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (language, theme, width)
            bars = page.locator(".performance-trend-bucket")
            bars.first.focus()
            bars.first.press("End")
            expect(bars.last).to_be_focused()
            bars.last.press("Home")
            expect(bars.first).to_be_focused()
            assert "selected" in bars.first.get_attribute("class")
            bars.first.press("ArrowRight")
            expect(bars.nth(1)).to_be_focused()
            expect(page.locator(".performance-trend-readout")).to_contain_text(manager.text("أنشئت"))
            assert_accessible(page)
            if motion == "no-preference":
                bars.nth(2).click()
                page.evaluate("document.activeElement?.blur(); window.scrollTo({top:0,behavior:'instant'})")
                page.screenshot(path=str(ARTIFACTS / f"performance-{language}-{theme}-{width}.png"), full_page=True, animations="disabled")
                page.screenshot(path=str(ARTIFACTS / f"performance-{language}-{theme}-{width}-viewport.png"), animations="disabled")
        page.set_viewport_size({"width": 1440, "height": 1000})
        period(manager, "all")
        assert page.locator("[data-completion-count]").inner_text().translate(str.maketrans("٠١٢٣٤٥٦٧٨٩", "0123456789")) == (
            "3 من 5" if language == "ar" else "3 of 5"
        )
        person = j.page.evaluate("state.user.name")
        delivery(manager).get_by_role("link", name=person, exact=True).click()
        manager.settle()
        assert "days=all" in page.url and "member=" in page.url
        assert page.locator("[data-completion-count]").inner_text().translate(str.maketrans("٠١٢٣٤٥٦٧٨٩", "0123456789")) == (
            "0 من 1" if language == "ar" else "0 of 1"
        )
        expect(page.locator("[data-speed-value]")).to_have_text("—")
        manager.click("link", "أدائي", page.locator(".channel-tabs"))
        assert page.locator("[data-completion-count]").inner_text().translate(str.maketrans("٠١٢٣٤٥٦٧٨٩", "0123456789")) == (
            "3 من 4" if language == "ar" else "3 of 4"
        )
        result["outcomes"] = [
            "same cohort completion, SLA and evidenced duration counts in both languages/themes",
            "keyboard chart inspection",
            "member and period filtering",
            "no horizontal page overflow",
            "no serious or critical accessibility violations",
        ]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_empty_performance_has_no_invented_success_or_speed(app, language):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with review_session(app, language, "performance-charts-empty", create_case=False) as (j, _manager, result):
        result["kind"] = "interface acceptance with no operational cases"
        appearance(j, language, "dark")
        j.nav("الأداء")
        expect(j.page.locator("[data-completion-value]")).to_have_text("—")
        expect(j.page.locator("[data-speed-value]")).to_have_text("—")
        expect(j.page.locator(".performance-trend-bucket")).to_have_count(0)
        expect(j.page.locator(".performance-duration-track span")).to_have_count(0)
        assert counter(j, "قضايا نشطة") == counter(j, "أغلقت خلال الفترة") == 0
        for width in (1440, 390):
            j.page.set_viewport_size({"width": width, "height": 1000})
            assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            assert_accessible(j.page)
            j.page.screenshot(path=str(ARTIFACTS / f"performance-empty-{language}-{width}.png"), full_page=True, animations="disabled")


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_boundary_percentages_remain_distinct_from_zero_and_complete(app, language):
    with review_session(app, language, "performance-chart-boundaries", create_case=False) as (j, _manager, result):
        result["kind"] = "isolated browser rendering of boundary API contracts; no users or completed investigations"
        appearance(j, language, "dark")
        j.page.set_viewport_size({"width": 390, "height": 844})
        boundary = {"metric": "completion", "count": 1999, "total": 2000, "percentage": 99.95}

        def respond(route):
            response = route.fetch()
            data = response.json()
            total = boundary["total"]
            completed = boundary["count"] if boundary["metric"] == "completion" else total
            on_time = boundary["count"] if boundary["metric"] == "speed" else completed
            data["completion"] = {
                "total": total,
                "completed": completed,
                "pending": total - completed,
                "unmeasured": 0,
                "percentage": boundary["percentage"] if boundary["metric"] == "completion" else 100,
                "basis": "created_in_period",
            }
            data["speed"] = {
                "on_time": on_time,
                "late": completed - on_time,
                "included": completed,
                "unmeasured": 0,
                "compliance_percent": boundary["percentage"] if boundary["metric"] == "speed" else 100,
                "basis": "configured_case_sla",
            }
            data["counts"].update({"open": total - completed, "closed": completed})
            data["severity"] = {"medium": total - completed}
            route.fulfill(response=response, json=data)

        j.page.route("**/api/soc/performance?*", respond)
        for metric in ("completion", "speed"):
            for count, total, percentage, expected in (
                (1999, 2000, 99.95, "99.95%"),
                (1, 2000, 0.05, "0.05%"),
                (99999, 100000, 99.999, ">99.99%"),
                (1, 100000, 0.001, "<0.01%"),
            ):
                boundary.update(metric=metric, count=count, total=total, percentage=percentage)
                j.page.goto(j.base + "/performance")
                j.settle()
                value = j.page.locator(f"[data-{metric}-value]").inner_text()
                normalized = value.translate(str.maketrans("٠١٢٣٤٥٦٧٨٩٫٪", "0123456789.%")).translate(
                    {ord(mark): None for mark in "\u061c\u200e\u200f\u2066\u2067\u2068\u2069"}
                )
                assert normalized == expected
                assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                assert j.page.locator(".performance-speed-score").evaluate("el => el.scrollWidth <= el.clientWidth")
                assert j.page.locator(".performance-ring-label strong").evaluate("el => el.scrollWidth <= el.parentElement.clientWidth")
        assert_accessible(j.page)
