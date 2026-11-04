"""Interface clarity from retained evidence; appearances are not extra users."""

import json
from pathlib import Path

import pytest
from playwright.sync_api import expect

from tests.e2e.test_batch_boundary_journeys import upload_logs
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_investigation_link_journeys import choose
from tests.e2e.test_performance_charts_browser import appearance, prepare_history
from tests.e2e.test_performance_goal_journeys import period
from tests.e2e.test_review_workflow import review_session

ARTIFACTS = Path("artifacts/interface-final-review")


def capture(j, result, view):
    phase = "after"
    for theme in ("dark", "light"):
        appearance(j, result["language"], theme)
        for width in (1440, 390):
            j.page.set_viewport_size({"width": width, "height": 1000})
            j.page.evaluate("window.scrollTo({top:0,behavior:'instant'})")
            assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth"), view
            target = ARTIFACTS / f"{phase}-{result['language']}-{view}-{theme}-{width}.png"
            j.page.screenshot(path=str(target), full_page=True, animations="disabled")
            result.setdefault("screenshots", []).append(str(target))
            if view == "response" and width == 390:
                summary = j.page.locator(".sla-summary")
                bounds = summary.evaluate("el => ({available:el.clientWidth,content:el.scrollWidth})")
                result.setdefault("mobile_sla_widths", []).append({"theme": theme, **bounds})
                assert bounds["content"] <= bounds["available"] + 1, bounds
            if width == 1440:
                viewport = target.with_name(target.stem + "-viewport.png")
                j.page.screenshot(path=str(viewport), full_page=False, animations="disabled")
                result["screenshots"].append(str(viewport))
        assert_accessible(j.page)


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_record_evidence_and_relationships_remain_clear_across_appearance(app, database, language):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    phase = "after"
    with review_session(app, language, f"interface-clarity-{phase}") as (j, manager, result):
        result["scope"] = "One simulated task per language; themes and widths are visual checks, not additional users. No native PDF export claimed."
        upload_logs(j, "gateway-evidence.json", "Source")
        j.click("link", "الاستجابة والتصعيد")
        actor = j.page.evaluate("`${state.user.name} · ${autopsyLabel(state.user.role)}`")
        j.record(
            "response",
            {
                "title": "source",
                "phase": "detection",
                "status": "succeeded",
                "details": "open",
                "performed_by": actor,
                "performed_at": "2026-11-02T09:01",
                "evidence_id": "gateway-evidence.json",
            },
        )
        card = j.page.locator(".record-card").filter(has=j.page.get_by_role("heading", name="source", exact=True))
        capture(j, result, "response")
        result["record_before_assertion"] = card.inner_text()
        expect(card.get_by_role("rowheader", name=j.text("العنوان"), exact=True)).to_have_count(0)
        expect(card.get_by_role("cell", name="open", exact=True)).to_be_visible()
        expect(card.get_by_role("row").filter(has=j.page.get_by_role("rowheader", name=j.text("الدليل المرتبط"), exact=True))).to_contain_text(
            "gateway-evidence.json"
        )
        for _ in range(2):
            j.page.locator("[data-language-toggle]").click()
            j.settle()
            expect(card.get_by_role("heading", name="source", exact=True)).to_be_visible()
            expect(card.get_by_role("cell", name="open", exact=True)).to_be_visible()
            expect(card).to_contain_text("gateway-evidence.json")
            expect(card).not_to_contain_text("undefined")
        missing_reference = j.page.evaluate(
            """() => autopsyRecordCard({kind:'response',payload:{title:'Unavailable reference check',evidence_id:99999999},updated_at:'2026-11-02T09:00:00Z'}).textContent"""
        )
        assert j.text("الدليل غير متاح") in missing_reference
        assert "undefined" not in missing_reference
        result["component_contract"] = "An unavailable evidence reference renders no inferred title; detached renderer check, not another user journey."
        j.click("button", "تعديل", card)
        dialog = j.page.get_by_role("dialog")
        expect(dialog.locator("input[name=title]")).to_have_value("source")
        expect(dialog.locator("[name=details]")).to_have_value("open")
        dialog.locator("input[name=phase]").focus()
        dialog.locator("input[name=phase]").press("ArrowDown")
        expect(dialog.get_by_role("listbox")).to_be_visible()
        dialog.locator("input[name=phase]").press("Escape")
        expect(dialog.locator("input[name=phase]")).to_be_focused()
        j.click("button", "إغلاق", dialog)

        j.click("link", "التحقيق والخط الزمني")
        capture(j, result, "investigation")
        expect(j.page.locator(".autopsy-timeline")).to_contain_text(j.text("وقت مسجل في المصدر"))
        expect(j.page.locator(".autopsy-timeline").get_by_role("heading", name="Source", exact=True)).to_be_visible()
        graph = j.page.locator("section.panel").filter(has=j.page.get_by_role("heading", name=j.text("جدول العلاقات ومراجع الأدلة"), exact=True)).last
        if language == "ar":
            for untranslated in ("Event", "Host", "Incident", "observed"):
                expect(graph.get_by_role("cell", name=untranslated, exact=True)).to_have_count(0)

        j.click("link", "التقارير والمراجعة")
        j.click("button", "إعداد تقرير جديد")
        revision = j.page.locator(".report-revision").first
        revision.locator("summary").filter(has_text=j.text("عرض بيانات النسخة للمراجعة")).click()
        preview = revision.locator(".report-preview")
        expect(preview).to_be_visible()
        capture(j, result, "report")
        result["retained_evidence"] = [{"id": item["id"], "title": item["title"]} for item in j.state()["evidence"]]

        manager.login("manager@socify.local")
        prepare_history(j, manager, database, result)
        manager.nav("الأداء")
        period(manager, "all")
        capture(manager, result, "performance")
        menu = manager.page.get_by_role("button", name=manager.text("فتح القائمة"), exact=True)
        menu.focus()
        menu.press("Enter")
        expect(menu).to_have_attribute("aria-expanded", "true")
        manager.page.keyboard.press("Escape")
        expect(menu).to_have_attribute("aria-expanded", "false")
        expect(menu).to_be_focused()
        result["outcomes"] = [
            "Uploaded retained evidence",
            "Saved an evidence-linked response",
            "Reviewed and keyboard-edited its fields",
            "Read chronology and relationships",
            "Prepared a new report snapshot",
            "Reviewed measured team performance",
            "Keyboard opened and dismissed mobile navigation",
        ]
    (ARTIFACTS / f"{phase}-{language}-review.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_response_allowance_summary_stays_readable_without_horizontal_scroll(app, language):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with review_session(app, language, "interface-sla-readability") as (analyst, j, result):
        j.login("manager@socify.local")
        j.page.goto(analyst.case_url)
        j.settle()
        j.click("link", "الاستجابة والتصعيد")
        for state in ("unconfigured", "configured"):
            if state == "configured":
                form = j.page.locator("form").filter(has=j.page.locator("input[name=minutes]"))
                form.locator("input[name=minutes]").fill("120")
                choose(j, form, "mode", j.page.evaluate("autopsyLabel('business')"))
                form.locator("[name=reason]").fill("Agreed response window for the investigation")
                j.click("button", "حفظ", form)
            summary = j.page.locator(".sla-summary")
            expect(summary).to_contain_text(j.text("المهلة جارية" if state == "configured" else "لم تُحدد المهلة"))
            for theme in ("dark", "light"):
                appearance(j, language, theme)
                for width in (1440, 390):
                    j.page.set_viewport_size({"width": width, "height": 1000})
                    bounds = summary.evaluate("el => ({available:el.clientWidth,content:el.scrollWidth})")
                    assert bounds["content"] <= bounds["available"] + 1, bounds
                    assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                    result.setdefault("summary_widths", []).append({"state": state, "theme": theme, "width": width, **bounds})
                    target = ARTIFACTS / f"sla-{language}-{state}-{theme}-{width}.png"
                    summary.screenshot(path=str(target), animations="disabled")
                    result.setdefault("screenshots", []).append(str(target))
                    if state == "configured" and theme == "dark":
                        page_target = ARTIFACTS / f"sla-{language}-page-{width}.png"
                        j.page.screenshot(path=str(page_target), full_page=True, animations="disabled")
                        result["screenshots"].append(str(page_target))
            assert_accessible(j.page)
        result["scope"] = "SLA layout regression within the live case page, two languages; states and appearances are not new users."
    (ARTIFACTS / f"sla-{language}-review.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
