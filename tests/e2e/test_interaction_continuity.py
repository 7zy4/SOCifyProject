"""Keyboard continuity during popup dismissal, reflow and live motion changes."""

import json
from pathlib import Path

import pytest
from playwright.sync_api import expect

from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_review_workflow import review_session

ARTIFACTS = Path("artifacts/interaction-final-review")


def capture(page, name):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(ARTIFACTS / f"{name}.png"), animations="disabled")


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_popup_tab_keeps_the_case_draft_and_keyboard_path(app, language):
    with review_session(app, language, "interaction-popup-tab", create_case=False) as (j, _, result):
        result["kind"] = "interaction acceptance condition, not a new simulated user"
        page = j.page
        page.set_viewport_size({"width": 390, "height": 844})
        j.click("button", "إنشاء قضية")
        dialog = page.get_by_role("dialog")
        title = dialog.locator("input[name=title]")
        title.fill("Keyboard navigation investigation")
        reason = dialog.locator("input[name=reason]")
        original = reason.input_value()
        reason.focus()
        reason.press("ArrowDown")
        page.keyboard.press("End")
        expect(dialog.get_by_role("option").last).to_be_focused()
        capture(page, f"popup-before-tab-{language}")
        page.keyboard.press("Tab")
        expect(dialog.locator("textarea[name=objective]")).to_be_focused()
        expect(reason).to_have_value(original)
        expect(dialog.locator(".choice-menu:visible")).to_have_count(0)
        objective = "Check the retained evidence and record the decision."
        page.keyboard.press("Control+A")
        page.keyboard.type(objective)
        expect(dialog.locator("textarea[name=objective]")).to_have_value(objective)
        reason.focus()
        reason.press("ArrowDown")
        page.keyboard.press("Shift+Tab")
        assert page.evaluate("document.activeElement.checkVisibility()")
        assert dialog.evaluate("el => el.contains(document.activeElement)")
        expect(reason).to_have_value(original)
        # A pointer dismissal must also leave the typed draft intact.
        reason.focus()
        reason.press("ArrowDown")
        dialog.get_by_role("heading").click()
        expect(dialog.locator(".choice-menu:visible")).to_have_count(0)
        expect(title).to_have_value("Keyboard navigation investigation")
        expect(dialog.locator("textarea[name=objective]")).to_have_value(objective)
        assert_accessible(page)
        capture(page, f"popup-after-tab-{language}")
        j.click("button", "حفظ", dialog)
        page.wait_for_url("**/cases/*")
        j.settle()
        expect(page.locator(".case-overview")).to_contain_text(objective)
        result["outcomes"] = [
            "Tab exits options without selecting another value",
            "reverse Tab retains visible focus",
            "outside dismissal preserves the draft",
            "keyboard draft saved through the interface",
        ]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_reflow_focus_and_live_motion_preference_remain_operable(app, language):
    with review_session(app, language, "interaction-reflow-motion", create_case=False) as (j, _, result):
        result["kind"] = "interaction acceptance condition, not a new simulated user"
        page = j.page
        page.locator("#primary-nav a").first.focus()
        page.set_viewport_size({"width": 390, "height": 844})
        menu = page.locator("#menu-toggle")
        expect(menu).to_be_focused()
        expect(page.locator("#workspace-navigation")).not_to_be_visible()
        menu.press("ArrowDown")
        expect(page.locator("#primary-nav a").first).to_be_focused()
        page.keyboard.press("Escape")
        expect(menu).to_be_focused()
        light = page.locator('[data-theme-option="light"]')
        dark = page.locator('[data-theme-option="dark"]')
        system = page.locator('[data-theme-option="system"]')
        page.emulate_media(reduced_motion="no-preference")
        light.focus()
        light.press("Enter")
        dark.focus()
        dark.press("Space")
        page.emulate_media(reduced_motion="reduce")
        expect(dark).to_have_attribute("aria-pressed", "true")
        expect(page.locator("html")).to_have_attribute("data-theme", "dark")
        page.wait_for_function("new DOMMatrix(getComputedStyle(document.querySelector('.theme-switch-thumb')).transform).m41 === 80")
        stopped = page.locator(".theme-switch-thumb").evaluate("e => getComputedStyle(e).transform")
        page.wait_for_timeout(120)
        assert page.locator(".theme-switch-thumb").evaluate("e => getComputedStyle(e).transform") == stopped
        page.emulate_media(color_scheme="light")
        system.focus()
        system.press("Enter")
        expect(page.locator("html")).to_have_attribute("data-theme", "light")
        page.emulate_media(color_scheme="dark")
        expect(page.locator("html")).to_have_attribute("data-theme", "dark")
        expect(system).to_be_focused()
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        assert_accessible(page)
        capture(page, f"reflow-reduced-motion-{language}")
        result["outcomes"] = [
            "focus returns to visible menu after responsive reflow",
            "theme accepts keyboard interruption",
            "live reduced-motion change stops spring at selected theme",
            "system theme updates without losing focus",
        ]
        (ARTIFACTS / f"reflow-motion-{language}.json").write_text(
            json.dumps(
                {"outcomes": result["outcomes"], "browser": page.context.browser.version, "reduced_motion_transform": stopped}, ensure_ascii=False, indent=2
            ),
            encoding="utf-8",
        )


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_current_case_tab_stays_visible_without_moving_the_document(app, language):
    with review_session(app, language, "interaction-current-case-tab") as (j, _, result):
        result["kind"] = "interaction acceptance condition, not a new simulated user"
        page = j.page
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto(f"{j.base}/cases/{j.case_id}?tab=response")
        j.settle()
        if language == "en":
            page.locator('[data-theme-option="light"]').click()
        nav = page.locator(".case-tabs")
        active = nav.locator('[aria-current="page"]')

        def measurements():
            return nav.evaluate("""el => {
                const tab = el.querySelector('[aria-current="page"]');
                const n = el.getBoundingClientRect(), t = tab.getBoundingClientRect();
                return {left:n.left,right:n.right,tabLeft:t.left,tabRight:t.right,
                    scrollLeft:el.scrollLeft,pageY:scrollY,active:document.activeElement.tagName};
            }""")

        values = measurements()
        capture(page, f"current-tab-direct-{language}")
        (ARTIFACTS / f"current-tab-direct-{language}.json").write_text(json.dumps(values, indent=2), encoding="utf-8")
        expect(active).to_contain_text(j.text("الاستجابة والتصعيد"))
        assert values["tabLeft"] >= values["left"] - 1 and values["tabRight"] <= values["right"] + 1, values
        assert values["pageY"] == 0, values
        fonts = json.loads(Path("static/design-tokens.json").read_text(encoding="utf-8"))["fonts"]
        loaded = page.evaluate(
            """async fonts => Promise.all(fonts.map(async font => {
            const weight=font.weight === '700' ? 700 : 400;
            const sample=font.family.includes('Arabic') || font.family === 'Cairo' ? 'عربي' : 'Aa12';
            const faces=await document.fonts.load(`${weight} 16px "${font.family}"`, sample);
            return {family:font.family,file:font.file,statuses:faces.map(face => face.status)};
        }))""",
            fonts,
        )
        assert all(font["statuses"] and all(status == "loaded" for status in font["statuses"]) for font in loaded), loaded
        (ARTIFACTS / f"retained-fonts-loaded-{language}.json").write_text(json.dumps(loaded, indent=2), encoding="utf-8")
        for motion in ("no-preference", "reduce"):
            page.set_viewport_size({"width": 1440, "height": 844})
            page.emulate_media(reduced_motion=motion)
            action = page.locator(".case-content button").first
            action.focus()
            page.evaluate("window.scrollTo({top:0,behavior:'instant'})")
            page.set_viewport_size({"width": 390, "height": 844})
            page.wait_for_function("""() => {
                const el=document.querySelector('.case-tabs');
                const n=el.getBoundingClientRect(),t=el.querySelector('[aria-current="page"]').getBoundingClientRect();
                return t.left>=n.left-1 && t.right<=n.right+1;
            }""")
            expect(action).to_be_focused()
            assert measurements()["pageY"] == 0
            capture(page, f"current-tab-resize-{motion}-{language}")
        assert_accessible(page)
        result["outcomes"] = [
            "current tab visible on a mobile deep link",
            "active tab remains visible after desktop-to-mobile reflow",
            "local tab scrolling preserves document position and keyboard focus",
            "same behavior with reduced motion",
        ]
