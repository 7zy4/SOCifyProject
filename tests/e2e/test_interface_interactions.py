"""Keyboard, touch-sized controls and visual identity on the operational interface."""

import json
from pathlib import Path

import pytest
from playwright.sync_api import expect

from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_review_workflow import review_session

ARTIFACTS = Path("artifacts/interface-interactions")


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("motion", ["no-preference", "reduce"])
def test_interface_interactions(app, language, theme, motion):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    name = f"interface-{theme}-{motion}"
    with review_session(app, language, name) as (j, _manager, result):
        page = j.page
        page.emulate_media(reduced_motion=motion)
        if page.locator("html").get_attribute("lang") != language:
            page.locator("[data-language-toggle]").click()
            j.settle()
        page.locator(f'[data-theme-option="{theme}"]').click()
        prefix = f"{name}-{language}"
        menu = page.locator("#menu-toggle")
        sidebar = page.locator("#workspace-navigation")
        for width in (320, 390, 768, 1099, 1100, 1440):
            page.set_viewport_size({"width": width, "height": 844})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), width
            if width < 1100:
                expect(menu).to_be_visible()
                menu.click()
                expect(menu).to_have_attribute("aria-expanded", "true")
                expect(sidebar).to_be_visible()
                box = menu.bounding_box()
                assert box["width"] >= 43.99 and box["height"] >= 43.99
                assert sidebar.bounding_box()["y"] >= box["y"] + box["height"]
                # The same button must stay reachable while the drawer is open.
                menu.click()
                expect(sidebar).not_to_be_visible()
            else:
                expect(menu).not_to_be_visible()
                expect(sidebar).to_be_visible()
        page.set_viewport_size({"width": 390, "height": 844})
        page.screenshot(animations="disabled", path=str(ARTIFACTS / f"{prefix}-header.png"))
        menu.focus()
        menu.press("ArrowDown")
        expect(page.locator("#primary-nav a").first).to_be_focused()
        page.screenshot(animations="disabled", path=str(ARTIFACTS / f"{prefix}-navigation.png"))
        assert_accessible(page)
        page.keyboard.press("Escape")
        expect(menu).to_be_focused()
        expect(sidebar).not_to_be_visible()
        menu.click()
        page.locator(".navigation-shade").click(position={"x": 10 if language == "ar" else 350, "y": 400})
        expect(menu).to_have_attribute("aria-expanded", "false")
        menu.click()
        page.set_viewport_size({"width": 1440, "height": 844})
        expect(page.locator(".navigation-shade")).not_to_be_visible()
        page.set_viewport_size({"width": 390, "height": 844})
        expect(sidebar).not_to_be_visible()
        page.locator(".account-menu summary").click()
        page.screenshot(animations="disabled", path=str(ARTIFACTS / f"{prefix}-account.png"))
        assert_accessible(page)
        page.keyboard.press("Escape")
        expect(page.locator(".account-menu summary")).to_be_focused()
        page.locator(".account-menu summary").press("Enter")
        page.locator(".language-toggle").focus()
        expect(page.locator(".account-popover")).not_to_be_visible()
        page.set_viewport_size({"width": 1440, "height": 1000})
        control = page.locator(".choice-control").first
        control.locator(".choice-toggle").click()
        expect(control.locator(".choice-toggle")).to_have_attribute("aria-expanded", "true")
        page.screenshot(animations="disabled", path=str(ARTIFACTS / f"{prefix}-choice.png"))
        control.locator("input").press("ArrowDown")
        expect(control.get_by_role("option").first).to_be_focused()
        page.keyboard.press("End")
        expect(control.get_by_role("option").last).to_be_focused()
        page.keyboard.press("Home")
        expect(control.get_by_role("option").first).to_be_focused()
        page.keyboard.press("Escape")
        expect(control.locator("input")).to_be_focused()
        expect(control.locator(".choice-menu")).not_to_be_visible()
        page.set_viewport_size({"width": 390, "height": 844})
        control.locator(".choice-toggle").click()
        page.screenshot(animations="disabled", path=str(ARTIFACTS / f"{prefix}-choice-mobile.png"))
        control.get_by_role("option").last.focus()
        expect(control.get_by_role("option").last).to_be_in_viewport()
        page.keyboard.press("Escape")
        page.set_viewport_size({"width": 1440, "height": 1000})
        j.click("link", "التقارير والمراجعة")
        field = page.locator("main select").first
        options = field.locator("option").evaluate_all("items => items.filter(x => !x.disabled).map(x => x.value)")
        field.click()
        page.screenshot(animations="disabled", path=str(ARTIFACTS / f"{prefix}-select.png"))
        page.keyboard.press("End")
        page.keyboard.press("Enter")
        expect(field).to_have_value(options[-1])
        field.click()
        page.keyboard.press("Escape")
        expect(field).to_be_focused()
        for width in (390, 1440):
            page.set_viewport_size({"width": width, "height": 1000})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            assert_accessible(page)
        if motion == "reduce":
            menu_styles = menu.evaluate("e => ({transition: getComputedStyle(e).transitionDuration, animation: getComputedStyle(e).animationName})")
            assert menu_styles == {"transition": "0s", "animation": "none"}
        result["kind"] = "interface acceptance matrix, not new simulated users"
        (ARTIFACTS / f"{prefix}.json").write_text(
            json.dumps(
                {
                    "browser": page.context.browser.version,
                    "base_select": page.evaluate("CSS.supports('appearance', 'base-select')"),
                    "widths": [320, 390, 768, 1099, 1100, 1440],
                    "theme": theme,
                    "motion": motion,
                }
            ),
            encoding="utf-8",
        )
