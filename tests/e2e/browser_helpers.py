"""Browser launch and accessibility helpers shared by the browser journeys."""

import os
import shutil
from pathlib import Path


def launch_browser(playwright):
    channel = os.environ.get("SOCIFY_BROWSER_CHANNEL")
    if channel:
        return playwright.chromium.launch(channel=channel)
    executable = shutil.which("chromium") or shutil.which("google-chrome")
    return playwright.chromium.launch(executable_path=executable) if executable else playwright.chromium.launch()


def account_menu(page):
    """Open the sidebar account menu, which holds the theme and language controls, and return the page."""
    menu = page.locator("details.account-menu")
    if menu.count() and not menu.evaluate("element => element.open"):
        toggle = page.locator("#menu-toggle")
        if toggle.is_visible() and toggle.get_attribute("aria-expanded") != "true":
            toggle.click()
        menu.locator("summary").click()
    return page


def new_page(browser, **kwargs):
    axe_path = Path("node_modules/axe-core/axe.min.js").resolve()
    if not axe_path.exists():
        raise AssertionError("axe-core is required for browser accessibility tests")
    page = browser.new_page(locale="ar-SA", **kwargs)
    page.add_init_script(path=str(axe_path))
    return page


def assert_accessible(page) -> None:
    # Check the settled interface: a menu still fading in reads as low contrast to axe, never to a reader.
    # Endless animations such as spinners are left running.
    page.evaluate(
        """() => Promise.all(document.getAnimations()
            .filter(animation => animation.playState === "running" && animation.effect?.getComputedTiming().endTime !== Infinity)
            .map(animation => animation.finished.catch(() => null)))"""
    )
    results = page.evaluate("async () => await axe.run(document, {resultTypes: ['violations']})")
    violations = [item for item in results["violations"] if item["impact"] in {"serious", "critical"}]
    assert not violations, [(item["id"], item["impact"], [node["target"] for node in item["nodes"]]) for item in violations]
