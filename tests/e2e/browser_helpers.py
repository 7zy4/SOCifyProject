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


def new_page(browser, **kwargs):
    axe_path = Path("node_modules/axe-core/axe.min.js").resolve()
    if not axe_path.exists():
        raise AssertionError("axe-core is required for browser accessibility tests")
    page = browser.new_page(locale="ar-SA", **kwargs)
    page.add_init_script(path=str(axe_path))
    return page


def assert_accessible(page) -> None:
    results = page.evaluate("async () => await axe.run(document, {resultTypes: ['violations']})")
    violations = [item for item in results["violations"] if item["impact"] in {"serious", "critical"}]
    assert not violations, [(item["id"], item["impact"], [node["target"] for node in item["nodes"]]) for item in violations]
