"""Observer resilience checks; these are infrastructure tests, not user journeys."""

import pytest
from playwright.sync_api import Error, sync_playwright

from tests.e2e.test_browser import launch_browser
from tests.e2e.test_review_workflow import ReviewJourney


class MissingCancellationPage:
    """Model an absent old-document cancellation event."""

    def __init__(self, page):
        self.page = page

    def __getattr__(self, name):
        return getattr(self.page, name)

    def on(self, name, callback):
        if name == "requestfailed":
            self.page.on(name, lambda request: callback(request) if "/held-old" not in request.url else None)
        else:
            self.page.on(name, callback)


@pytest.mark.e2e
def test_completed_navigation_retires_only_the_previous_document():
    with sync_playwright() as play:
        browser = launch_browser(play)
        page = browser.new_page()
        held = []
        page.route(
            "https://observer.invalid/**",
            lambda route: held.append(route)
            if "/held-" in route.request.url
            else route.fulfill(body="<main id='workspace' aria-busy='false'>Ready</main>", content_type="text/html"),
        )
        journey = ReviewJourney(MissingCancellationPage(page), "https://observer.invalid", [])
        page.goto("https://observer.invalid/first")
        journey.settle()
        with page.expect_request("**/held-old"):
            page.evaluate("void fetch('/held-old').catch(() => {})")
        page.goto("https://observer.invalid/second")
        journey.settle()
        assert not journey.pending
        assert journey.navigation_retirements == [["/held-old"]]
        with page.expect_request("**/held-current"):
            page.evaluate("void fetch('/held-current')")
        assert any(request.url.endswith("/held-current") for request in journey.pending)
        page.evaluate("history.pushState({}, '', '/same-document')")
        assert any(request.url.endswith("/held-current") for request in journey.pending)
        held[-1].fulfill(body="ok")
        journey.settle()
        assert not journey.pending
        browser.close()


@pytest.mark.e2e
def test_failed_navigation_keeps_the_existing_document_requests():
    with sync_playwright() as play:
        browser = launch_browser(play)
        page = browser.new_page()
        held = []

        def route_request(route):
            if route.request.url.endswith("/failed"):
                route.abort()
            elif route.request.url.endswith("/held-current"):
                held.append(route)
            else:
                route.fulfill(body="<main id='workspace' aria-busy='false'>Ready</main>", content_type="text/html")

        page.route("https://observer.invalid/**", route_request)
        journey = ReviewJourney(page, "https://observer.invalid", [])
        page.goto("https://observer.invalid/first")
        journey.settle()
        with page.expect_request("**/held-current"):
            page.evaluate("void fetch('/held-current')")
        with pytest.raises(Error):
            page.goto("https://observer.invalid/failed")
        assert not journey.navigation_retirements
        # The current document request may be explicitly cancelled by the browser;
        # it must not be retired by a navigation that never committed.
        assert journey.main_navigation is None
        browser.close()
