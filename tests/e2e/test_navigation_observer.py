"""Observer resilience checks; these are infrastructure tests, not user journeys."""

import pytest
from playwright.sync_api import Error, sync_playwright

from tests.e2e.test_browser import launch_browser
from tests.e2e.test_review_workflow import ReviewJourney


class MissingCancellationSession:
    """Model an absent old-document cancellation event."""

    def __init__(self, page):
        self.session = page.context.new_cdp_session(page)
        self.omitted = set()
        self.session.on("Network.requestWillBeSent", lambda event: self.omitted.add(event["requestId"]) if "/held-old" in event["request"]["url"] else None)

    def __getattr__(self, name):
        return getattr(self.session, name)

    def on(self, name, callback):
        if name in {"Network.loadingFailed", "Network.loadingFinished"}:
            self.session.on(name, lambda event: callback(event) if event["requestId"] not in self.omitted else None)
        else:
            self.session.on(name, callback)


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
        journey = ReviewJourney(page, "https://observer.invalid", [], network_session=MissingCancellationSession(page))
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
        original_loaders = dict(journey.network.loaders)
        with page.expect_request("**/held-current"):
            page.evaluate("void fetch('/held-current')")
        with pytest.raises(Error):
            page.goto("https://observer.invalid/failed")
        assert not journey.navigation_retirements
        # The current document request may be explicitly cancelled by the browser;
        # it must not be retired by a navigation that never committed.
        assert journey.network.loaders == original_loaders
        browser.close()


@pytest.mark.e2e
def test_old_document_request_started_during_navigation_is_retired():
    with sync_playwright() as play:
        browser = launch_browser(play)
        page = browser.new_page()
        held = {}

        def route_request(route):
            path = route.request.url.rsplit("/", 1)[-1]
            if path in {"second", "held-old", "held-current"}:
                held[path] = route
            else:
                route.fulfill(body="<main id='workspace' aria-busy='false'>Ready</main>", content_type="text/html")

        page.route("https://observer.invalid/**", route_request)
        journey = ReviewJourney(page, "https://observer.invalid", [], network_session=MissingCancellationSession(page))
        page.goto("https://observer.invalid/first")
        journey.settle()
        with page.expect_request("**/held-old"):
            page.evaluate("setTimeout(() => fetch('/held-old').catch(() => {}), 100); setTimeout(() => { location.href = '/second'; }, 0)")
        held["second"].fulfill(
            body="<main id='workspace' aria-busy='false'>Ready</main><script>fetch('/held-current')</script>",
            content_type="text/html",
        )
        page.wait_for_url("**/second", wait_until="domcontentloaded")
        page.wait_for_timeout(100)
        assert not any(request.url.endswith("/held-old") for request in journey.pending)
        assert any(request.url.endswith("/held-current") for request in journey.pending)
        held["held-current"].fulfill(body="ok")
        journey.settle()
        browser.close()
