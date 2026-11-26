"""One bounded wait for tests: check a condition until it holds, never longer than a deadline.

It returns as soon as the condition holds, so a fast system is never slowed down by a fixed sleep. Browser tests pass
`pause=playwright_pause(page)`: Playwright runs route and request handlers only while it has control, so the pause
hands control to it between checks.
"""

import time
from collections.abc import Callable
from typing import Any


def wait_until[T](check: Callable[[], T], timeout: float, *, interval: float = 0.05, pause: Callable[[float], Any] = time.sleep, message: str = "") -> T:
    """Return the first truthy result of check(); raise TimeoutError once `timeout` seconds pass without one."""
    deadline = time.monotonic() + timeout
    while True:
        result = check()
        if result:
            return result
        if time.monotonic() >= deadline:
            raise TimeoutError(message or f"condition not met within {timeout} seconds")
        pause(interval)


def playwright_pause(page) -> Callable[[float], None]:
    """A pause that lets Playwright dispatch events (route handlers, request listeners) while a test waits."""
    return lambda seconds: page.wait_for_timeout(seconds * 1000)
