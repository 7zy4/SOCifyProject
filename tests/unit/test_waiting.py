"""The shared bounded wait returns as soon as the condition holds and stops at its deadline."""

import pytest

from tests.waiting import wait_until


def test_returns_the_first_truthy_result_without_pausing_after_it():
    results = iter([None, 0, {"state": "done"}])
    pauses = []
    assert wait_until(lambda: next(results), 5, interval=0.25, pause=pauses.append) == {"state": "done"}
    assert pauses == [0.25, 0.25]


def test_raises_after_the_deadline_with_the_message():
    with pytest.raises(TimeoutError, match="never ready"):
        wait_until(lambda: False, 0.05, interval=0.01, message="never ready")
