"""Independent calendar properties; generated inputs are not user journeys."""

from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo

import pytest
from hypothesis import given, seed, settings
from hypothesis import strategies as st

from socify.autopsy_workflow import _calendar_admission_info, _clear_calendar_cache, _year_work_totals, business_seconds, validate_calendar
from socify.validation import ValidationError

ZONES = ["UTC", "Etc/UTC", "America/Havana", "America/New_York", "Africa/Casablanca", "Europe/Berlin", "Australia/Lord_Howe", "Asia/Kathmandu"]
ANCHORS = [
    datetime(2012, 2, 29, tzinfo=UTC),
    datetime(2020, 12, 31, tzinfo=UTC),
    datetime(2024, 3, 10, 7, tzinfo=UTC),
    datetime(2024, 4, 7, 15, tzinfo=UTC),
    datetime(2024, 10, 27, 1, tzinfo=UTC),
    datetime(2024, 11, 3, 5, tzinfo=UTC),
    datetime(2026, 2, 15, tzinfo=UTC),
]


def previous_daily_measure(start, end, policy):
    """Daily UTC intersections from the pre-aggregation policy, no new helpers."""
    if end <= start:
        return 0.0
    if policy["mode"] == "24x7":
        return (end - start).total_seconds()
    zone = UTC if policy["timezone"].upper() in {"UTC", "ETC/UTC"} else ZoneInfo(policy["timezone"])
    first, final = start.astimezone(zone).date(), end.astimezone(zone).date()
    if (final - first).days > 3660:
        raise ValidationError("The retained business-calendar interval exceeds 3660 days")
    values = []
    for offset in range((final - first).days + 1):
        local_date = first + timedelta(days=offset)
        if local_date.weekday() not in policy["weekdays"] or local_date.isoformat() in policy["holidays"]:
            continue
        begin = datetime.combine(local_date, time(policy["start_hour"]), zone).replace(fold=0).astimezone(UTC)
        finish = datetime.combine(local_date + timedelta(days=policy["end_hour"] // 24), time(policy["end_hour"] % 24), zone).replace(fold=1).astimezone(UTC)
        if min(end, finish) > max(start, begin):
            values.append((min(end, finish) - max(start, begin)).total_seconds())
    return sum(values)


@st.composite
def calendar_intervals(draw):
    anchor = draw(st.sampled_from(ANCHORS))
    start = anchor + timedelta(seconds=draw(st.integers(-40 * 86400, 40 * 86400)), microseconds=draw(st.integers(0, 999999)))
    days = draw(st.one_of(st.sampled_from([0, 1, 28, 29, 30, 365, 366, 550]), st.integers(0, 550)))
    end = start + timedelta(days=days, seconds=draw(st.integers(0, 86399)), microseconds=draw(st.integers(0, 999999)))
    opening = draw(st.integers(0, 23))
    closing = draw(st.integers(opening + 1, 24))
    timezone = draw(st.sampled_from(ZONES))
    zone = UTC if timezone.upper() in {"UTC", "ETC/UTC"} else ZoneInfo(timezone)
    first = start.astimezone(zone).date()
    holiday_offsets = draw(st.lists(st.integers(-1, days + 1), unique=True, max_size=8))
    policy = validate_calendar(
        {
            "mode": "business",
            "timezone": timezone,
            "weekdays": draw(st.lists(st.integers(0, 6), min_size=1, max_size=7, unique=True)),
            "start_hour": opening,
            "end_hour": closing,
            "holidays": [(first + timedelta(days=offset)).isoformat() for offset in holiday_offsets],
        }
    )
    return start, end, policy


@seed(2026110407)
@given(calendar_intervals())
@settings(max_examples=600, deadline=None)
def test_generated_intervals_match_the_previous_daily_measure(example):
    start, end, policy = example
    _clear_calendar_cache()
    expected = previous_daily_measure(start, end, policy)
    actual = business_seconds(start, end, policy)
    assert actual == pytest.approx(expected, rel=0, abs=0.000001)
    # First and repeated use must agree even when the execution path changes.
    assert business_seconds(start, end, policy) == pytest.approx(expected, rel=0, abs=0.000001)
    # Partitioning the same observation cannot change its counted work duration.
    split = start + (end - start) / 2
    assert actual == pytest.approx(business_seconds(start, split, policy) + business_seconds(split, end, policy), rel=0, abs=0.000001)
    assert business_seconds(end, start, policy) == business_seconds(start, start, policy) == 0


@pytest.mark.parametrize("year,timezone", [(9999, "UTC"), (9999, "Pacific/Kiritimati"), (1, "Asia/Kathmandu")])
def test_valid_interval_does_not_evaluate_unrequested_datetime_boundary_days(year, timezone):
    policy = {"mode": "business", "timezone": timezone, "weekdays": list(range(7)), "start_hour": 0, "end_hour": 24, "holidays": []}
    start, end = datetime(year, 4, 10, 8, 17, tzinfo=UTC), datetime(year, 6, 20, 19, 43, tzinfo=UTC)
    assert business_seconds(start, end, policy) == previous_daily_measure(start, end, policy)


@pytest.mark.parametrize("offset", [3659, 3660, 3661])
def test_long_calendar_guard_is_measured_in_local_dates(offset):
    start = datetime(2010, 1, 1, 12, tzinfo=UTC)
    end = start + timedelta(days=offset)
    policy = {"mode": "business", "timezone": "America/Havana", "weekdays": [1, 3, 5], "start_hour": 1, "end_hour": 24, "holidays": ["2012-02-29"]}
    if offset > 3660:
        with pytest.raises(ValidationError):
            business_seconds(start, end, policy)
    else:
        assert business_seconds(start, end, policy) == previous_daily_measure(start, end, policy)
    assert business_seconds(start, end, {"mode": "24x7", "timezone": "America/Havana"}) == (end - start).total_seconds()


def test_mutated_policy_and_cache_eviction_preserve_independent_results():
    _clear_calendar_cache()
    start, end = datetime(2024, 1, 1, 12, tzinfo=UTC), datetime(2025, 1, 2, 15, tzinfo=UTC)
    policy = {"mode": "business", "timezone": "Africa/Casablanca", "weekdays": [0, 1, 2, 3, 4, 5, 6], "start_hour": 1, "end_hour": 24, "holidays": []}
    original = business_seconds(start, end, policy)
    expected = previous_daily_measure(start, end, policy)
    assert original == expected
    assert _year_work_totals.cache_info().currsize == 0
    for index in range(140):
        # Exercise the public calculator, including mutable per-case policy lists.
        policy["holidays"][:] = [(date(2024, 1, 1) + timedelta(days=index)).isoformat()]
        policy["timezone"] = ZONES[index % len(ZONES)]
        policy["start_hour"] = index % 23
        expected = previous_daily_measure(start, end, policy)
        assert business_seconds(start, end, policy) == expected
        assert business_seconds(start, end, policy) == expected
    info = _year_work_totals.cache_info()
    assert info.currsize == info.maxsize == 128
    assert _calendar_admission_info() == {"currsize": 128, "maxsize": 128}
    policy.update(timezone="Africa/Casablanca", start_hour=1, holidays=[])
    assert business_seconds(start, end, policy) == original
    _clear_calendar_cache()
    assert _year_work_totals.cache_info().currsize == _calendar_admission_info()["currsize"] == 0
