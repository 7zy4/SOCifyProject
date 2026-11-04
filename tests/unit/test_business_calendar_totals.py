"""Compare aggregated SLA time with the previous daily-window algorithm."""

from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo

import pytest

from socify.autopsy_workflow import _calendar_admission_info, _clear_calendar_cache, _year_work_totals, business_seconds, validate_calendar


def daily_seconds(start, end, calendar):
    """Independent reference retained from the pre-aggregation calculation."""
    if end <= start:
        return 0
    if calendar["mode"] == "24x7":
        return (end - start).total_seconds()
    zone = UTC if calendar["timezone"].upper() in ("UTC", "ETC/UTC") else ZoneInfo(calendar["timezone"])
    day, final = start.astimezone(zone).date(), end.astimezone(zone).date()
    holidays = set(calendar["holidays"])
    total = 0.0
    while day <= final:
        if day.weekday() in calendar["weekdays"] and day.isoformat() not in holidays:
            opening = datetime.combine(day, time(hour=calendar["start_hour"]), zone).replace(fold=0).astimezone(UTC)
            closing = (
                datetime.combine(day + timedelta(days=calendar["end_hour"] // 24), time(hour=calendar["end_hour"] % 24), zone).replace(fold=1).astimezone(UTC)
            )
            left, right = max(start, opening), min(end, closing)
            if right > left:
                total += (right - left).total_seconds()
        day += timedelta(days=1)
    return total


PERIODS = [
    ("2011-12-01T00:30:00+00:00", "2012-02-01T23:45:00+00:00"),
    ("2019-12-15T10:17:42.123456+00:00", "2020-03-02T03:08:17.234567+00:00"),
    ("2025-12-31T23:59:00+00:00", "2026-02-01T00:00:00+00:00"),
    ("2026-01-01T00:00:00+00:00", "2026-01-29T00:00:00+00:00"),
    ("2026-01-01T00:00:00+00:00", "2026-01-30T00:00:00+00:00"),
    ("2026-03-01T06:30:00+00:00", "2026-11-02T06:15:00+00:00"),
]


@pytest.mark.parametrize("period", PERIODS)
@pytest.mark.parametrize("timezone", ["UTC", "America/New_York", "Europe/London", "Australia/Lord_Howe", "Pacific/Apia", "Asia/Riyadh"])
@pytest.mark.parametrize("hours", [(0, 24), (1, 3), (9, 17)])
@pytest.mark.parametrize("weekdays", [[0, 1, 2, 3, 4], list(range(7))])
def test_prefix_totals_match_daily_calendar_across_boundaries(period, timezone, hours, weekdays):
    _clear_calendar_cache()
    calendar = validate_calendar(
        {
            "mode": "business",
            "timezone": timezone,
            "weekdays": weekdays,
            "start_hour": hours[0],
            "end_hour": hours[1],
            "holidays": ["2019-12-25", "2020-02-29", "2026-03-08", "2026-11-01"],
        }
    )
    start, end = map(datetime.fromisoformat, period)
    expected = daily_seconds(start, end, calendar)
    assert business_seconds(start, end, calendar) == pytest.approx(expected, rel=0, abs=0.000001)
    assert business_seconds(start, end, calendar) == pytest.approx(expected, rel=0, abs=0.000001)
    assert business_seconds(end, start, calendar) == 0


def test_calendar_cache_never_mixes_timezones_hours_weekdays_or_holidays():
    _clear_calendar_cache()
    start, end = datetime(2026, 10, 1, 6, 17, tzinfo=UTC), datetime(2026, 11, 30, 18, 43, tzinfo=UTC)
    base = {"mode": "business", "timezone": "America/New_York", "weekdays": list(range(7)), "start_hour": 0, "end_hour": 4, "holidays": []}
    calendars = [
        base,
        {**base, "timezone": "Europe/London"},
        {**base, "start_hour": 1},
        {**base, "end_hour": 3},
        {**base, "weekdays": [0, 1, 2, 3, 4]},
        {**base, "holidays": ["2026-11-01"]},
    ]
    for calendar in [*calendars, *reversed(calendars), base]:
        assert business_seconds(start, end, calendar) == daily_seconds(start, end, calendar)
    assert _year_work_totals.cache_info().hits > 0


def test_calendar_cache_has_a_fixed_memory_bound():
    _clear_calendar_cache()
    for offset in range(150):
        key = ("UTC", (0, 1, 2, 3, 4), 9, 17, ((date(2026, 1, 1) + timedelta(days=offset)).isoformat(),))
        assert len(_year_work_totals(2026, key)) == 366
    assert _year_work_totals.cache_info().maxsize == _year_work_totals.cache_info().currsize == 128
    _clear_calendar_cache()


def test_single_use_calendars_do_not_build_years_and_admission_is_bounded():
    _clear_calendar_cache()
    start, end = datetime(2025, 7, 3, 10, 12, tzinfo=UTC), datetime(2026, 7, 3, 16, 24, tzinfo=UTC)
    calendars = [
        validate_calendar(
            {
                "mode": "business",
                "timezone": "UTC",
                "weekdays": [0, 1, 2, 3, 4],
                "start_hour": 9,
                "end_hour": 17,
                "holidays": [(date(2026, 1, 1) + timedelta(days=offset)).isoformat()],
            }
        )
        for offset in range(160)
    ]
    for calendar in calendars:
        assert business_seconds(start, end, calendar) == daily_seconds(start, end, calendar)
        assert _year_work_totals.cache_info().currsize == 0
        assert _calendar_admission_info()["currsize"] <= 128
    assert _calendar_admission_info() == {"currsize": 128, "maxsize": 128}
    # A reused policy earns the shared-year cache; an evicted first-use policy does not.
    assert business_seconds(start, end, calendars[-1]) == daily_seconds(start, end, calendars[-1])
    assert _year_work_totals.cache_info().misses == _year_work_totals.cache_info().currsize == 2
    before = _year_work_totals.cache_info()
    assert business_seconds(start, end, calendars[0]) == daily_seconds(start, end, calendars[0])
    assert _year_work_totals.cache_info() == before
    _clear_calendar_cache()


def test_calendar_keeps_the_ten_year_limit_and_24x7_behavior():
    start, end = datetime(2000, 1, 1, tzinfo=UTC), datetime(2026, 1, 1, tzinfo=UTC)
    calendar = validate_calendar({"mode": "business", "timezone": "UTC", "weekdays": [0, 1, 2, 3, 4], "start_hour": 9, "end_hour": 17})
    with pytest.raises(ValueError):
        business_seconds(start, end, calendar)
    assert business_seconds(start, end, {"mode": "24x7"}) == (end - start).total_seconds()
