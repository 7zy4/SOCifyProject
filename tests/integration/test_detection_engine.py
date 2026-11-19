"""The rule engine at the point every producer reaches it: socify.events.ingest_event.

Case imports, source ingestion and capsule imports all store events through this function, so its windowing, grouping,
idempotency and event-time policy are checked here once, without going through any one producer's API.
"""

import json

from socify.db import get_db, transaction
from socify.events import ingest_event
from socify.seeding import _rule

THRESHOLD_RULE = "Five failed logins in ten minutes"


def emit(app, key, **fields):
    with app.app_context(), transaction():
        return ingest_event(get_db(), {"idempotency_key": key, **fields}, None, 1)


def failed_login(app, number, source_ip="198.51.100.20", prefix="login"):
    return emit(
        app,
        f"{prefix}-{source_ip}-{number}",
        source="integration-auth",
        source_type="synthetic",
        severity="medium",
        category="authentication",
        event_type="failed_login",
        title="Synthetic failed login",
        description="Isolated integration event",
        event_time=f"2026-10-19T10:0{number}:00Z",
        source_ip=source_ip,
        username="amina",
        hostname="idp-lab-01",
        action="login",
        outcome="failed",
        raw_payload={"synthetic": True},
    )


def test_failed_login_window_creates_one_explainable_alert(app, database):
    for index in range(1, 5):
        assert failed_login(app, index, prefix="threshold")[1:] == ([], False)
    _, alerts, duplicate = failed_login(app, 5, prefix="threshold")
    assert len(alerts) == 1 and duplicate is False
    alert = database.execute("SELECT * FROM alerts WHERE id = ?", (alerts[0],)).fetchone()
    assert alert["rule_version"] == 1
    assert json.loads(alert["mitre_technique_ids"]) == ["T1110"]
    assert json.loads(alert["trace"])["condition"]["matched"] is True
    assert database.execute("SELECT COUNT(*) FROM alert_events WHERE alert_id = ?", (alerts[0],)).fetchone()[0] == 5


def test_grouping_does_not_mix_source_addresses(app, database):
    for index in range(1, 5):
        assert failed_login(app, index, "198.51.100.20", "group")[1] == []
    assert failed_login(app, 5, "203.0.113.40", "group")[1] == []
    assert database.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0


def test_replayed_event_returns_the_stored_one_and_raises_no_second_alert(app, database):
    for index in range(1, 5):
        failed_login(app, index, prefix="dedup")
    fifth = failed_login(app, 5, prefix="dedup")
    replay = failed_login(app, 5, prefix="dedup")
    assert fifth[2] is False and replay[2] is True
    assert replay[0] == fifth[0]
    assert database.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
    assert database.execute("SELECT COUNT(*) FROM security_events WHERE source = 'integration-auth'").fetchone()[0] == 5


def test_inactive_rule_does_not_detect(app, database):
    database.execute("UPDATE rules SET is_active = 0 WHERE name = ?", (THRESHOLD_RULE,))
    for index in range(1, 6):
        assert failed_login(app, index, prefix="disabled")[1] == []


def test_event_time_watermark_handles_late_out_of_order_and_replayed_events(app, database, user_ids):
    dsl = {
        "condition": {"field": "event_type", "operator": "equals", "value": "watermark_test"},
        "window": {"seconds": 600, "threshold": 2, "group_by": ["source_ip"], "mode": "count", "allowed_lateness_seconds": 60},
    }
    action = json.loads(database.execute("SELECT action_value FROM rules WHERE name = ?", (THRESHOLD_RULE,)).fetchone()[0])
    rule_id = _rule(database, user_ids["admin"], "Event-time watermark policy", "Late and replayed events", dsl, action)

    def at(key, event_time, source_ip="192.0.2.44"):
        return emit(app, key, source="watermark-fixture", event_type="watermark_test", source_ip=source_ip, event_time=event_time, title=key)

    assert at("watermark-newest", "2026-10-20T10:10:00Z")[1] == []
    assert at("watermark-too-late", "2026-10-20T10:00:00Z", "192.0.2.45")[1] == []
    out_of_order = at("watermark-first-out-of-order", "2026-10-20T12:09:00+02:00")
    assert out_of_order[1] == []
    completed = at("watermark-completed", "2026-10-20T10:09:30Z")
    assert len(completed[1]) == 1

    trace = json.loads(database.execute("SELECT trace FROM alerts WHERE id = ?", (completed[1][0],)).fetchone()[0])
    assert trace["policy"] == "event_time_window"
    assert trace["allowed_lateness_seconds"] == 60
    assert trace["late_by_seconds"] == 30
    times = [
        row[0]
        for row in database.execute(
            "SELECT e.event_time FROM alert_events ae JOIN security_events e ON e.id = ae.event_id WHERE ae.alert_id = ? ORDER BY e.event_time",
            (completed[1][0],),
        )
    ]
    assert times == ["2026-10-20T10:09:00Z", "2026-10-20T10:09:30Z"]

    assert at("watermark-completed", "2026-10-20T10:09:30Z")[2] is True
    assert at("watermark-overlapping", "2026-10-20T10:09:45Z")[1] == []
    assert database.execute("SELECT COUNT(*) FROM alerts WHERE rule_id = ?", (rule_id,)).fetchone()[0] == 1
    assert database.execute("SELECT suppressions FROM rules WHERE id = ?", (rule_id,)).fetchone()[0] == 1
    event = database.execute("SELECT event_time, ingested_at FROM security_events WHERE id = ?", (out_of_order[0],)).fetchone()
    assert event["event_time"] == "2026-10-20T10:09:00Z"
    assert event["ingested_at"] != event["event_time"]
