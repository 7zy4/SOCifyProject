def test_event_time_watermark_handles_late_out_of_order_and_replayed_events(client, login_as, database):
    login_as("admin")
    rule = client.post(
        "/api/rules",
        json={
            "name": "Event-time watermark policy",
            "dsl": {
                "condition": {"field": "event_type", "operator": "equals", "value": "watermark_test"},
                "window": {
                    "seconds": 600,
                    "threshold": 2,
                    "group_by": ["source_ip"],
                    "mode": "count",
                    "allowed_lateness_seconds": 60,
                },
            },
            "active": True,
        },
    )
    assert rule.status_code == 201

    def emit(key: str, event_time: str, source_ip: str = "192.0.2.44"):
        return client.post(
            "/api/events",
            headers={"Idempotency-Key": key},
            json={
                "source": "watermark-fixture",
                "event_type": "watermark_test",
                "source_ip": source_ip,
                "event_time": event_time,
                "title": key,
            },
        )

    newest = emit("watermark-newest", "2026-10-20T10:10:00Z")
    assert newest.json["detections"] == []
    too_late = emit("watermark-too-late", "2026-10-20T10:00:00Z", "192.0.2.45")
    assert too_late.json["detections"] == []
    first_out_of_order = emit("watermark-first-out-of-order", "2026-10-20T12:09:00+02:00")
    assert first_out_of_order.json["detections"] == []
    completed = emit("watermark-completed", "2026-10-20T10:09:30Z")
    assert len(completed.json["detections"]) == 1

    alert = client.get(f"/api/alerts/{completed.json['detections'][0]}").json
    assert alert["trace"]["policy"] == "event_time_window"
    assert alert["trace"]["allowed_lateness_seconds"] == 60
    assert alert["trace"]["late_by_seconds"] == 30
    assert [event["event_time"] for event in alert["events"]] == ["2026-10-20T10:09:00Z", "2026-10-20T10:09:30Z"]

    replay = emit("watermark-completed", "2026-10-20T10:09:30Z")
    assert replay.json["duplicate"] is True
    overlapping = emit("watermark-overlapping", "2026-10-20T10:09:45Z")
    assert overlapping.json["detections"] == []
    assert database.execute("SELECT COUNT(*) FROM alerts WHERE rule_id = ?", (rule.json["id"],)).fetchone()[0] == 1
    suppressed = database.execute("SELECT suppressions FROM rules WHERE id = ?", (rule.json["id"],)).fetchone()[0]
    assert suppressed == 1
    event = database.execute("SELECT event_time, ingested_at FROM security_events WHERE id = ?", (first_out_of_order.json["id"],)).fetchone()
    assert event["event_time"] == "2026-10-20T10:09:00Z"
    assert event["ingested_at"] != event["event_time"]
