import hashlib

from socify.schema import ensure_schema


def test_repeated_worker_startup_repairs_only_missing_metadata_and_preserves_case_history(autopsy_case, client, database):
    base = f"/api/cases/{autopsy_case}"
    imported = client.post(
        base + "/imports", json={"filename": "startup.json", "content": '[{"title":"Stable retained evidence"},{"title":"Legacy missing digest"}]'}
    )
    assert imported.status_code == 201
    events = client.get(base + "/logs").json["items"]
    legacy = next(event for event in events if event["title"] == "Legacy missing digest")
    database.execute("UPDATE security_events SET raw_hash=NULL WHERE id=?", (legacy["id"],))
    before_version = client.get(base).json["version"]
    before_rows = {
        row["id"]: dict(row)
        for row in database.execute("SELECT e.* FROM security_events e JOIN case_events ce ON ce.event_id=e.id WHERE ce.case_id=?", (autopsy_case,))
    }
    before_custody = client.get(base + "/custody").json
    database.execute(
        "CREATE TRIGGER startup_preserve_complete_evidence BEFORE UPDATE ON security_events WHEN old.raw_hash IS NOT NULL BEGIN SELECT RAISE(ABORT,'Startup rewrote valid evidence'); END"
    )
    ensure_schema(database)
    ensure_schema(database)
    for row in database.execute("SELECT e.* FROM security_events e JOIN case_events ce ON ce.event_id=e.id WHERE ce.case_id=?", (autopsy_case,)):
        expected = before_rows[row["id"]]
        if row["id"] == legacy["id"]:
            expected["raw_hash"] = hashlib.sha256(expected["raw_data"].encode()).hexdigest()
        assert dict(row) == expected
    assert client.get(base).json["version"] == before_version
    assert client.get(base + "/custody").json == before_custody
