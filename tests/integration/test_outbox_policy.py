"""outbox_events is written only where something reads it: the legacy event stream, which operational mode retires."""

import re
from pathlib import Path

from socify.db import get_db
from socify.schema import insert_outbox, outbox_has_reader

SOCIFY = Path(__file__).parents[2] / "socify"


def _outbox_rows(database):
    return database.execute("SELECT COUNT(*) FROM outbox_events").fetchone()[0]


def test_only_the_retired_legacy_stream_reads_outbox_events():
    readers = sorted(path.name for path in SOCIFY.glob("*.py") if re.search(r"FROM\s+outbox_events", path.read_text(encoding="utf-8"), re.IGNORECASE))
    # maintenance.py deletes old rows ("DELETE FROM"); it does not read them for anyone.
    assert readers == ["maintenance.py", "visualization.py"]
    assert "DELETE FROM outbox_events" in (SOCIFY / "maintenance.py").read_text(encoding="utf-8")


def test_operational_mode_writes_no_outbox_events(autopsy_case, app, client, database):
    before = _outbox_rows(database)
    assert client.post("/api/cases", json={"title": "Second operational case", "reason": "alert_review", "objective": "Check the outbox"}).status_code == 201
    assert client.post(f"/api/cases/{autopsy_case}/imports", json={"filename": "events.jsonl", "content": '{"title":"Outbox probe"}\n'}).status_code == 201
    with app.app_context():
        assert outbox_has_reader() is False
        assert insert_outbox(get_db(), 1, "probe.created", {"id": 1}) is None
    assert _outbox_rows(database) == before
    assert client.get("/api/stream/events?once=1").status_code == 410


def test_legacy_training_mode_still_records_outbox_events(app, client, login_as, database, event_payload):
    login_as("analyst")
    before = _outbox_rows(database)
    assert client.post("/api/events", json=event_payload).status_code == 201
    assert _outbox_rows(database) > before
    with app.app_context():
        assert outbox_has_reader() is True


def test_code_without_an_application_keeps_the_previous_behaviour(database):
    before = _outbox_rows(database)
    assert outbox_has_reader() is True
    assert insert_outbox(database, 1, "probe.created", {"id": 1}) is not None
    assert _outbox_rows(database) == before + 1
