"""outbox_events fed the training platform's event stream. The stream is gone, so nothing writes the table any more."""

import re
from pathlib import Path

SOCIFY = Path(__file__).resolve().parents[2] / "socify"


def _outbox_rows(database):
    return database.execute("SELECT COUNT(*) FROM outbox_events").fetchone()[0]


def test_no_module_writes_or_reads_outbox_events():
    users = {
        path.name: sorted(set(re.findall(r"(INSERT INTO|FROM|UPDATE)\s+outbox_events", path.read_text(encoding="utf-8"), re.IGNORECASE)))
        for path in SOCIFY.glob("*.py")
        if "outbox_events" in path.read_text(encoding="utf-8")
    }
    # The table stays in the schema for databases that already have it; maintenance only prunes rows written by older versions.
    assert users == {"maintenance.py": ["FROM"], "schema.py": []}
    assert "DELETE FROM outbox_events" in (SOCIFY / "maintenance.py").read_text(encoding="utf-8")


def test_case_work_leaves_the_outbox_empty(autopsy_case, client, database):
    before = _outbox_rows(database)
    assert client.post("/api/cases", json={"title": "Second operational case", "reason": "alert_review", "objective": "Check the outbox"}).status_code == 201
    assert client.post(f"/api/cases/{autopsy_case}/imports", json={"filename": "events.jsonl", "content": '{"title":"Outbox probe"}\n'}).status_code == 201
    assert _outbox_rows(database) == before
    assert client.get("/api/stream/events?once=1").status_code == 410
