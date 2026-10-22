import json
import sys
import types

import pytest

import socify.ingestion as ingestion
from socify.db import get_db
from socify.schema import ensure_schema


def test_import_recovers_from_committed_chunk_without_duplicate_effects(app, client, login_as, monkeypatch):
    login_as("analyst")
    records = [json.dumps({"source": "chunk-recovery", "event_type": "chunk_event", "severity": "low", "title": f"Row {index}"}) for index in range(101)]
    content = "\n".join(records)
    queued = client.post("/api/imports?defer=1", json={"filename": "chunked.jsonl", "format": "jsonl", "content": content})
    assert queued.status_code == 202
    job_id = queued.json["id"]
    original = ingestion.ingest_event
    calls = 0

    def interrupt_after_checkpoint(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 101:
            raise RuntimeError("simulated worker interruption")
        return original(*args, **kwargs)

    with app.app_context():
        monkeypatch.setattr(ingestion, "ingest_event", interrupt_after_checkpoint)
        with pytest.raises(RuntimeError, match="simulated worker interruption"):
            ingestion._process_job(job_id)
        checkpoint = get_db().execute("SELECT status, checkpoint, accepted FROM ingestion_jobs WHERE id = ?", (job_id,)).fetchone()
        assert tuple(checkpoint) == ("processing", 100, 100)
        assert get_db().execute("SELECT COUNT(*) FROM security_events WHERE source = 'chunk-recovery'").fetchone()[0] == 100
        ensure_schema(get_db())
        assert get_db().execute("SELECT status FROM ingestion_jobs WHERE id = ?", (job_id,)).fetchone()[0] == "interrupted"
        monkeypatch.setattr(ingestion, "ingest_event", original)
    resumed = client.post(f"/api/imports/{job_id}/resume")
    assert resumed.status_code == 200
    assert resumed.json["status"] == "completed"
    assert resumed.json["checkpoint"] == 101
    assert resumed.json["accepted"] == 101
    assert client.get("/api/events?source=chunk-recovery&page_size=200").json["total"] == 101


@pytest.mark.parametrize(
    "mutation",
    [
        {"evidence_ciphertext": None},
        {"evidence_ciphertext": "invalid-ciphertext"},
        {"raw_size": 999999},
    ],
)
def test_import_evidence_integrity_failure_is_redacted_and_persisted(client, login_as, database, mutation):
    login_as("analyst")
    suffix = next(iter(mutation)) + str(mutation[next(iter(mutation))])
    content = json.dumps({"source": "integrity-fixture", "event_type": suffix, "severity": "low", "title": "Integrity check"})
    queued = client.post("/api/imports?defer=1", json={"filename": f"{suffix}.json", "format": "json", "content": content})
    assert queued.status_code == 202
    field, value = next(iter(mutation.items()))
    database.execute(f"UPDATE ingestion_jobs SET {field} = ? WHERE id = ?", (value, queued.json["id"]))
    evidence = client.get(f"/api/imports/{queued.json['id']}/evidence")
    assert evidence.status_code == 409
    assert evidence.json["error"]["code"] == "IMPORT_EVIDENCE_INVALID"
    failed = client.post(f"/api/imports/{queued.json['id']}/resume")
    assert failed.status_code == 200
    assert failed.json["status"] == "failed"
    detail = client.get(f"/api/imports/{queued.json['id']}")
    assert detail.json["errors"][-1]["error_code"] == "JOB_FAILURE"
    assert content not in detail.get_data(as_text=True)


def test_import_write_operations_require_job_ownership(client, login_as, database, user_ids):
    login_as("analyst")
    queued = client.post("/api/imports?defer=1", json={"filename": "ownership.json", "format": "json", "content": '{"title":"Owned job"}'})
    database.execute("UPDATE ingestion_jobs SET created_by = ? WHERE id = ?", (user_ids["instructor"], queued.json["id"]))
    assert client.get(f"/api/imports/{queued.json['id']}").status_code == 200
    assert client.post(f"/api/imports/{queued.json['id']}/resume").status_code == 404
    assert client.post(f"/api/imports/{queued.json['id']}/cancel").status_code == 404


def test_processing_import_observes_concurrent_cancel_request(app, client, login_as, monkeypatch):
    login_as("analyst")
    content = '{"source":"cancel-race","event_type":"cancel_event","severity":"low","title":"Cancel race"}'
    queued = client.post("/api/imports?defer=1", json={"filename": "cancel-race.jsonl", "format": "jsonl", "content": content})
    job_id = queued.json["id"]
    original = ingestion.ingest_event

    def request_cancel(*args, **kwargs):
        result = original(*args, **kwargs)
        get_db().execute("UPDATE ingestion_jobs SET status = 'cancel_requested' WHERE id = ?", (job_id,))
        return result

    with app.app_context():
        monkeypatch.setattr(ingestion, "ingest_event", request_cancel)
        result = ingestion._process_job(job_id)
        assert result["status"] == "cancelled"


def test_evtx_adapter_normalizes_records_without_executing_uploaded_content(app, client, login_as, monkeypatch):
    class FakeRecord:
        def xml(self):
            return '<Event><System><EventID>1</EventID><Computer>training-host</Computer><TimeCreated SystemTime="2026-10-22T10:00:00Z"/></System><EventData><Data Name="Image">training.exe</Data></EventData></Event>'

    class FakeEvtx:
        def __init__(self, path):
            self.path = path

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def records(self):
            return [FakeRecord()]

    module = types.ModuleType("Evtx.Evtx")
    module.Evtx = FakeEvtx
    monkeypatch.setitem(sys.modules, "Evtx.Evtx", module)
    with app.app_context():
        format_name, records = ingestion.parse_records("training.evtx", b"synthetic-evtx-fixture", "evtx", "windows-training")
        parsed = list(records)
    assert format_name == "evtx"
    assert parsed[0]["event_type"] == "sysmon_1"
    assert parsed[0]["hostname"] == "training-host"
    assert parsed[0]["idempotency_key"].startswith("import:")
    login_as("analyst")
    queued = client.post("/api/imports?defer=1", json={"filename": "training.evtx", "format": "evtx", "content": "synthetic-evtx-fixture"})
    assert queued.status_code == 202
    assert queued.json["estimated_total"] == 0
    xml = '<Events><Event><System><EventID>1</EventID><Computer>training-host</Computer></System></Event></Events>'
    sysmon = client.post("/api/imports?defer=1", json={"filename": "training.xml", "format": "sysmon_xml", "content": xml})
    assert sysmon.status_code == 202
    assert sysmon.json["estimated_total"] == 1
