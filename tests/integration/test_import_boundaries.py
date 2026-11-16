import io
import json

import pytest

from socify.seeding import _rule


def test_multipart_import_preserves_source_metrics_and_preview_limit(autopsy_case, client, login_as, database):
    login_as("admin")
    source = client.post("/api/sources", json={"name": "Import regression", "type": "file", "default_case_id": autopsy_case})
    assert source.status_code == 201, source.json
    source = source.json
    login_as("analyst")
    records = [{"event_type": "boundary_event", "title": f"Synthetic row {i}"} for i in range(25)]
    content = json.dumps(records).encode()
    preview = client.post(f"/api/cases/{autopsy_case}/imports/preview", data={"file": (io.BytesIO(content), "events.json"), "source_id": str(source["id"])})
    assert preview.status_code == 200
    assert len(preview.json["preview"]) == 20
    assert database.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 0
    imported = client.post(f"/api/cases/{autopsy_case}/imports", data={"file": (io.BytesIO(content), "events.json"), "source_id": str(source["id"])})
    assert imported.status_code == 201
    assert imported.json["accepted"] == 25
    detail = client.get(f"/api/cases/{autopsy_case}/imports/{imported.json['id']}")
    assert detail.json["errors"] == []
    assert len(client.get(f"/api/cases/{autopsy_case}/imports").json["items"]) == 1
    stored_source = database.execute("SELECT rows_ingested, error_rate, status FROM event_sources WHERE id = ?", (source["id"],)).fetchone()
    assert tuple(stored_source) == (25, 0, "connected")


@pytest.mark.parametrize("suffix", ["", "/preview"])
def test_import_rejects_bad_upload_and_inaccessible_run(autopsy_case, client, suffix):
    path = f"/api/cases/{autopsy_case}/imports{suffix}"
    assert client.post(path, json={}).status_code == 422
    assert client.post(path, data={"other": (io.BytesIO(b"{}"), "events.json")}).status_code == 422
    assert client.post(path, data={"file": (io.BytesIO(b"{}"), "events.json"), "source_id": "bad"}).status_code == 422
    # A case import cannot be steered into a training run: the field is not part of the case contract.
    assert client.post(path, json={"filename": "events.json", "content": "{}", "training_run_id": 99999}).status_code == 422


def test_import_records_validation_and_parse_errors(autopsy_case, client, login_as, database):
    login_as("admin")
    assert client.get(f"/api/cases/{autopsy_case}/imports/99999").status_code == 404
    assert client.post(f"/api/cases/{autopsy_case}/imports", json={"filename": "events.json", "content": "{}", "source_id": 99999}).status_code == 404
    assert client.post(f"/api/cases/{autopsy_case}/imports", json={"filename": "events.json", "content": "{}", "format": "unsupported"}).status_code == 422
    invalid = client.post(f"/api/cases/{autopsy_case}/imports", json={"filename": "invalid.json", "content": '{"severity":"invalid"}'})
    assert invalid.status_code == 201
    assert invalid.json["accepted"] == 0
    assert invalid.json["rejected"] == 1
    assert client.get(f"/api/cases/{autopsy_case}/imports/{invalid.json['id']}").json["errors"][0]["error_code"] == "VALIDATION_ERROR"
    malformed = client.post(f"/api/cases/{autopsy_case}/imports", json={"filename": "malformed.json", "content": "{"})
    assert malformed.status_code == 201
    assert malformed.json["status"] == "completed_with_errors"
    assert client.get(f"/api/cases/{autopsy_case}/imports/{malformed.json['id']}").json["errors"][0]["error_code"] == "PARSE_ERROR"
    assert database.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 0


def test_import_row_budget_is_enforced(autopsy_case, app, client, login_as):
    login_as("admin")
    app.config["MAX_IMPORT_ROWS"] = 1
    result = client.post(f"/api/cases/{autopsy_case}/imports", json={"filename": "limit.json", "content": '[{"title":"First"},{"title":"Second"}]'})
    assert result.status_code == 201
    assert result.json["accepted"] == 1
    assert result.json["rejected"] == 1
    errors = client.get(f"/api/cases/{autopsy_case}/imports/{result.json['id']}").json["errors"]
    assert errors[0]["error_code"] == "ROW_LIMIT"
    assert client.get(f"/api/cases/{autopsy_case}/logs").json["total"] == 1


def test_auto_detection_uses_content_and_sanitizes_filename(autopsy_case, client, login_as, database):
    login_as("admin")
    payload = b'{"source":"content-sniff","event_type":"safe","title":"Content wins"}'
    imported = client.post(
        f"/api/cases/{autopsy_case}/imports",
        data={"file": (io.BytesIO(payload), "../../misleading.evtx"), "format": "auto"},
    )
    assert imported.status_code == 201
    assert imported.json["format"] == "json"
    stored = database.execute("SELECT filename FROM ingestion_jobs WHERE id = ?", (imported.json["id"],)).fetchone()[0]
    assert stored == "misleading.evtx"


def test_accepted_import_runs_detection_and_preserves_explorer_provenance(autopsy_case, client, database, user_ids):
    _rule(
        database,
        user_ids["admin"],
        "Imported pipeline detection",
        "Matches the imported event type",
        {"condition": {"field": "event_type", "operator": "equals", "value": "pipeline_event"}},
        {"severity": "medium"},
    )
    imported = client.post(
        f"/api/cases/{autopsy_case}/imports",
        json={
            "filename": "pipeline.jsonl",
            "format": "jsonl",
            "content": '{"source":"pipeline-import","event_type":"pipeline_event","title":"Pipeline event"}',
        },
    )
    assert imported.status_code == 201
    explorer = client.get(f"/api/cases/{autopsy_case}/logs")
    assert explorer.json["total"] == 1
    event_id = explorer.json["items"][0]["id"]
    raw = client.get(f"/api/cases/{autopsy_case}/logs/{event_id}").json
    assert raw["provenance"]["file_sha256"] == imported.json["content_hash"]
    assert database.execute("SELECT COUNT(*) FROM detection_matches WHERE event_id = ?", (event_id,)).fetchone()[0] == 1


def test_import_timestamps_normalize_or_expose_explicit_assumption(autopsy_case, client, login_as):
    legacy = client.post(
        f"/api/cases/{autopsy_case}/imports/preview",
        json={
            "filename": "legacy.log",
            "format": "syslog",
            "content": "<34>Oct 19 10:00:00 host sshd[1]: Accepted publickey for analyst from 198.51.100.2",
        },
    )
    assert legacy.status_code == 200
    assert legacy.json["preview"][0]["timestamp_assumption"] == "current_year_utc"

    naive = client.post(
        f"/api/cases/{autopsy_case}/imports",
        json={
            "filename": "naive.jsonl",
            "format": "jsonl",
            "content": '{"source":"time-fixture","event_time":"2026-10-19T10:00:00","title":"Naive"}',
        },
    )
    # A case import declares the source timezone (UTC unless stated), so a timestamp without an offset is read in it.
    assert (naive.json["accepted"], naive.json["rejected"]) == (1, 0)
    assert client.get(f"/api/cases/{autopsy_case}/logs").json["items"][0]["event_time"] == "2026-10-19T10:00:00Z"

    unix = client.post(
        f"/api/cases/{autopsy_case}/imports",
        json={
            "filename": "unix.jsonl",
            "format": "jsonl",
            "content": '{"source":"time-fixture","event_time":0,"title":"Unix"}',
        },
    )
    assert unix.json["accepted"] == 1
    assert "1970-01-01T00:00:00Z" in [item["event_time"] for item in client.get(f"/api/cases/{autopsy_case}/logs").json["items"]]
