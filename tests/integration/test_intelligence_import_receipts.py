"""Intelligence retry receipts retain the immutable import and its access boundary."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Barrier

import pytest

PATH = "/api/autopsy/intelligence"
KEY = {"Idempotency-Key": "intelligence-import-001"}
BODY = {
    "name": "Reviewed indicators",
    "version": "1",
    "source": "Internal review",
    "license": "Internal use",
    "expires_at": "2030-01-01T00:00:00Z",
    "format": "flat",
    "content": [{"type": "ip", "value": "192.0.2.48", "verdict": "suspicious"}],
}


def counts(database):
    return [
        database.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        for table in ("autopsy_intel_bundles", "autopsy_intel_entries", "intelligence_import_receipts")
    ]


def test_replay_preserves_later_activation_and_does_not_add_entries(client, login_as, database):
    login_as("soc_manager")
    first = client.post(PATH, json=BODY, headers=KEY)
    assert first.status_code == 201
    assert client.post(f"{PATH}/{first.json['id']}/activate").status_code == 200
    before = counts(database)
    assert client.post(PATH, json=dict(reversed(list(BODY.items()))), headers=KEY).json == first.json
    assert counts(database) == before
    assert client.get(PATH).json["items"][0]["active"] == 1
    assert client.post(PATH, json=BODY, headers={"Idempotency-Key": "another-import-002"}).status_code == 409
    assert counts(database) == before


@pytest.mark.parametrize(
    "change",
    [
        {"version": "2"},
        {"source": "Other provenance"},
        {"license": "Other licence"},
        {"content": [{"type": "ip", "value": "192.0.2.49"}]},
        {"expires_at": "2031-01-01T00:00:00Z"},
    ],
)
def test_same_key_cannot_replace_the_bound_import(client, login_as, database, change):
    login_as("soc_manager")
    assert client.post(PATH, json=BODY, headers=KEY).status_code == 201
    before = counts(database)
    response = client.post(PATH, json={**BODY, **change}, headers=KEY)
    assert response.status_code == 409 and response.json["error"]["code"] == "INTELLIGENCE_REQUEST_CONFLICT"
    assert counts(database) == before


@pytest.mark.parametrize("key", ["", "short", "x" * 129, "key with spaces"])
def test_invalid_retry_keys_do_not_import(client, login_as, database, key):
    login_as("soc_manager")
    before = counts(database)
    assert client.post(PATH, json=BODY, headers={"Idempotency-Key": key}).status_code == 422
    assert counts(database) == before


def test_failed_import_does_not_consume_a_key(client, login_as, database):
    login_as("soc_manager")
    assert client.post(PATH, json={**BODY, "content": []}, headers=KEY).status_code == 422
    assert counts(database) == [0, 0, 0]
    assert client.post(PATH, json=BODY, headers=KEY).status_code == 201


def test_retry_requires_current_permission(client, login_as, database, user_ids):
    login_as("soc_manager")
    first = client.post(PATH, json=BODY, headers=KEY)
    database.execute("UPDATE users SET role='analyst' WHERE id=?", (user_ids["soc_manager"],))
    denied = client.post(PATH, json=BODY, headers=KEY)
    assert denied.status_code == 403 and "sha256" not in denied.json
    database.execute("UPDATE users SET role='soc_manager' WHERE id=?", (user_ids["soc_manager"],))
    assert client.post(PATH, json=BODY, headers=KEY).json == first.json


def test_receipt_is_scoped_to_workspace_and_author(client, login_as, database, user_ids):
    login_as("soc_manager")
    first = client.post(PATH, json=BODY, headers=KEY)
    login_as("admin")
    assert client.post(PATH, json=BODY, headers=KEY).status_code == 409
    second = client.post(PATH, json={**BODY, "version": "2"}, headers=KEY)
    assert second.status_code == 201 and second.json["id"] != first.json["id"]
    database.execute("INSERT INTO training_workspaces(id,name,public_id,created_at) VALUES (99,'Other team','intel-other','2026-11-03T00:00:00Z')")
    database.execute("UPDATE users SET workspace_id=99 WHERE id=?", (user_ids["admin"],))
    with client.session_transaction() as session:
        session["workspace_id"] = 99
    third = client.post(PATH, json=BODY, headers=KEY)
    assert third.status_code == 201 and third.json["id"] not in {first.json["id"], second.json["id"]}
    assert database.execute("SELECT workspace_id FROM autopsy_intel_bundles WHERE id=?", (third.json["id"],)).fetchone()[0] == 99


def test_import_and_receipt_rollback_together(client, login_as, database):
    login_as("soc_manager")
    before = counts(database)
    database.execute("CREATE TRIGGER fail_intel_receipt BEFORE INSERT ON intelligence_import_receipts BEGIN SELECT RAISE(ABORT,'receipt unavailable'); END")
    with pytest.raises(sqlite3.IntegrityError, match="receipt unavailable"):
        client.post(PATH, json=BODY, headers=KEY)
    assert counts(database) == before
    database.execute("DROP TRIGGER fail_intel_receipt")
    assert client.post(PATH, json=BODY, headers=KEY).status_code == 201


def test_concurrent_retries_commit_once(app, database, user_ids, monkeypatch):
    from socify import autopsy_intel

    barrier = Barrier(2)
    original = autopsy_intel.convert_intelligence

    def convert_together(content, format_name):
        result = original(content, format_name)
        barrier.wait(timeout=10)
        return result

    monkeypatch.setattr(autopsy_intel, "convert_intelligence", convert_together)

    def submit(_):
        with app.test_client() as client:
            with client.session_transaction() as session:
                session["user_id"] = user_ids["soc_manager"]
                session["workspace_id"] = 1
            response = client.post(PATH, json=BODY, headers=KEY)
            return response.status_code, response.json

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(submit, range(2)))
    assert results[0] == results[1] and results[0][0] == 201
    assert counts(database) == [1, 1, 1]


def test_acknowledging_a_saved_import_does_not_renew_expired_intelligence(client, login_as, monkeypatch):
    from socify import autopsy_intel

    login_as("soc_manager")
    first = client.post(PATH, json=BODY, headers=KEY)

    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2032, 1, 1, tzinfo=UTC)

    monkeypatch.setattr(autopsy_intel, "datetime", Later)
    monkeypatch.setattr(autopsy_intel, "utc_now", Later.now)
    assert client.post(PATH, json=BODY, headers=KEY).json == first.json
    assert client.post(f"{PATH}/{first.json['id']}/activate").status_code == 409
    assert client.post(PATH, json={**BODY, "version": "2"}).status_code == 422
