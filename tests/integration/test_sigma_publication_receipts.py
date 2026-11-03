"""Transport retries are one publication, not a new detection deployment."""

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from tests.integration.test_autopsy_intelligence_detection import FIXTURES, SIGMA

BODY = {"source": SIGMA, "fixtures": FIXTURES, "reason": "Reviewed expected gateway matches"}
PATH = "/api/autopsy/sigma/publish"
KEY = {"Idempotency-Key": "gateway-publication-001"}


def counts(database):
    return [
        database.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        for table in ("rules", "rule_versions", "autopsy_sigma_sources", "security_audit_logs", "sigma_publication_receipts")
    ]


def test_receipt_replays_original_even_after_a_later_publication(client, login_as, database):
    login_as("soc_manager")
    original = client.post(PATH, json=BODY, headers=KEY)
    assert original.status_code == 201
    updated = client.post(PATH, json={**BODY, "rule_id": original.json["id"], "version": 1})
    assert updated.status_code == 201 and updated.json["version"] == 2
    before = counts(database)
    replay = client.post(PATH, json=dict(reversed(list(BODY.items()))), headers=KEY)
    assert replay.status_code == 201 and replay.json == original.json
    assert counts(database) == before
    assert database.execute("SELECT version FROM rules WHERE id=?", (original.json["id"],)).fetchone()[0] == 2


@pytest.mark.parametrize(
    "change",
    [{"reason": "A different decision"}, {"source": SIGMA + "\n"}, {"version": 2}, {"fixtures": {**FIXTURES, "negative": [{"title": "Different routine"}]}}],
)
def test_same_key_cannot_be_used_for_a_different_operation(client, login_as, database, change):
    login_as("soc_manager")
    assert client.post(PATH, json=BODY, headers=KEY).status_code == 201
    before = counts(database)
    response = client.post(PATH, json={**BODY, **change}, headers=KEY)
    assert response.status_code == 409 and response.json["error"]["code"] == "RULE_REQUEST_CONFLICT"
    assert counts(database) == before


@pytest.mark.parametrize("key", ["", "short", "x" * 129, "key with spaces"])
def test_invalid_keys_do_not_publish(client, login_as, database, key):
    login_as("soc_manager")
    before = counts(database)
    assert client.post(PATH, json=BODY, headers={"Idempotency-Key": key}).status_code == 422
    assert counts(database) == before


def test_error_does_not_consume_a_key_and_acknowledged_new_intent_is_allowed(client, login_as, database):
    login_as("soc_manager")
    assert client.post(PATH, json={**BODY, "fixtures": {"positive": [], "negative": []}}, headers=KEY).status_code == 422
    first = client.post(PATH, json=BODY, headers=KEY)
    second = client.post(PATH, json=BODY, headers={"Idempotency-Key": "gateway-new-publication-002"})
    assert first.status_code == second.status_code == 201
    assert first.json["id"] != second.json["id"]
    assert database.execute("SELECT COUNT(*) FROM sigma_publication_receipts").fetchone()[0] == 2


def test_replay_still_requires_the_authors_current_permission(client, login_as, database, user_ids):
    login_as("soc_manager")
    first = client.post(PATH, json=BODY, headers=KEY)
    database.execute("UPDATE users SET role='analyst' WHERE id=?", (user_ids["soc_manager"],))
    response = client.post(PATH, json=BODY, headers=KEY)
    assert response.status_code == 403 and "compiled" not in response.json
    database.execute("UPDATE users SET role='soc_manager' WHERE id=?", (user_ids["soc_manager"],))
    assert client.post(PATH, json=BODY, headers=KEY).json == first.json


def test_keys_are_scoped_to_workspace_and_author(client, login_as, database, user_ids):
    login_as("soc_manager")
    first = client.post(PATH, json=BODY, headers=KEY)
    login_as("admin")
    second = client.post(PATH, json=BODY, headers=KEY)
    assert second.status_code == 201 and second.json["id"] != first.json["id"]
    database.execute("INSERT INTO training_workspaces(id,name,public_id,created_at) VALUES (99,'Other team','receipt-other','2026-11-03T00:00:00Z')")
    database.execute("UPDATE users SET workspace_id=99 WHERE id=?", (user_ids["admin"],))
    with client.session_transaction() as session:
        session["workspace_id"] = 99
    third = client.post(PATH, json=BODY, headers=KEY)
    assert third.status_code == 201 and third.json["id"] not in {first.json["id"], second.json["id"]}
    assert database.execute("SELECT workspace_id FROM rules WHERE id=?", (third.json["id"],)).fetchone()[0] == 99


def test_receipt_and_publication_rollback_together(client, login_as, database):
    login_as("soc_manager")
    before = counts(database)
    database.execute("CREATE TRIGGER fail_receipt BEFORE INSERT ON sigma_publication_receipts BEGIN SELECT RAISE(ABORT,'receipt unavailable'); END")
    with pytest.raises(sqlite3.IntegrityError, match="receipt unavailable"):
        client.post(PATH, json=BODY, headers=KEY)
    assert counts(database) == before
    database.execute("DROP TRIGGER fail_receipt")
    assert client.post(PATH, json=BODY, headers=KEY).status_code == 201


def test_concurrent_retries_commit_and_audit_once(app, database, user_ids, monkeypatch):
    from socify import autopsy_detection

    barrier = Barrier(2)
    original = autopsy_detection.compile_sigma

    def compile_together(source):
        result = original(source)
        barrier.wait(timeout=10)
        return result

    monkeypatch.setattr(autopsy_detection, "compile_sigma", compile_together)

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
    assert database.execute("SELECT COUNT(*) FROM autopsy_sigma_sources").fetchone()[0] == 1
    assert database.execute("SELECT COUNT(*) FROM security_audit_logs WHERE resource_type='sigma_rule' AND action='publish'").fetchone()[0] == 1
    receipt = database.execute("SELECT response FROM sigma_publication_receipts").fetchone()[0]
    assert json.loads(receipt) == results[0][1]


def test_recovery_uses_the_committed_result_when_the_compiler_changes(client, login_as, monkeypatch):
    login_as("soc_manager")
    original = client.post(PATH, json=BODY, headers=KEY)

    def unavailable(_):
        raise ValueError("New compiler rejects this old source")

    monkeypatch.setattr("socify.autopsy_detection.compile_sigma", unavailable)
    recovered = client.post(PATH, json=BODY, headers=KEY)
    assert recovered.status_code == 201 and recovered.json == original.json
    assert client.post(PATH, json=BODY, headers={"Idempotency-Key": "new-operation-after-change"}).status_code == 422


def test_recovery_at_capacity_does_not_consume_another_slot(client, login_as, database):
    login_as("soc_manager")
    original = client.post(PATH, json=BODY, headers=KEY)
    for _ in range(100):
        response = client.post(PATH, json=BODY)
        if response.status_code == 409:
            assert response.json["error"]["code"] == "RULE_CAPACITY"
            break
    else:
        pytest.fail("The active-rule limit was not enforced")
    before = counts(database)
    recovered = client.post(PATH, json=BODY, headers=KEY)
    assert recovered.status_code == 201 and recovered.json == original.json
    assert counts(database) == before
