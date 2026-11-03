"""Creation retries retain one authorized case, its tasks and approval history."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

BODY = {"title": "Gateway incident", "reason": "alert_review", "objective": "Determine affected identities and response", "classification": "confidential"}
PATH = "/api/cases"
KEY = {"Idempotency-Key": "case-intake-operation-001"}


@pytest.fixture(autouse=True)
def operational(app, login_as):
    app.config.update(LEGACY_TRAINING_TESTS=False, REQUIRE_CASE_APPROVAL=False, REQUIRE_INVESTIGATION_SELECTION=False)
    login_as("analyst")


def counts(database):
    tables = (
        "incident_cases",
        "case_tasks",
        "autopsy_case_context",
        "case_approvals",
        "autopsy_case_members",
        "case_history",
        "security_audit_logs",
        "outbox_events",
        "case_creation_receipts",
    )
    return [database.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in tables]


@pytest.mark.parametrize("queued", [False, True])
def test_retry_creates_no_second_case_tasks_approval_or_audit(client, database, queued):
    body = {**BODY, **({"assignee": None} if queued else {})}
    first = client.post(PATH, json=body, headers=KEY)
    assert first.status_code == 201, first.json
    before = counts(database)
    retried = client.post(PATH, json=dict(reversed(list(body.items()))), headers=KEY)
    assert retried.status_code == 201 and retried.json["id"] == first.json["id"]
    assert retried.headers["Location"] == first.headers["Location"]
    assert counts(database) == before


@pytest.mark.parametrize("change", [{"title": "Another case"}, {"classification": "restricted"}, {"assignee": None}, {"objective": "A different goal"}])
def test_key_is_bound_to_exact_creation_intent(client, database, change):
    assert client.post(PATH, json=BODY, headers=KEY).status_code == 201
    before = counts(database)
    response = client.post(PATH, json={**BODY, **change}, headers=KEY)
    assert response.status_code == 409 and response.json["error"]["code"] == "CASE_REQUEST_CONFLICT"
    assert counts(database) == before


@pytest.mark.parametrize("key", ["", "short", "x" * 129, "key with space"])
def test_invalid_key_never_creates_a_case(client, database, key):
    before = counts(database)
    assert client.post(PATH, json=BODY, headers={"Idempotency-Key": key}).status_code == 422
    assert counts(database) == before


def test_failed_validation_does_not_consume_key_or_prevent_new_explicit_intent(client):
    assert client.post(PATH, json={**BODY, "title": "x"}, headers=KEY).status_code == 422
    first = client.post(PATH, json=BODY, headers=KEY)
    second = client.post(PATH, json=BODY, headers={"Idempotency-Key": "another-case-intent"})
    assert first.status_code == second.status_code == 201
    assert first.json["id"] != second.json["id"]


def test_creation_api_alias_recovers_the_same_operation(client, database):
    first = client.post(PATH, json=BODY, headers=KEY)
    before = counts(database)
    recovered = client.post("/api/incidents", json=BODY, headers=KEY)
    assert recovered.status_code == 201 and recovered.json["id"] == first.json["id"]
    assert counts(database) == before


def test_recovery_rechecks_permission_and_current_case_membership(client, database, user_ids):
    first = client.post(PATH, json=BODY, headers=KEY)
    identifier = first.json["id"]
    database.execute("UPDATE users SET role='auditor' WHERE id=?", (user_ids["analyst"],))
    assert client.post(PATH, json=BODY, headers=KEY).status_code == 403
    database.execute("UPDATE users SET role='analyst' WHERE id=?", (user_ids["analyst"],))
    database.execute("DELETE FROM autopsy_case_members WHERE case_id=? AND user_id=?", (identifier, user_ids["analyst"]))
    before = counts(database)
    response = client.post(PATH, json=BODY, headers=KEY)
    assert response.status_code == 404 and "title" not in response.json
    assert counts(database) == before
    database.execute(
        "INSERT INTO autopsy_case_members(case_id,user_id,responsibility,assigned_by,assigned_at) VALUES (?,?,'analyst',?,'2026-11-03T00:00:00Z')",
        (identifier, user_ids["analyst"], user_ids["soc_manager"]),
    )
    assert client.post(PATH, json=BODY, headers=KEY).json["id"] == identifier


def test_archived_creation_is_not_replayed_or_recreated(client, database):
    identifier = client.post(PATH, json=BODY, headers=KEY).json["id"]
    database.execute("UPDATE incident_cases SET archived_at='2026-11-03T00:00:00Z' WHERE id=?", (identifier,))
    before = counts(database)
    assert client.post(PATH, json=BODY, headers=KEY).status_code == 404
    assert counts(database) == before


def test_receipt_respects_actor_and_workspace_boundaries(client, login_as, database, user_ids):
    first = client.post(PATH, json=BODY, headers=KEY)
    login_as("soc_manager")
    second = client.post(PATH, json=BODY, headers=KEY)
    assert first.json["id"] != second.json["id"]
    database.execute("INSERT INTO training_workspaces(id,name,public_id,created_at) VALUES (99,'Other','intake-other','2026-11-03T00:00:00Z')")
    database.execute("UPDATE users SET workspace_id=99 WHERE id=?", (user_ids["soc_manager"],))
    with client.session_transaction() as session:
        session["workspace_id"] = 99
    third = client.post(PATH, json=BODY, headers=KEY)
    assert third.status_code == 201 and third.json["workspace_id"] == 99
    assert third.json["id"] not in {first.json["id"], second.json["id"]}


def test_retry_preserves_a_colleagues_claim_and_returns_current_view(client, login_as, user_ids, database):
    body = {**BODY, "assignee": None}
    identifier = client.post(PATH, json=body, headers=KEY).json["id"]
    login_as("soc_manager")
    claimed = client.post(f"/api/cases/{identifier}/claim", json={})
    assert claimed.status_code == 200, claimed.json
    login_as("analyst")
    before = counts(database)
    recovered = client.post(PATH, json=body, headers=KEY)
    assert recovered.status_code == 201 and recovered.json["id"] == identifier
    assert recovered.json["assignee"] == user_ids["soc_manager"]
    assert counts(database) == before


def test_required_approval_survives_retry_and_is_not_reopened(client, app, login_as, database):
    app.config["REQUIRE_CASE_APPROVAL"] = True
    first = client.post(PATH, json=BODY, headers=KEY)
    assert first.json["approval"]["state"] == "pending"
    login_as("soc_manager")
    approved = client.post(f"/api/cases/{first.json['id']}/approval", json={"decision": "approved", "version": 1, "reason": "Authorized intake"})
    assert approved.status_code == 200, approved.json
    login_as("analyst")
    before = counts(database)
    recovered = client.post(PATH, json=BODY, headers=KEY)
    assert recovered.status_code == 201 and recovered.json["approval"]["state"] == "approved"
    assert counts(database) == before


def test_receipt_failure_rolls_back_the_entire_case(client, database):
    before = counts(database)
    database.execute("CREATE TRIGGER fail_case_receipt BEFORE INSERT ON case_creation_receipts BEGIN SELECT RAISE(ABORT,'receipt unavailable'); END")
    with pytest.raises(sqlite3.IntegrityError, match="receipt unavailable"):
        client.post(PATH, json=BODY, headers=KEY)
    assert counts(database) == before
    database.execute("DROP TRIGGER fail_case_receipt")
    assert client.post(PATH, json=BODY, headers=KEY).status_code == 201


def test_simultaneous_creation_retries_commit_once(app, database, user_ids, monkeypatch):
    from socify import cases

    barrier = Barrier(2)
    original = cases._user_valid

    def validate_together(identifier):
        value = original(identifier)
        barrier.wait(timeout=10)
        return value

    monkeypatch.setattr(cases, "_user_valid", validate_together)
    before = counts(database)

    def submit(_):
        with app.test_client() as client:
            with client.session_transaction() as session:
                session["user_id"] = user_ids["analyst"]
                session["workspace_id"] = 1
            response = client.post(PATH, json=BODY, headers=KEY)
            return response.status_code, response.json["id"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(submit, range(2)))
    assert outcomes[0] == outcomes[1] and outcomes[0][0] == 201
    after = counts(database)
    assert after[0] == before[0] + 1 and after[1] == before[1] + 2
    assert after[-1] == before[-1] + 1
