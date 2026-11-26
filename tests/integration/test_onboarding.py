"""The first-run checklist: who sees it, what it recognises on its own, manual marks, dismissal and per-user progress."""

import hashlib
import json
import secrets
from datetime import timedelta

import pytest

from scripts.bootstrap_team import create_manager
from socify.timeutils import iso_now, utc_now
from tests.conftest import DEMO_LOGIN_VALUE, issue_session


def _stamp(moment):
    return moment.isoformat().replace("+00:00", "Z")


@pytest.fixture
def new_team(app, client, database):
    """A team created by scripts.bootstrap_team, with its manager signed in; it has no cases yet."""
    manager = create_manager(app, "owner@new-team.example.test", "Team Owner", "New Response Team", DEMO_LOGIN_VALUE)
    workspace = database.execute("SELECT workspace_id FROM users WHERE id = ?", (manager,)).fetchone()[0]

    def sign_in(user_id=manager, role="soc_manager"):
        with client.session_transaction() as state:
            state.clear()
            state.update(user_id=user_id, workspace_id=workspace, user_role=role, session_id=issue_session(app, user_id, workspace))

    sign_in()
    return {"manager": manager, "workspace": workspace, "sign_in": sign_in}


def _items(response):
    return {item["id"]: item for item in response.json["items"]}


def test_only_managers_see_the_checklist_and_change_it(client, login_as):
    login_as("analyst")
    assert client.get("/api/onboarding").json == {"visible": False}
    assert client.put("/api/onboarding/items/attack_catalogue", json={"done": True}).status_code == 403
    assert client.post("/api/onboarding/dismiss", json={}).status_code == 403


def test_a_team_that_already_has_cases_does_not_suddenly_get_a_checklist(client, login_as, autopsy_case):
    login_as("soc_manager")
    assert client.get("/api/onboarding").json["visible"] is False


def test_a_new_team_sees_six_steps_and_keeps_them_after_its_first_case(app, client, database, new_team):
    first = client.get("/api/onboarding")
    assert first.json["visible"] is True and first.json["total"] == 6 and first.json["completed"] == 0
    assert list(_items(first)) == ["invite_team", "first_case", "sla_calendar", "attack_catalogue", "threat_intel", "backups"]
    assert first.json["first_case_id"] is None and first.json["attack_version"]
    created = client.post("/api/cases", json={"title": "First onboarding case", "reason": "alert_review", "objective": "Learn the case flow"})
    assert created.status_code == 201, created.json
    after = client.get("/api/onboarding")
    assert after.json["visible"] is True and _items(after)["first_case"] == {"id": "first_case", "done": True, "detected": True, "marked": False}
    assert after.json["first_case_id"] == created.json["id"]


def test_steps_with_a_trace_tick_themselves(app, client, database, new_team, user_ids):
    workspace = new_team["workspace"]
    database.execute(
        "INSERT INTO team_invitations (workspace_id, email, role, token_hash, created_by, expires_at) VALUES (?, 'analyst@new-team.example.test', 'analyst', ?, ?, ?)",
        (workspace, hashlib.sha256(secrets.token_bytes(16)).hexdigest(), new_team["manager"], _stamp(utc_now() + timedelta(days=1))),
    )
    database.execute(
        "INSERT INTO autopsy_intel_bundles (workspace_id, name, version, source, license, expires_at, payload, sha256, created_by, created_at) VALUES (?, 'Local feed', '1', 'local', 'internal', ?, '{}', ?, ?, ?)",
        (workspace, _stamp(utc_now() + timedelta(days=30)), "0" * 64, new_team["manager"], iso_now()),
    )
    database.execute("INSERT INTO backup_runs (started_at, finished_at, status, encrypted) VALUES (?, ?, 'succeeded', 0)", (iso_now(), iso_now()))
    case = client.post("/api/cases", json={"title": "SLA onboarding case", "reason": "alert_review", "objective": "Set the response policy"}).json["id"]
    database.execute(
        "INSERT INTO autopsy_records (case_id, kind, payload, created_by, updated_by, created_at, updated_at) VALUES (?, 'workflow_sla', ?, ?, ?, ?, ?)",
        (
            case,
            json.dumps({"minutes": 240, "calendar": {"mode": "24x7", "timezone": "Asia/Riyadh"}}),
            new_team["manager"],
            new_team["manager"],
            iso_now(),
            iso_now(),
        ),
    )
    items = _items(client.get("/api/onboarding"))
    assert all(items[name]["detected"] for name in ("invite_team", "first_case", "sla_calendar", "threat_intel", "backups"))
    assert items["attack_catalogue"] == {"id": "attack_catalogue", "done": False, "detected": False, "marked": False}


def test_an_old_backup_does_not_count(client, database, new_team):
    old = _stamp(utc_now() - timedelta(hours=72))
    database.execute("INSERT INTO backup_runs (started_at, finished_at, status, encrypted) VALUES (?, ?, 'succeeded', 0)", (old, old))
    body = client.get("/api/onboarding").json
    assert _items_from(body)["backups"]["done"] is False and body["last_backup_at"] == old


def _items_from(body):
    return {item["id"]: item for item in body["items"]}


def test_manual_marks_are_saved_cleared_and_validated(client, database, new_team):
    marked = client.put("/api/onboarding/items/attack_catalogue", json={"done": True})
    assert marked.status_code == 200 and _items(marked)["attack_catalogue"]["marked"] and marked.json["completed"] == 1
    cleared = client.put("/api/onboarding/items/attack_catalogue", json={"done": False})
    assert not _items(cleared)["attack_catalogue"]["done"]
    assert client.put("/api/onboarding/items/unknown", json={"done": True}).status_code == 404
    for body in ({"done": "yes"}, {}, {"done": True, "extra": 1}):
        assert client.put("/api/onboarding/items/backups", json=body).status_code == 422
    actions = [row[0] for row in database.execute("SELECT action FROM security_audit_logs WHERE action = 'onboarding_step'")]
    assert actions == ["onboarding_step", "onboarding_step"]


def test_finishing_every_step_or_dismissing_hides_the_checklist(client, new_team):
    for item in ("invite_team", "first_case", "sla_calendar", "attack_catalogue", "threat_intel"):
        assert client.put(f"/api/onboarding/items/{item}", json={"done": True}).json["visible"] is True
    assert client.put("/api/onboarding/items/backups", json={"done": True}).json["visible"] is False
    client.put("/api/onboarding/items/backups", json={"done": False})
    assert client.get("/api/onboarding").json["visible"] is True
    assert client.post("/api/onboarding/dismiss", json={}).json["visible"] is False
    assert client.get("/api/onboarding").json["visible"] is False


def test_progress_belongs_to_each_manager_and_team(app, client, database, new_team, login_as):
    client.put("/api/onboarding/items/attack_catalogue", json={"done": True})
    second = database.execute(
        "INSERT INTO users (email, password_hash, name, role, team, workspace_id, created_at, is_active) VALUES ('second@new-team.example.test', 'x', 'Second Manager', 'soc_manager', 'New Response Team', ?, ?, 1)",
        (new_team["workspace"], iso_now()),
    ).lastrowid
    new_team["sign_in"](second)
    assert _items(client.get("/api/onboarding"))["attack_catalogue"]["marked"] is False
    rows = database.execute("SELECT DISTINCT workspace_id FROM onboarding_progress").fetchall()
    assert {row[0] for row in rows} == {new_team["workspace"]}
