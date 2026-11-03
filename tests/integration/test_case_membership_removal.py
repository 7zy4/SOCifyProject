"""Case-local revocation preserves work, history and independent access."""

import importlib
import json

import pytest

from tests.integration.test_autopsy_teams import new_member


def transfer(client, case_id, source, target):
    response = client.post(
        f"/api/cases/{case_id}/handoff",
        json={
            "from_user": source,
            "to_user": target,
            "version": client.get(f"/api/cases/{case_id}").json["version"],
            "reason": "Transfer ongoing investigation",
        },
    )
    assert response.status_code == 200, response.json


def payload(client, case_id):
    return {"version": client.get(f"/api/cases/{case_id}").json["version"], "reason": "End access after handoff"}


def test_removal_is_case_local_audited_and_retry_safe(autopsy_case, client, database, login_as, user_ids):
    source, target = user_ids["analyst"], user_ids["soc_manager"]
    other = client.post("/api/cases", json={"title": "Separate work", "reason": "alert_review", "objective": "Independent access"}).json["id"]
    login_as("soc_manager")
    transfer(client, autopsy_case, source, target)
    before = client.get(f"/api/cases/{autopsy_case}").json
    body = payload(client, autopsy_case)
    url = f"/api/cases/{autopsy_case}/members/{source}"
    assert client.delete(url, json=body).status_code == 200
    after = client.get(f"/api/cases/{autopsy_case}").json
    assert after["version"] > before["version"]
    assert after["tasks"] == before["tasks"]
    assert client.delete(url, json=body).status_code == 200
    assert client.get(f"/api/cases/{autopsy_case}").json["version"] == after["version"]
    custody = client.get(f"/api/cases/{autopsy_case}/custody").json
    assert custody["integrity_valid"]
    assert len([r for r in custody["items"] if r["action"] == "member_access_revoked"]) == 1
    login_as("analyst")
    for suffix in ["", "/records", "/tasks", "/custody", "/events", "/imports"]:
        assert client.get(f"/api/cases/{autopsy_case}" + suffix).status_code == 404, suffix
    assert client.post(f"/api/cases/{autopsy_case}/reports", json={"version": after["version"]}).status_code == 404
    assert client.get(f"/api/cases/{other}").status_code == 200
    assert database.execute("SELECT is_active FROM users WHERE id=?", (source,)).fetchone()[0] == 1
    login_as("soc_manager")
    assert client.post(f"/api/cases/{autopsy_case}/members", json={"user_id": source, "responsibility": "reviewer"}).status_code == 200
    # An old retry must not remove a subsequent deliberate grant.
    assert client.delete(url, json=body).status_code == 409
    login_as("analyst")
    assert client.get(f"/api/cases/{autopsy_case}").status_code == 200


@pytest.mark.parametrize("work", ["owner", "task", "assignment", "corrective", "completed_corrective", "escalation", "acknowledged_escalation"])
def test_outstanding_work_requires_handoff(autopsy_case, client, database, login_as, user_ids, work):
    source = user_ids["analyst"]
    login_as("soc_manager")
    if work != "owner":
        transfer(client, autopsy_case, source, user_ids["soc_manager"])
        assert client.post(f"/api/cases/{autopsy_case}/members", json={"user_id": source, "responsibility": "investigator"}).status_code == 200
        if work == "task":
            assert client.post(f"/api/incidents/{autopsy_case}/tasks", json={"title": "Outstanding evidence review", "assignee": source}).status_code == 201
        elif work == "assignment":
            job = client.post(f"/api/cases/{autopsy_case}/imports", json={"filename": "assigned.jsonl", "content": '{"title":"Retained work"}'}).json
            assert (
                client.post(
                    "/api/team/assignments", json={"case_id": autopsy_case, "job_id": job["id"], "assignee": source, "instructions": "Retain task ownership"}
                ).status_code
                == 201
            )
            database.execute("UPDATE case_tasks SET status='completed' WHERE case_id=? AND assignee=?", (autopsy_case, source))
        elif "corrective" in work:
            data = {
                "title": "Verify remediation",
                "owner_id": source,
                "due_at": "2026-11-06T10:00:00Z",
                "status": "completed" if work.startswith("completed") else "open",
            }
            assert client.post(f"/api/cases/{autopsy_case}/records/corrective", json=data).status_code == 201
        else:
            data = {"to_user": source, "from_level": "management", "to_level": "l1", "reason": "Review evidence", "priority": "high", "status": "raised"}
            response = client.post(f"/api/cases/{autopsy_case}/records/escalation", json=data)
            assert response.status_code == 201
            if work.startswith("acknowledged"):
                database.execute("UPDATE autopsy_records SET payload=json_set(payload,'$.status','acknowledged') WHERE id=?", (response.json["id"],))
    response = client.delete(f"/api/cases/{autopsy_case}/members/{source}", json=payload(client, autopsy_case))
    assert response.status_code == 409 and response.json["error"]["code"] == "CASE_MEMBER_HAS_WORK"
    assert database.execute("SELECT 1 FROM autopsy_case_members WHERE case_id=? AND user_id=?", (autopsy_case, source)).fetchone()


def test_completed_history_and_restricted_batch_grants(autopsy_case, client, database, login_as, user_ids):
    source = user_ids["analyst"]
    login_as("soc_manager")
    task = client.post(f"/api/incidents/{autopsy_case}/tasks", json={"title": "Completed retained work", "assignee": source}).json["id"]
    assert client.patch(f"/api/incidents/{autopsy_case}/tasks/{task}", json={"status": "completed"}).status_code == 200
    transfer(client, autopsy_case, source, user_ids["soc_manager"])
    job = client.post(f"/api/cases/{autopsy_case}/imports", json={"filename": "restricted.jsonl", "content": '{"title":"Identity review"}'}).json["id"]
    database.execute(
        "INSERT INTO autopsy_batch_access(job_id,restricted,changed_by,changed_at) VALUES (?,1,?,'2026-11-03T00:00:00Z')", (job, user_ids["soc_manager"])
    )
    database.execute("INSERT INTO autopsy_batch_members(job_id,user_id) VALUES (?,?)", (job, source))
    response = client.delete(f"/api/cases/{autopsy_case}/members/{source}", json=payload(client, autopsy_case))
    assert response.status_code == 200, response.json
    assert not database.execute("SELECT 1 FROM autopsy_batch_members WHERE user_id=? AND job_id=?", (source, job)).fetchone()
    row = database.execute("SELECT status,assignee FROM case_tasks WHERE id=?", (task,)).fetchone()
    assert row["status"] == "completed" and row["assignee"] == source


@pytest.mark.parametrize("mode", ["stale", "foreign_member", "manager", "legacy", "role", "manager_policy_floor", "closed_history"])
def test_removal_boundaries(autopsy_case, app, client, database, login_as, user_ids, mode):
    source = user_ids["analyst"]
    login_as("soc_manager")
    transfer(client, autopsy_case, source, user_ids["soc_manager"])
    body = payload(client, autopsy_case)
    expected = 409
    if mode == "stale":
        database.execute("UPDATE incident_cases SET version=version+1 WHERE id=?", (autopsy_case,))
    elif mode == "foreign_member":
        source = new_member(database, source, "analyst", "separate@internal.test")
        database.execute("INSERT INTO training_workspaces(id,name,public_id,created_at) VALUES (99,'Separate','separate','2026-11-03T00:00:00Z')")
        database.execute("UPDATE users SET workspace_id=99 WHERE id=?", (source,))
        expected = 404
    elif mode == "manager":
        source = user_ids["soc_manager"]
    elif mode == "legacy":
        database.execute("DELETE FROM autopsy_case_context WHERE case_id=?", (autopsy_case,))
    elif mode == "role":
        database.execute(
            "INSERT OR REPLACE INTO team_role_permissions(workspace_id,role,permissions) VALUES (1,'analyst',?)", (json.dumps(["cases.read", "cases.assign"]),)
        )
        login_as("analyst")
        expected = 403
    elif mode == "manager_policy_floor":
        database.execute(
            "INSERT OR REPLACE INTO team_role_permissions(workspace_id,role,permissions) VALUES (1,'soc_manager',?)", (json.dumps(["cases.read"]),)
        )
        expected = 200
    else:
        database.execute("UPDATE incident_cases SET status='closed',assignee=? WHERE id=?", (source, autopsy_case))
        expected = 200
    response = client.delete(f"/api/cases/{autopsy_case}/members/{source}", json=body)
    assert response.status_code == expected, response.json


@pytest.mark.parametrize(
    "body",
    [
        None,
        {},
        {"version": True, "reason": "No"},
        {"version": 0, "reason": "No"},
        {"version": 1, "reason": ""},
        {"version": 1, "reason": "x" * 1001},
        {"version": 1, "reason": "Valid reason", "force": True},
    ],
)
def test_invalid_removal_does_not_modify_access(autopsy_case, client, login_as, user_ids, body):
    login_as("soc_manager")
    response = client.delete(f"/api/cases/{autopsy_case}/members/{user_ids['analyst']}", json=body)
    assert response.status_code == 422


def test_custody_failure_rolls_back_access_removal(autopsy_case, client, database, login_as, user_ids, monkeypatch):
    login_as("soc_manager")
    source = user_ids["analyst"]
    transfer(client, autopsy_case, source, user_ids["soc_manager"])
    body = payload(client, autopsy_case)

    def unavailable(*args, **kwargs):
        raise RuntimeError("Audit unavailable")

    monkeypatch.setattr(importlib.import_module("socify.autopsy_api"), "custody", unavailable)
    with pytest.raises(RuntimeError, match="Audit unavailable"):
        client.delete(f"/api/cases/{autopsy_case}/members/{source}", json=body)
    assert database.execute("SELECT 1 FROM autopsy_case_members WHERE case_id=? AND user_id=?", (autopsy_case, source)).fetchone()
    assert client.get(f"/api/cases/{autopsy_case}").json["version"] == body["version"]


@pytest.mark.parametrize("work", ["none", "pending_task", "completed_task", "reviewed_task", "corrective", "escalation", "owner"])
def test_previous_shift_can_transfer_only_new_unfinished_work(autopsy_case, client, database, login_as, user_ids, work):
    source, target = user_ids["analyst"], user_ids["soc_manager"]
    login_as("soc_manager")
    transfer(client, autopsy_case, source, target)
    task = None
    if work.endswith("task"):
        task = client.post(f"/api/incidents/{autopsy_case}/tasks", json={"title": "Follow-up after handoff", "assignee": source}).json["id"]
        if work != "pending_task":
            database.execute("UPDATE case_tasks SET status=? WHERE id=?", (work.removesuffix("_task"), task))
    elif work == "corrective":
        assert (
            client.post(
                f"/api/cases/{autopsy_case}/records/corrective",
                json={"title": "Later correction", "owner_id": source, "due_at": "2026-11-06T10:00:00Z", "status": "open"},
            ).status_code
            == 201
        )
    elif work == "escalation":
        assert (
            client.post(
                f"/api/cases/{autopsy_case}/records/escalation",
                json={"to_user": source, "from_level": "management", "to_level": "l1", "reason": "Later escalation", "priority": "high", "status": "raised"},
            ).status_code
            == 201
        )
    elif work == "owner":
        database.execute("UPDATE incident_cases SET assignee=? WHERE id=?", (source, autopsy_case))
    response = client.post(f"/api/cases/{autopsy_case}/handoff", json={"from_user": source, "to_user": target, **payload(client, autopsy_case)})
    if work in {"none", "completed_task", "reviewed_task"}:
        assert response.status_code == 409 and response.json["error"]["code"] == "HANDOFF_ALREADY_COMPLETED"
        if task:
            assert database.execute("SELECT assignee FROM case_tasks WHERE id=?", (task,)).fetchone()[0] == source
    else:
        assert response.status_code == 200, response.json
        if task:
            assert database.execute("SELECT assignee FROM case_tasks WHERE id=?", (task,)).fetchone()[0] == target
        assert client.delete(f"/api/cases/{autopsy_case}/members/{source}", json=payload(client, autopsy_case)).status_code == 200


def test_revoked_author_cannot_finish_queued_report_or_retain_selection(autopsy_case, app, client, login_as, user_ids):
    from socify.autopsy_worker import run_autopsy_worker_once

    base = f"/api/cases/{autopsy_case}"
    report = client.post(base + "/reports", json={"version": client.get(base).json["version"]}).json
    login_as("soc_manager")
    transfer(client, autopsy_case, user_ids["analyst"], user_ids["soc_manager"])
    assert client.delete(base + f"/members/{user_ids['analyst']}", json=payload(client, autopsy_case)).status_code == 200
    with app.app_context():
        run_autopsy_worker_once("case-member-revoked")
    job = client.get(base + f"/jobs/{report['job_id']}").json
    assert job["state"] == "failed" and job["error_code"] == "ACCESS_REVOKED"
    login_as("analyst")
    with client.session_transaction() as session:
        session["investigation_cases"] = [autopsy_case]
    assert client.get("/api/investigation-selection").json["case_ids"] == []
    assert client.get(base + f"/jobs/{report['job_id']}").status_code == 404
    for suffix in [f"/reports/{report['id']}", f"/reports/{report['id']}/files/pdf"]:
        assert client.get(base + suffix).status_code == 404
