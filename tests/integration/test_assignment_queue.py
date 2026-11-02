import json

import pytest


@pytest.fixture
def assigned(autopsy_case, client, login_as, user_ids):
    login_as("soc_manager")
    base = f"/api/cases/{autopsy_case}"
    job = client.post(base + "/imports", json={"filename": "identity.json", "content": '[{"title":"Assigned review"}]'}).json["id"]
    response = client.post(
        "/api/team/assignments", json={"case_id": autopsy_case, "job_id": job, "assignee": user_ids["analyst"], "instructions": "Review 100%_literal identity"}
    )
    assert response.status_code == 201, response.json
    row = client.get("/api/team/assignments?scope=team").json["items"][0]
    return row


@pytest.mark.parametrize("permission", ["cases.read", "cases.update", "events.read"])
def test_assignment_requires_recipient_read_and_execution_permissions(autopsy_case, client, database, login_as, user_ids, permission):
    login_as("soc_manager")
    job = client.post(f"/api/cases/{autopsy_case}/imports", json={"filename": "review.json", "content": '[{"title":"Review policy"}]'}).json["id"]
    policy = next(role["permissions"] for role in client.get("/api/team").json["roles"] if role["role"] == "analyst")
    assert client.put("/api/team/roles/analyst", json={"permissions": [value for value in policy if value != permission]}).status_code == 200
    version = client.get(f"/api/cases/{autopsy_case}").json["version"]
    tasks = database.execute("SELECT COUNT(*) FROM case_tasks WHERE case_id=?", (autopsy_case,)).fetchone()[0]
    payload = {"case_id": autopsy_case, "job_id": job, "assignee": user_ids["analyst"], "instructions": "Review identity context"}
    rejected = client.post("/api/team/assignments", json=payload)
    assert rejected.status_code == 422 and rejected.json["error"]["code"] == "ASSIGNEE_PERMISSION_REQUIRED"
    assert client.get(f"/api/cases/{autopsy_case}").json["version"] == version
    assert database.execute("SELECT COUNT(*) FROM case_tasks WHERE case_id=?", (autopsy_case,)).fetchone()[0] == tasks
    assert client.put("/api/team/roles/analyst", json={"permissions": policy}).status_code == 200
    assert client.post("/api/team/assignments", json=payload).status_code == 201


def test_restricted_assignment_requires_explicit_access_without_silent_grants(autopsy_case, client, database, login_as, user_ids):
    login_as("soc_manager")
    base = f"/api/cases/{autopsy_case}"
    job = client.post(base + "/imports", json={"filename": "private.json", "content": '[{"title":"Sensitive review"}]'}).json["id"]
    access = f"{base}/imports/{job}/access"
    assert client.put(access, json={"restricted": True, "members": [], "reason": "Restrict review"}).status_code == 200
    payload = {"case_id": autopsy_case, "job_id": job, "assignee": user_ids["analyst"], "instructions": "Review private identity batch"}
    before = client.get(base).json["version"]
    rejected = client.post("/api/team/assignments", json=payload)
    assert rejected.status_code == 422 and rejected.json["error"]["code"] == "ASSIGNEE_BATCH_ACCESS_REQUIRED"
    assert client.get(base).json["version"] == before
    assert database.execute("SELECT COUNT(*) FROM autopsy_batch_members WHERE job_id=?", (job,)).fetchone()[0] == 0
    assert database.execute("SELECT COUNT(*) FROM team_log_assignments WHERE job_id=?", (job,)).fetchone()[0] == 0
    assert client.put(access, json={"restricted": True, "members": [user_ids["analyst"]], "reason": "Approve specific recipient"}).status_code == 200
    created = client.post("/api/team/assignments", json=payload)
    assert created.status_code == 201
    assert client.put(access, json={"restricted": True, "members": [], "reason": "Withdraw access before repeat"}).status_code == 200
    assert client.post("/api/team/assignments", json=payload).status_code == 422
    assert database.execute("SELECT COUNT(*) FROM team_log_assignments WHERE job_id=?", (job,)).fetchone()[0] == 1
    login_as("analyst")
    assert client.get("/api/team/assignments").json["items"] == []


def test_restricted_batch_creator_can_receive_own_work(autopsy_case, client, login_as, user_ids):
    base = f"/api/cases/{autopsy_case}"
    job = client.post(base + "/imports", json={"filename": "own.json", "content": '[{"title":"Own evidence review"}]'}).json["id"]
    login_as("soc_manager")
    assert client.put(f"{base}/imports/{job}/access", json={"restricted": True, "members": [], "reason": "Preserve creator access"}).status_code == 200
    response = client.post(
        "/api/team/assignments", json={"case_id": autopsy_case, "job_id": job, "assignee": user_ids["analyst"], "instructions": "Review own evidence"}
    )
    assert response.status_code == 201
    login_as("analyst")
    assert client.get("/api/team/assignments").json["total"] == 1


def test_queue_search_pages_and_personal_scope_do_not_silently_stop_at_100(assigned, client, login_as, user_ids):
    for index in range(102):
        job = client.post(
            f"/api/cases/{assigned['case_id']}/imports", json={"filename": f"queue-{index}.json", "content": json.dumps([{"title": f"Queue event {index}"}])}
        ).json["id"]
        assert (
            client.post(
                "/api/team/assignments",
                json={"case_id": assigned["case_id"], "job_id": job, "assignee": user_ids["analyst"], "instructions": f"Review queue batch {index}"},
            ).status_code
            == 201
        )
    assert client.get("/api/team/assignments").json["total"] == 0
    first = client.get("/api/team/assignments?scope=team").json
    last = client.get("/api/team/assignments?scope=team&page=5").json
    assert first["total"] == last["total"] == 103
    assert len(first["items"]) == 25 and len(last["items"]) == 3
    assert last["items"][-1]["id"] == assigned["id"]
    assert not {row["id"] for row in first["items"]} & {row["id"] for row in last["items"]}
    for query in ("100%_literal", "identity.json"):
        found = client.get("/api/team/assignments", query_string={"scope": "team", "q": query}).json
        assert found["total"] == 1 and found["items"][0]["id"] == assigned["id"]
    assert client.get("/api/team/assignments", query_string={"scope": "team", "q": "%_"}).json["total"] == 1
    assert client.get("/api/team/assignments?scope=team&page=1000000").json["items"] == []
    login_as("analyst")
    assert client.get("/api/team/assignments?scope=team").json["total"] == 103
    login_as("instructor")
    assert client.get("/api/team/assignments?scope=team").json["total"] == 0


def test_task_and_assignment_share_completion_reopen_and_idempotent_history(assigned, client, database, login_as):
    login_as("analyst")
    case = assigned["case_id"]
    path = f"/api/incidents/{case}/tasks/{assigned['task_id']}"
    update = client.patch(path, json={"status": "completed"})
    assert update.status_code == 200
    row = client.get("/api/team/assignments?status=completed").json["items"][0]
    task = database.execute("SELECT * FROM case_tasks WHERE id=?", (row["task_id"],)).fetchone()
    assert row["state"] == row["task_status"] == "completed" and row["completed_at"] == task["completed_at"]
    history = database.execute("SELECT COUNT(*) FROM case_history WHERE case_id=?", (case,)).fetchone()[0]
    assert client.patch(path, json={"status": "completed"}).json["updated"] is False
    assert client.patch(f"/api/team/assignments/{assigned['id']}", json={"status": "completed", "expected_status": "pending"}).json["updated"] is False
    assert database.execute("SELECT COUNT(*) FROM case_history WHERE case_id=?", (case,)).fetchone()[0] == history
    assert client.patch(f"/api/team/assignments/{assigned['id']}", json={"status": "in_progress", "expected_status": "pending"}).status_code == 409
    assert client.patch(f"/api/team/assignments/{assigned['id']}", json={"status": "in_progress", "expected_status": "completed"}).status_code == 200
    assert client.get("/api/team/assignments?status=completed").json["total"] == 0
    reopened = client.get("/api/team/assignments?status=in_progress").json["items"][0]
    assert reopened["state"] == "in_progress" and reopened["completed_at"] is None
    for status, state in (("reviewed", "completed"), ("pending", "assigned")):
        assert client.patch(path, json={"status": status}).status_code == 200
        assert client.get("/api/team/assignments").json["items"][0]["state"] == state


def test_queue_filters_restricted_batches_before_counts_and_blocks_both_update_paths(assigned, client, login_as, user_ids):
    path = f"/api/cases/{assigned['case_id']}/imports/{assigned['job_id']}/access"
    assert client.put(path, json={"restricted": True, "members": [], "reason": "Sensitive batch reassigned"}).status_code == 200
    login_as("analyst")
    assert client.get("/api/team/assignments").json["total"] == 0
    assert client.patch(f"/api/team/assignments/{assigned['id']}", json={"status": "completed"}).status_code == 404
    assert client.patch(f"/api/incidents/{assigned['case_id']}/tasks/{assigned['task_id']}", json={"status": "completed"}).status_code == 403
    login_as("soc_manager")
    assert client.put(path, json={"restricted": True, "members": [user_ids["analyst"]], "reason": "Restore approved batch review"}).status_code == 200
    login_as("analyst")
    assert client.get("/api/team/assignments").json["total"] == 1


def test_queue_rechecks_permissions_membership_selection_and_closed_case(assigned, app, client, database, login_as, user_ids):
    case = assigned["case_id"]
    app.config["REQUIRE_INVESTIGATION_SELECTION"] = True
    login_as("analyst")
    assert client.get("/api/team/assignments").json["total"] == 0
    assert client.post("/api/investigation-selection", json={"case_ids": [case]}).status_code == 200
    assert client.get("/api/team/assignments").json["total"] == 1
    database.execute("DELETE FROM autopsy_case_members WHERE case_id=? AND user_id=?", (case, user_ids["analyst"]))
    assert client.get("/api/team/assignments").json["total"] == 0
    app.config["REQUIRE_INVESTIGATION_SELECTION"] = False
    login_as("soc_manager")
    permissions = next(role["permissions"] for role in client.get("/api/team").json["roles"] if role["role"] == "analyst")
    assert client.put("/api/team/roles/analyst", json={"permissions": [value for value in permissions if value != "cases.update"]}).status_code == 200
    database.execute(
        "INSERT INTO autopsy_case_members(case_id,user_id,responsibility,assigned_by,assigned_at) VALUES (?,?,'investigator',?,'2026-11-03T00:00:00Z')",
        (case, user_ids["analyst"], user_ids["soc_manager"]),
    )
    login_as("analyst")
    assert client.get("/api/team/assignments").json["items"][0]["can_update"] is False
    assert client.patch(f"/api/team/assignments/{assigned['id']}", json={"status": "completed"}).status_code == 403
    login_as("soc_manager")
    database.execute("UPDATE incident_cases SET status='closed' WHERE id=?", (case,))
    assert client.get("/api/team/assignments?scope=team").json["items"][0]["can_update"] is False
    assert client.patch(f"/api/team/assignments/{assigned['id']}", json={"status": "completed"}).status_code == 409


def test_other_workspace_cannot_enumerate_or_update_assignments(assigned, client, database, user_ids):
    tenant = database.execute(
        "INSERT INTO training_workspaces(public_id,name,created_at) VALUES ('assignment-other','Other team','2026-11-03T00:00:00Z')"
    ).lastrowid
    member = database.execute(
        "INSERT INTO users(email,password_hash,name,role,workspace_id,is_active) SELECT 'assignment-other@team.test',password_hash,'Other manager','soc_manager',?,1 FROM users WHERE id=?",
        (tenant, user_ids["soc_manager"]),
    ).lastrowid
    with client.session_transaction() as session:
        session.clear()
        session.update(user_id=member, workspace_id=tenant, user_role="soc_manager")
    assert client.get("/api/team/assignments?scope=team").json["total"] == 0
    assert client.patch(f"/api/team/assignments/{assigned['id']}", json={"status": "completed"}).status_code == 404


@pytest.mark.parametrize(
    "params", [{"q": "a" * 201}, {"status": "bad"}, {"scope": "all"}, {"page": "0"}, {"page": "-1"}, {"page": "1e2"}, {"page": "9" * 1000}, {"page": "١"}]
)
def test_invalid_queue_filters_are_rejected(assigned, client, params):
    assert client.get("/api/team/assignments", query_string=params).status_code == 422
