import hashlib

from socify.timeutils import iso_now


def new_member(database, template_id, role, email):
    identifier = database.execute(
        "INSERT INTO users(email, password_hash, name, role, workspace_id, is_active) SELECT ?, password_hash, ?, ?, workspace_id, 1 FROM users WHERE id = ? RETURNING id",
        (email, role, role, template_id),
    ).fetchone()[0]
    database.execute("INSERT INTO workspace_memberships(workspace_id, user_id, role, created_at) VALUES (1, ?, ?, ?)", (identifier, role, iso_now()))
    return identifier


def switch(client, identifier):
    with client.session_transaction() as state:
        state.clear()
        state.update(user_id=identifier, workspace_id=1)


def test_case_log_assignment_grants_new_role_membership_and_revocation_takes_effect(autopsy_case, client, database, login_as, user_ids):
    responder = new_member(database, user_ids["analyst"], "l2_responder", "l2@internal.test")
    login_as("soc_manager")
    job = client.post(f"/api/cases/{autopsy_case}/imports", json={"filename": "assigned.jsonl", "content": '{"title":"Assigned original"}'}).json
    payload = {
        "case_id": autopsy_case,
        "job_id": job["id"],
        "assignee": responder,
        "instructions": "Validate network evidence and document containment findings",
    }
    created = client.post("/api/team/assignments", json=payload)
    assert created.status_code == 201, created.json
    assignment_id = created.json["id"]
    other = client.post("/api/cases", json={"title": "Different case", "reason": "alert_review", "objective": "Check assignment boundary"}).json["id"]
    assert client.post("/api/team/assignments", json={**payload, "case_id": other}).status_code == 422
    switch(client, responder)
    assert client.get(f"/api/cases/{autopsy_case}").status_code == 200
    assert client.get("/api/team").json["assignments"][0]["id"] == assignment_id
    assert client.patch(f"/api/team/assignments/{assignment_id}", json={"status": "in_progress"}).status_code == 200
    database.execute("DELETE FROM autopsy_case_members WHERE case_id = ? AND user_id = ?", (autopsy_case, responder))
    assert client.get("/api/team").json["assignments"] == []
    assert client.patch(f"/api/team/assignments/{assignment_id}", json={"status": "completed"}).status_code == 404


def test_deactivation_transfers_case_tasks_and_revokes_existing_sessions_atomically(autopsy_case, client, database, login_as, user_ids):
    replacement = new_member(database, user_ids["analyst"], "investigator", "investigator@internal.test")
    login_as("soc_manager")
    corrective = client.post(
        f"/api/cases/{autopsy_case}/records/corrective",
        json={"title": "Close monitoring gap", "owner_id": user_ids["analyst"], "due_at": "2026-11-01T10:00:00Z", "status": "open"},
    )
    escalation = client.post(
        f"/api/cases/{autopsy_case}/records/escalation",
        json={
            "to_user": user_ids["analyst"],
            "from_level": "management",
            "to_level": "l1",
            "reason": "Review preserved evidence",
            "priority": "high",
            "status": "raised",
        },
    )
    assert corrective.status_code == 201 and escalation.status_code == 201
    task = client.post(f"/api/incidents/{autopsy_case}/tasks", json={"title": "Required evidence handoff", "required": True, "assignee": user_ids["analyst"]})
    assert task.status_code == 201
    database.execute(
        "INSERT INTO auth_sessions(session_hash, user_id, workspace_id, created_at, last_seen_at, expires_at) VALUES (?, ?, 1, ?, ?, '2099-01-01T00:00:00Z')",
        (hashlib.sha256(b"Synthetic session identifier").hexdigest(), user_ids["analyst"], iso_now(), iso_now()),
    )
    path = f"/api/team/members/{user_ids['analyst']}/deactivate"
    assert client.post(path, json={"reason": "Staff transition"}).status_code == 409
    assert database.execute("SELECT is_active FROM users WHERE id = ?", (user_ids["analyst"],)).fetchone()[0] == 1
    assert client.post(path, json={"reason": "Staff transition", "handoff_to": user_ids["auditor"]}).status_code == 422
    handed_off = client.post(path, json={"reason": "Staff transition with evidence ownership retained", "handoff_to": replacement})
    assert handed_off.status_code == 200, handed_off.json
    assert handed_off.json["cases_transferred"] == 1
    assert database.execute("SELECT is_active FROM users WHERE id = ?", (user_ids["analyst"],)).fetchone()[0] == 0
    assert database.execute("SELECT revoked_at FROM auth_sessions WHERE user_id = ?", (user_ids["analyst"],)).fetchone()[0]
    assert database.execute("SELECT assignee FROM incident_cases WHERE id = ?", (autopsy_case,)).fetchone()[0] == replacement
    assert database.execute("SELECT assignee FROM case_tasks WHERE id = ?", (task.json["id"],)).fetchone()[0] == replacement
    assert client.get(f"/api/cases/{autopsy_case}/records?kind=corrective").json["items"][0]["payload"]["owner_id"] == replacement
    escalations = client.get(f"/api/cases/{autopsy_case}/records?kind=escalation").json["items"]
    assert escalations[0]["payload"]["to_user"] == replacement and escalations[0]["payload"]["status"] == "raised"
    assert escalations[1]["payload"]["status"] == "returned"
    switch(client, replacement)
    assert client.get(f"/api/cases/{autopsy_case}").status_code == 200
    assert client.patch(f"/api/incidents/{autopsy_case}/tasks/{task.json['id']}", json={"status": "completed"}).status_code == 200
    login_as("analyst")
    assert client.get(f"/api/cases/{autopsy_case}").status_code == 401


def test_operational_roles_no_training_role_or_training_permissions(autopsy_case, client, login_as, user_ids):
    login_as("soc_manager")
    assert client.post("/api/team/invitations", json={"email": "training@internal.test", "role": "instructor"}).status_code == 422
    assert client.patch(f"/api/team/members/{user_ids['analyst']}", json={"role": "instructor"}).status_code == 422
    assert client.put("/api/team/roles/analyst", json={"permissions": ["training.run"]}).status_code == 422
    assert client.post("/api/team/invitations", json={"email": "valid@internal.test", "role": "l1_analyst", "is_admin": True}).status_code == 422
    invite = client.post("/api/team/invitations", json={"email": "valid@internal.test", "role": "l1_analyst"})
    assert invite.status_code == 201
    assert "instructor" not in [role["role"] for role in client.get("/api/team").json["roles"]]


def test_queued_reports_respect_role_policy_revocation_before_render(autopsy_case, app, client, login_as):
    from socify.autopsy_worker import run_autopsy_worker_once

    base = f"/api/cases/{autopsy_case}"
    version = client.get(base).json["version"]
    queued = client.post(base + "/reports", json={"version": version}).json
    login_as("soc_manager")
    assert client.put("/api/team/roles/analyst", json={"permissions": ["cases.read", "cases.update"]}).status_code == 200
    with app.app_context():
        run_autopsy_worker_once("policy-revocation")
    status = client.get(base + f"/jobs/{queued['job_id']}")
    assert status.json["state"] == "failed" and status.json["error_code"] == "ACCESS_REVOKED"
