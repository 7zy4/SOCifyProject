import hashlib

from socify.security import ROLE_PERMISSIONS

LOGIN_VALUE = "Team-Integration-Safe-2026!"


def account(client, database, email, **options):
    response = client.post("/api/auth/register", json={"email": email, "name": "Team member", "password": LOGIN_VALUE, **options})
    assert response.status_code == 201, response.json
    row = database.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    with client.session_transaction() as session:
        session.clear()
        session["user_id"] = row["id"]
        session["workspace_id"] = row["workspace_id"]
    return dict(row)


def switch(client, user):
    with client.session_transaction() as session:
        session.clear()
        session["user_id"] = user["id"]
        session["workspace_id"] = user["workspace_id"]


def test_team_registration_invitation_and_live_permission_policy(client, database):
    owner = account(client, database, "owner@team.test", team_name="Incident Team", role="admin")
    assert owner["role"] == "soc_manager"
    assert owner["workspace_id"] != 1
    invite = client.post("/api/team/invitations", json={"email": "analyst@team.test", "role": "analyst"})
    assert invite.status_code == 201
    token = invite.json["invitation_token"]
    stored = database.execute("SELECT token_hash FROM team_invitations").fetchone()[0]
    assert stored == hashlib.sha256(token.encode()).hexdigest()
    assert token not in client.get("/api/team").text
    wrong = client.post("/api/auth/register", json={"email": "wrong@team.test", "name": "Wrong member", "password": LOGIN_VALUE, "invitation_token": token})
    assert wrong.status_code == 422
    member = account(client, database, "analyst@team.test", invitation_token=token, role="admin")
    assert member["role"] == "analyst"
    assert member["workspace_id"] == owner["workspace_id"]
    replay = client.post("/api/auth/register", json={"email": "other@team.test", "name": "Other member", "password": LOGIN_VALUE, "invitation_token": token})
    assert replay.status_code == 422
    assert client.post("/api/team/invitations", json={"email": "elevate@team.test", "role": "soc_manager"}).status_code == 403
    assert client.get("/api/events").status_code == 200
    switch(client, owner)
    assert client.put("/api/team/roles/analyst", json={"permissions": ["users.manage"]}).status_code == 422
    assert client.put("/api/team/roles/analyst", json={"permissions": sorted(ROLE_PERMISSIONS["analyst"] - {"events.read"})}).status_code == 200
    switch(client, member)
    assert client.get("/api/events").status_code == 403
    assert "events.read" not in client.get("/api/auth/me").json["permissions"]
    switch(client, owner)
    assert client.patch(f"/api/team/members/{owner['id']}", json={"role": "analyst"}).status_code == 409
    assert client.patch(f"/api/team/members/{member['id']}", json={"role": "auditor"}).status_code == 200
    switch(client, member)
    assert client.post("/api/incidents", json={"title": "Forbidden mutation"}).status_code == 403


def test_log_assignment_connects_import_case_task_and_member_progress(client, database, login_as, user_ids):
    login_as("soc_manager")
    job = client.post("/api/imports", json={"filename": "team.jsonl", "content": '{"source":"team-logs","title":"Assigned log"}'}).json
    case = client.post("/api/incidents", json={"title": "Team incident"}).json
    payload = {
        "job_id": job["id"],
        "case_id": case["id"],
        "assignee": user_ids["analyst"],
        "instructions": "Review the source and document an ATT&CK conclusion",
    }
    assert client.post("/api/team/assignments", json=payload).status_code == 409
    assert client.post(f"/api/incidents/{case['id']}/imports", json={"job_id": job["id"]}).status_code == 200
    created = client.post("/api/team/assignments", json=payload)
    assert created.status_code == 201
    identifier = created.json["id"]
    assert client.post("/api/team/assignments", json=payload).json["id"] == identifier
    detail = client.get(f"/api/incidents/{case['id']}").json
    assert len(detail["tasks"]) == 3
    assert any(row["action"] == "logs_assigned" for row in detail["history"])
    login_as("instructor")
    assert client.get("/api/team").json["assignments"] == []
    assert client.patch(f"/api/team/assignments/{identifier}", json={"status": "completed"}).status_code == 404
    assigned_task = next(task for task in detail["tasks"] if task["assignee"] == user_ids["analyst"])
    assert client.patch(f"/api/incidents/{case['id']}/tasks/{assigned_task['id']}", json={"status": "completed"}).status_code == 403
    login_as("analyst")
    assert len(client.get("/api/team").json["assignments"]) == 1
    assert client.patch(f"/api/team/assignments/{identifier}", json={"status": "completed"}).status_code == 200
    login_as("soc_manager")
    assert client.get("/api/team").json["assignments"][0]["task_status"] == "completed"
    assert client.get(f"/api/incidents/{case['id']}").json["tasks"][-1]["status"] == "completed"
    assert client.put("/api/team/roles/analyst", json={"permissions": sorted(ROLE_PERMISSIONS["analyst"] - {"cases.read"})}).status_code == 200
    login_as("analyst")
    assert client.get("/api/team").json["assignments"] == []
    assert client.get(f"/api/incidents/{case['id']}").status_code == 403


def test_new_teams_cannot_see_or_manage_other_team(client, database):
    first = account(client, database, "first@team.test", team_name="First Team")
    case_id = client.post("/api/incidents", json={"title": "First team case"}).json["id"]
    second = account(client, database, "second@team.test", team_name="Second Team")
    assert first["workspace_id"] != second["workspace_id"]
    assert client.get(f"/api/incidents/{case_id}").status_code == 404
    assert client.get("/api/incidents").json["total"] == 0
    assert client.patch(f"/api/team/members/{first['id']}", json={"role": "analyst"}).status_code == 404
    assert client.post("/api/incidents", json={"title": "Second team case"}).status_code == 201


def test_expired_invitation_and_malformed_management_payloads(client, database, login_as):
    login_as("soc_manager")
    token = client.post("/api/team/invitations", json={"email": "expired@team.test", "role": "analyst"}).json["invitation_token"]
    database.execute("UPDATE team_invitations SET expires_at = '2000-01-01T00:00:00Z'")
    response = client.post(
        "/api/auth/register", json={"email": "expired@team.test", "name": "Expired invitation", "password": LOGIN_VALUE, "invitation_token": token}
    )
    assert response.status_code == 422
    assert not database.execute("SELECT 1 FROM users WHERE email = 'expired@team.test'").fetchone()
    for method, path, payload in [
        ("post", "/api/team/invitations", {"email": "invalid", "role": "admin"}),
        ("patch", "/api/team/members/99999", {"role": []}),
        ("put", "/api/team/roles/analyst", {"permissions": ["*"]}),
        ("put", "/api/team/roles/soc_manager", {"permissions": []}),
        ("post", "/api/team/assignments", {"job_id": True}),
        ("patch", "/api/team/assignments/99999", {"status": []}),
    ]:
        assert getattr(client, method)(path, json=payload).status_code == 422
