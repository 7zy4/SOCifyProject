import pytest


@pytest.mark.parametrize(
    "method,path,payload,status,code",
    [
        ("get", "/api/incidents?page=no", None, 400, "INVALID_PAGINATION"),
        ("get", "/api/incidents?q=" + "x" * 201, None, 422, "QUERY_TOO_LONG"),
        ("post", "/api/incidents", [], 400, "INVALID_JSON"),
        ("post", "/api/incidents", {}, 422, "INVALID_CASE"),
        ("post", "/api/incidents", {"title": "Boundary case", "severity": "bad"}, 422, "INVALID_CASE_PRIORITY"),
        ("post", "/api/incidents", {"title": "Boundary case", "assignee": 99999}, 422, "INVALID_ASSIGNEE"),
        ("post", "/api/incidents", {"title": "Boundary case", "tags": "bad"}, 422, "INVALID_CASE_METADATA"),
        ("post", "/api/incidents", {"title": "Boundary case", "event_ids": ["bad"]}, 422, "INVALID_EVENT_LINKS"),
        ("post", "/api/incidents", {"title": "Boundary case", "alert_ids": ["bad"]}, 422, "INVALID_ALERT_LINKS"),
        ("post", "/api/sources", [], 400, "INVALID_JSON"),
        ("post", "/api/sources", {}, 422, "INVALID_SOURCE_NAME"),
        ("post", "/api/sources", {"name": "Source", "type": "bad"}, 422, "INVALID_SOURCE_TYPE"),
        ("post", "/api/sources", {"name": "Source", "type": "file", "endpoint": 3}, 422, "INVALID_SOURCE_ENDPOINT"),
        ("post", "/api/sources", {"name": "Source", "type": "file", "credential": ""}, 422, "INVALID_SOURCE_CREDENTIAL"),
        ("post", "/api/sources", {"name": "Source", "type": "file", "is_active": 1}, 422, "INVALID_SOURCE_STATE"),
        ("delete", "/api/auth/sessions/99999", {}, 404, "SESSION_NOT_FOUND"),
        ("patch", "/api/admin/users/99999", {}, 404, "USER_NOT_FOUND"),
        ("patch", "/api/admin/users/1", {"role": "bad"}, 422, "INVALID_ROLE"),
        ("patch", "/api/admin/users/1", {"is_active": 1}, 422, "INVALID_USER_STATE"),
        ("patch", "/api/admin/users/1", {"is_active": False}, 409, "SELF_DISABLE_DENIED"),
        ("patch", "/api/admin/users/1", {}, 422, "NO_CHANGES"),
        ("delete", "/api/admin/users/1/mfa", {}, 422, "RESET_REASON_REQUIRED"),
        ("delete", "/api/admin/users/99999/mfa", {"reason": "Verified recovery request"}, 404, "USER_NOT_FOUND"),
    ],
)
def test_invalid_requests_have_stable_errors(client, login_as, method, path, payload, status, code):
    login_as("admin")
    response = client.open(path, method=method, json=payload)
    assert response.status_code == status, response.json
    assert response.json["error"]["code"] == code


@pytest.mark.parametrize(
    "method,path,payload",
    [
        ("get", "/api/incidents/99999", None),
        ("patch", "/api/incidents/99999", {}),
        ("post", "/api/incidents/99999/transitions", {}),
        ("post", "/api/incidents/99999/notes", {}),
        ("post", "/api/incidents/99999/events", {}),
        ("post", "/api/incidents/99999/alerts", {}),
        ("post", "/api/incidents/99999/evidence", {}),
        ("post", "/api/incidents/99999/tasks", {}),
        ("patch", "/api/incidents/99999/tasks/1", {}),
        ("get", "/api/incidents/99999/report", None),
        ("patch", "/api/sources/99999", {}),
        ("post", "/api/sources/99999/test", {}),
    ],
)
def test_missing_resources_never_mutate_state(client, login_as, database, method, path, payload):
    login_as("admin")
    before = database.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
    response = client.open(path, method=method, json=payload)
    assert response.status_code == 404, response.json
    assert database.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == before


def test_case_validation_and_task_lifecycle(client, login_as, user_ids, database):
    login_as("admin")
    case = client.post("/api/incidents", json={"title": "Boundary case"}).json
    url = f"/api/incidents/{case['id']}"
    version = database.execute("SELECT version FROM incident_cases WHERE id = ?", (case["id"],)).fetchone()[0]
    for payload, status in [
        (None, 400),
        ({"version": -1}, 409),
        ({"title": "x"}, 422),
        ({}, 422),
        # With the current version the request reaches field validation, and a refused field changes nothing.
        ({"version": version, "title": "x"}, 422),
        ({"version": version, "severity": "bad"}, 422),
        ({"version": version, "assignee": 99999}, 422),
        ({"version": version, "tags": [3]}, 422),
        ({"version": version}, 422),
        ({"version": version, "unknown_field": 1}, 422),
    ]:
        assert client.patch(url, json=payload).status_code == status, payload
    assert database.execute("SELECT version FROM incident_cases WHERE id = ?", (case["id"],)).fetchone()[0] == version
    for suffix, payload, status in [
        ("transitions", {}, 422),
        ("transitions", {"status": "open", "version": -1}, 409),
        ("transitions", {"status": "open", "reason": ""}, 422),
        ("notes", {"body": ""}, 422),
        ("events", {}, 422),
        ("events", {"event_id": 99999}, 404),
        ("alerts", {}, 422),
        ("alerts", {"alert_id": 99999}, 404),
        ("evidence", [], 400),
        ("evidence", {}, 422),
        ("tasks", {}, 422),
    ]:
        assert client.post(f"{url}/{suffix}", json=payload).status_code == status
    assert client.get(url + "/report?format=pdf").status_code == 422
    assert client.get(url + "/report").status_code == 404  # no archived report yet
    updated = client.patch(
        url,
        json={
            "version": database.execute("SELECT version FROM incident_cases WHERE id = ?", (case["id"],)).fetchone()[0],
            "title": "Updated boundary case",
            "description": "Detailed description",
            "team": "SOC",
            "severity": "high",
            "priority": "urgent",
            "assignee": user_ids["analyst"],
            "tags": ["triage"],
            "mitre_ids": ["T1110"],
        },
    )
    assert updated.status_code == 200, updated.json
    assert updated.json["tags"] == ["triage"]
    task = client.post(url + "/tasks", json={"title": "Verify evidence", "required": True, "assignee": user_ids["analyst"]})
    assert task.status_code == 201
    task_url = f"{url}/tasks/{task.json['id']}"
    assert client.patch(task_url, json={"status": "invalid"}).status_code == 422
    for state in ["in_progress", "completed", "reviewed", "pending"]:
        assert client.patch(task_url, json={"status": state}).json["status"] == state
        stored = next(item for item in client.get(url).json["tasks"] if item["id"] == task.json["id"])
        assert bool(stored["completed_at"]) == (state in {"completed", "reviewed"})
    evidence = {"type": "raw_log", "reference_id": "boundary-log", "title": "Evidence", "content": "Synthetic log"}
    assert client.post(url + "/evidence", json=evidence).status_code == 201
    assert client.post(url + "/evidence", json=evidence).status_code == 409


def test_admin_role_changes_and_mfa_recovery(client, login_as, user_ids, database):
    login_as("admin")
    identifier = user_ids["analyst"]
    response = client.patch(f"/api/admin/users/{identifier}", json={"role": "auditor", "is_active": False})
    assert response.status_code == 200
    assert response.json["role"] == "auditor"
    assert response.json["is_active"] == 0
    assert database.execute("SELECT role FROM workspace_memberships WHERE user_id = ?", (identifier,)).fetchone()[0] == "auditor"
    assert client.delete(f"/api/admin/users/{identifier}/mfa", json={"reason": "Verified recovery request"}).status_code == 204
