import pytest


@pytest.mark.parametrize(
    "method,path,payload,status,code",
    [
        ("get", "/api/incidents?page=no", None, 400, "INVALID_PAGINATION"),
        ("get", "/api/incidents?q=" + "x" * 201, None, 422, "QUERY_TOO_LONG"),
        ("get", "/api/alerts?page=no", None, 400, "INVALID_PAGINATION"),
        ("get", "/api/events?page=no", None, 400, "INVALID_PAGINATION"),
        ("post", "/api/incidents", [], 400, "INVALID_JSON"),
        ("post", "/api/incidents", {}, 422, "INVALID_CASE"),
        ("post", "/api/incidents", {"title": "Boundary case", "severity": "bad"}, 422, "INVALID_CASE_PRIORITY"),
        ("post", "/api/incidents", {"title": "Boundary case", "assignee": 99999}, 422, "INVALID_ASSIGNEE"),
        ("post", "/api/incidents", {"title": "Boundary case", "tags": "bad"}, 422, "INVALID_CASE_METADATA"),
        ("post", "/api/incidents", {"title": "Boundary case", "event_ids": ["bad"]}, 422, "INVALID_EVENT_LINKS"),
        ("post", "/api/incidents", {"title": "Boundary case", "alert_ids": ["bad"]}, 422, "INVALID_ALERT_LINKS"),
        ("post", "/api/rules", [], 400, "INVALID_JSON"),
        ("post", "/api/rules/1/toggle", {}, 422, "INVALID_TOGGLE"),
        ("post", "/api/rules/1/rollback", {}, 422, "VERSION_REQUIRED"),
        ("post", "/api/rules/1/rollback", {"version": 99999}, 404, "RULE_VERSION_NOT_FOUND"),
        ("post", "/api/rules/1/test", {}, 422, "EVENT_ID_REQUIRED"),
        ("post", "/api/rules/1/test", {"event_id": 99999}, 404, "EVENT_NOT_FOUND"),
        ("post", "/api/rules/1/backfill", {}, 422, "BACKFILL_REASON_REQUIRED"),
        ("post", "/api/rules/1/backfill", {"reason": "Boundary regression", "limit": "bad"}, 422, "INVALID_BACKFILL_LIMIT"),
        ("post", "/api/alerts/99999/triage", {}, 422, "INVALID_ALERT_STATUS"),
        ("post", "/api/alerts/99999/triage", {"status": "triaged"}, 404, "ALERT_NOT_FOUND"),
        ("post", "/api/hunt/query", {"query": []}, 422, "INVALID_QUERY"),
        ("post", "/api/hunt/query", {"query": "", "page": "bad"}, 422, "INVALID_PAGINATION"),
        ("post", "/api/hunt/saved-queries", {}, 422, "INVALID_SAVED_QUERY"),
        ("post", "/api/hunt/saved-queries", {"name": "Saved", "query": "", "visibility": "bad"}, 403, "INVALID_QUERY_VISIBILITY"),
        ("post", "/api/hunt/saved-queries", {"name": "Saved", "query": "invalid = 1"}, 422, "INVALID_HUNT_QUERY"),
        ("post", "/api/hunt/saved-queries", {"name": "Saved", "query": "", "tags": [123]}, 422, "INVALID_TAGS"),
        ("delete", "/api/hunt/saved-queries/99999", {}, 404, "SAVED_QUERY_NOT_FOUND"),
        ("post", "/api/iocs/extract", {}, 422, "EVENT_ID_REQUIRED"),
        ("post", "/api/iocs/extract", {"event_id": 99999}, 404, "EVENT_NOT_FOUND"),
        ("post", "/api/iocs/99999/enrich", {}, 404, "IOC_NOT_FOUND"),
        ("post", "/api/sources", [], 400, "INVALID_JSON"),
        ("post", "/api/sources", {}, 422, "INVALID_SOURCE_NAME"),
        ("post", "/api/sources", {"name": "Source", "type": "bad"}, 422, "INVALID_SOURCE_TYPE"),
        ("post", "/api/sources", {"name": "Source", "type": "file", "endpoint": 3}, 422, "INVALID_SOURCE_ENDPOINT"),
        ("post", "/api/sources", {"name": "Source", "type": "file", "credential": ""}, 422, "INVALID_SOURCE_CREDENTIAL"),
        ("post", "/api/sources", {"name": "Source", "type": "file", "is_active": 1}, 422, "INVALID_SOURCE_STATE"),
        ("post", "/api/scenarios", [], 400, "INVALID_JSON"),
        ("post", "/api/scenarios", {}, 422, "INVALID_SCENARIO"),
        ("post", "/api/playbooks", [], 400, "INVALID_JSON"),
        ("post", "/api/playbooks", {}, 422, "INVALID_PLAYBOOK"),
        ("post", "/api/playbooks", {"name": "Playbook", "steps": []}, 422, "INVALID_PLAYBOOK_STEPS"),
        ("post", "/api/playbooks", {"name": "Playbook", "steps": [{"action": "shell"}]}, 422, "UNSAFE_PLAYBOOK_ACTION"),
        ("post", "/api/playbooks", {"name": "Playbook", "steps": [{"action": "tag_ioc", "position": "x"}]}, 422, "INVALID_PLAYBOOK_STEP"),
        ("post", "/api/playbooks", {"name": "Playbook", "steps": [{"action": "tag_ioc", "parameters": {"x": "x" * 5001}}]}, 422, "INVALID_PLAYBOOK_STEP"),
        ("post", "/api/playbook-runs", {}, 422, "PLAYBOOK_REQUIRED"),
        ("post", "/api/playbook-runs", {"playbook_id": 99999}, 404, "PLAYBOOK_NOT_FOUND"),
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
        ("get", "/api/rules/99999", None),
        ("put", "/api/rules/99999", {}),
        ("delete", "/api/rules/99999", {}),
        ("post", "/api/rules/99999/clone", {}),
        ("post", "/api/rules/99999/backfill", {}),
        ("post", "/api/rules/99999/toggle", {"active": True}),
        ("post", "/api/rules/99999/test", {}),
        ("get", "/api/rules/99999/versions", None),
        ("get", "/api/alerts/99999", None),
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
        ("get", "/api/events/99999", None),
        ("get", "/api/events/99999/raw", None),
        ("put", "/api/events/99999", {}),
        ("delete", "/api/events/99999", {}),
        ("patch", "/api/sources/99999", {}),
        ("post", "/api/sources/99999/test", {}),
        ("get", "/api/scenarios/99999", None),
        ("post", "/api/scenarios/99999/transition", {}),
        ("post", "/api/scenarios/99999/versions", {}),
        ("post", "/api/playbooks/99999/preview", {}),
    ],
)
def test_missing_resources_never_mutate_state(client, login_as, database, method, path, payload):
    login_as("admin")
    before = database.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
    response = client.open(path, method=method, json=payload)
    assert response.status_code == 404, response.json
    assert database.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == before


def test_case_validation_and_task_lifecycle(client, login_as, user_ids):
    login_as("admin")
    case = client.post("/api/incidents", json={"title": "Boundary case"}).json
    url = f"/api/incidents/{case['id']}"
    for payload, status in [
        (None, 400),
        ({"version": -1}, 409),
        ({"title": "x"}, 422),
        ({"severity": "bad"}, 422),
        ({"assignee": 99999}, 422),
        ({"tags": [3]}, 422),
        ({}, 422),
    ]:
        assert client.patch(url, json=payload).status_code == status
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
    assert client.get(url + "/report").status_code == 409
    updated = client.patch(
        url,
        json={
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
    assert updated.status_code == 200
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


def test_backfill_preserves_activation_and_is_idempotent(client, login_as, database):
    login_as("admin")
    rule = client.post(
        "/api/rules",
        json={"name": "Backfill regression", "dsl": {"condition": {"field": "source", "operator": "equals", "value": "backfill-fixture"}}, "active": False},
    )
    assert rule.status_code == 201
    event = client.post("/api/events", json={"source": "backfill-fixture"})
    assert event.status_code == 201
    before = [tuple(row) for row in database.execute("SELECT id, is_active FROM rules ORDER BY id")]
    url = f"/api/rules/{rule.json['id']}/backfill"
    response = client.post(url, json={"reason": "Historical event regression"})
    assert response.status_code == 200
    assert len(response.json["created_alert_ids"]) == 1
    assert client.post(url, json={"reason": "Historical event regression"}).json["created_alert_ids"] == []
    assert [tuple(row) for row in database.execute("SELECT id, is_active FROM rules ORDER BY id")] == before
    alert_id = response.json["created_alert_ids"][0]
    triage_url = f"/api/alerts/{alert_id}/triage"
    assert client.post(triage_url, json={"status": "false_positive"}).status_code == 422
    assert client.post(triage_url, json={"status": "triaged", "assignee": 99999}).status_code == 422
    assert client.post(triage_url, json={"status": "false_positive", "reason": "Confirmed synthetic false positive"}).status_code == 200
    assert client.get("/api/alerts?status=false_positive&severity=medium").json["total"] == 1
    case_id = client.post("/api/incidents", json={"title": "Attach alert and event"}).json["id"]
    assert client.post(f"/api/incidents/{case_id}/alerts", json={"alert_id": alert_id}).status_code == 201
    assert client.post(f"/api/incidents/{case_id}/events", json={"event_id": event.json["id"]}).status_code == 201
    detail = client.get(f"/api/incidents/{case_id}").json
    assert len(detail["events"]) == 1
    assert len(detail["alerts"]) == 1
    assert len(detail["evidence"]) == 2
