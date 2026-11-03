"""Task navigation and completion preserve case scope and the original contribution."""

import pytest


def add_task(client, case_id, title):
    response = client.post(f"/api/incidents/{case_id}/tasks", json={"title": title})
    assert response.status_code == 201, response.json
    return response.json["id"]


def test_task_pages_and_exact_focus_include_work_older_than_the_summary_limit(autopsy_case, client):
    ids = [add_task(client, autopsy_case, f"Retained review {index:03d}") for index in range(103)]
    base = f"/api/cases/{autopsy_case}/tasks"
    first = client.get(base).json
    assert first["total"] == 105 and first["page_size"] == len(first["items"]) == 25
    assert ids[0] not in {task["id"] for task in first["items"]}
    assert ids[0] not in {task["id"] for task in client.get(f"/api/cases/{autopsy_case}").json["tasks"]}
    focused = client.get(base, query_string={"focus": ids[0]}).json
    assert focused["page"] == 5 and focused["focus"] == ids[0]
    assert ids[0] in {task["id"] for task in focused["items"]}
    assert client.get(base + "?page=999999").json["page"] == 5
    pages = [client.get(base, query_string={"page": page}).json["items"] for page in range(1, 6)]
    all_ids = [task["id"] for tasks in pages for task in tasks]
    assert len(all_ids) == len(set(all_ids)) == 105
    assert all_ids == sorted(all_ids, reverse=True)


def test_literal_task_search_and_status_filters_apply_before_pagination(autopsy_case, client):
    task_id = add_task(client, autopsy_case, "Review 100%_complete evidence")
    add_task(client, autopsy_case, "Review 100xZcomplete evidence")
    base = f"/api/cases/{autopsy_case}/tasks"
    matched = client.get(base, query_string={"q": "%_"}).json
    assert matched["total"] == 1 and matched["items"][0]["id"] == task_id
    assert client.patch(f"/api/incidents/{autopsy_case}/tasks/{task_id}", json={"status": "completed", "expected_status": "pending"}).status_code == 200
    assert client.get(base, query_string={"q": "%_", "status": "pending"}).json["total"] == 0
    assert client.get(base, query_string={"q": "%_", "status": "completed"}).json["total"] == 1
    assert client.get(base, query_string={"focus": task_id, "status": "pending"}).status_code == 404
    assert client.get(base, query_string={"q": "No match", "page": 42}).json["page"] == 1


@pytest.mark.parametrize(
    "query",
    [
        "page=0",
        "page=-1",
        "page=1000001",
        "page=abc",
        "page=1&page=2",
        "status=unknown",
        "focus=0",
        "focus=-1",
        "focus=9223372036854775808",
        "focus=abc",
        "focus=1&focus=2",
        "q=a&q=b",
        "extra=1",
    ],
)
def test_task_list_rejects_invalid_and_duplicate_filters(autopsy_case, client, query):
    response = client.get(f"/api/cases/{autopsy_case}/tasks?{query}")
    assert response.status_code == 422 and response.json["error"]["code"] == "INVALID_TASK_FILTER"


def test_task_list_rejects_oversized_search_and_unknown_focus(autopsy_case, client):
    base = f"/api/cases/{autopsy_case}/tasks"
    assert client.get(base, query_string={"q": "x" * 201}).status_code == 422
    assert client.get(base, query_string={"focus": "9" * 1000}).status_code == 422
    assert client.get(base, query_string={"focus": 9223372036854775807}).status_code == 404


def test_task_focus_does_not_cross_case_membership_or_reveal_another_title(autopsy_case, client, login_as, database):
    login_as("soc_manager")
    other = client.post("/api/cases", json={"title": "Private finance investigation"}).json["id"]
    task_id = add_task(client, other, "Private finance containment decision")
    login_as("analyst")
    assert client.get(f"/api/cases/{other}/tasks").status_code == 404
    response = client.get(f"/api/cases/{autopsy_case}/tasks?focus={task_id}")
    assert response.status_code == 404 and "Private finance" not in response.text
    database.execute("DELETE FROM autopsy_case_members WHERE case_id=?", (autopsy_case,))
    assert client.get(f"/api/cases/{autopsy_case}/tasks").status_code == 404


def test_task_list_respects_approval_selection_and_closed_case_read_only(autopsy_case, app, client, database):
    base = f"/api/cases/{autopsy_case}/tasks"
    app.config["REQUIRE_CASE_APPROVAL"] = True
    database.execute("UPDATE case_approvals SET state='pending' WHERE case_id=?", (autopsy_case,))
    assert client.get(base).status_code == 409
    app.config["REQUIRE_CASE_APPROVAL"] = False
    app.config["REQUIRE_INVESTIGATION_SELECTION"] = True
    assert client.get(base).status_code == 403
    assert client.post("/api/investigation-selection", json={"case_ids": [autopsy_case]}).status_code == 200
    assert all(task["can_update"] for task in client.get(base).json["items"])
    database.execute("UPDATE incident_cases SET status='closed' WHERE id=?", (autopsy_case,))
    assert not any(task["can_update"] for task in client.get(base).json["items"])


def test_repeated_completion_keeps_history_and_stale_reopen_is_rejected(autopsy_case, client, database, login_as, user_ids):
    task_id = add_task(client, autopsy_case, "Retained shared evidence review")
    path = f"/api/incidents/{autopsy_case}/tasks/{task_id}"
    login_as("soc_manager")
    version_before = database.execute("SELECT version FROM incident_cases WHERE id=?", (autopsy_case,)).fetchone()[0]
    completed = client.patch(path, json={"status": "completed", "expected_status": "pending"}).json
    assert completed["updated"] is True
    assert completed["case_version_before"] == version_before
    assert completed["case_version"] == version_before + 1
    before = dict(database.execute("SELECT * FROM case_tasks WHERE id=?", (task_id,)).fetchone())
    history = database.execute("SELECT COUNT(*) FROM case_history WHERE case_id=?", (autopsy_case,)).fetchone()[0]
    login_as("analyst")
    repeated = client.patch(path, json={"status": "completed", "expected_status": "pending"})
    assert repeated.status_code == 200 and repeated.json["updated"] is False
    assert repeated.json["case_version"] == repeated.json["case_version_before"] == completed["case_version"]
    assert dict(database.execute("SELECT * FROM case_tasks WHERE id=?", (task_id,)).fetchone()) == before
    assert database.execute("SELECT COUNT(*) FROM case_history WHERE case_id=?", (autopsy_case,)).fetchone()[0] == history
    assert before["completed_by"] == user_ids["soc_manager"]
    assert client.patch(path, json={"status": "in_progress", "expected_status": "pending"}).status_code == 409
    assert dict(database.execute("SELECT * FROM case_tasks WHERE id=?", (task_id,)).fetchone()) == before
    assert client.patch(path, json={"status": "in_progress", "expected_status": "completed"}).status_code == 200
    reopened = database.execute("SELECT * FROM case_tasks WHERE id=?", (task_id,)).fetchone()
    assert reopened["completed_by"] is None and reopened["completed_at"] is None
