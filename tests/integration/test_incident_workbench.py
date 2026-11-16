import pytest


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"technique_id": []},
        {"technique_id": "T999999", "reason": "Invalid catalog", "assessment": "suggested"},
        {"technique_id": "T1110", "reason": "Missing evidence", "assessment": "verified"},
        {"technique_id": "T1110", "reason": "Unrelated evidence", "assessment": "verified", "event_id": 999999},
    ],
)
def test_invalid_annotation_does_not_mutate_case(client, login_as, database, payload):
    login_as("analyst")
    case_id = client.post("/api/incidents", json={"title": "Validation exercise"}).json["id"]
    response = client.post(f"/api/incidents/{case_id}/techniques", json=payload)
    assert response.status_code in {400, 422}
    assert database.execute("SELECT COUNT(*) FROM case_technique_annotations WHERE case_id = ?", (case_id,)).fetchone()[0] == 0


def test_case_enum_inputs_are_rejected_without_server_error(client, login_as):
    login_as("analyst")
    case_id = client.post("/api/incidents", json={"title": "Enum validation"}).json["id"]
    url = f"/api/incidents/{case_id}"
    assert client.patch(url, json={"severity": []}).status_code == 422
    assert client.post(url + "/notes", json={"body": "Invalid scope", "visibility": []}).status_code == 422
    task_id = client.get(url).json["tasks"][0]["id"]
    assert client.patch(f"{url}/tasks/{task_id}", json={"status": []}).status_code == 422
    assert client.post(url + "/imports", json={"job_id": True}).status_code == 422
