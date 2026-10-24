import json

import pytest


def test_import_to_case_annotation_timeline_and_report(client, login_as):
    login_as("soc_manager")
    case_id = client.post("/api/incidents", json={"title": "Log dissection exercise"}).json["id"]
    url = f"/api/incidents/{case_id}"
    content = "\n".join(
        json.dumps(
            {
                "source": "incident-fixture",
                "title": f"Incident log {i}",
                "event_type": "failed_login",
                "source_ip": "198.51.100.20",
                "event_time": "2026-10-24T01:00:00Z",
            }
        )
        for i in range(205)
    )
    imported = client.post("/api/imports", json={"filename": "incident.jsonl", "content": content})
    assert imported.status_code == 201
    job_id = imported.json["id"]
    first = client.post(url + "/imports", json={"job_id": job_id})
    assert first.status_code == 200
    assert first.json["added"] == 200
    assert first.json["has_more"] is True
    second = client.post(url + "/imports", json={"job_id": job_id, "after_id": first.json["next_after_id"]})
    assert second.json["added"] == 5
    assert second.json["has_more"] is False
    assert client.post(url + "/imports", json={"job_id": job_id}).json["added"] == 0
    detail = client.get(url).json
    assert len(detail["events"]) == 205
    event_id = detail["events"][0]["id"]
    payload = {"technique_id": "T1110", "assessment": "verified", "event_id": event_id, "reason": "Repeated authentication failures in the linked source"}
    assert client.post(url + "/techniques", json=payload).status_code == 201
    assert client.get(url).json["technique_annotations"][0]["event_id"] == event_id
    assert len(client.get(f"/api/visualizations/timeline?case_id={case_id}&limit=500").json["items"]) == 205
    client.post(url + "/notes", json={"body": "PRIVATE-MARKER", "visibility": "private"})
    client.post(url + "/notes", json={"body": "Reviewed <script>attack()</script>", "visibility": "team"})
    for task in detail["tasks"]:
        assert client.patch(f"{url}/tasks/{task['id']}", json={"status": "completed"}).status_code == 200
    for status in ("investigating", "contained", "recovered"):
        assert client.post(url + "/transitions", json={"status": status, "reason": "Reviewed incident phase"}).status_code == 200
    closure = {"status": "closed", "reason": "Verified completed incident"}
    closure.update(
        {
            key: "Reviewed supporting evidence"
            for key in ("disposition", "root_cause", "impact", "response_summary", "evidence_summary", "validation", "lessons_learned")
        }
    )
    assert client.post(url + "/transitions", json=closure).status_code == 200
    report = client.get(url + "/report").json
    assert len(report["event_timeline"]) == 205
    assert report["technique_annotations"][0]["technique_id"] == "T1110"
    assert len(report["tasks"]) == 2
    html = client.get(url + "/report?format=html").text
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "PRIVATE-MARKER" not in html
    assert client.post(url + "/imports", json={"job_id": job_id}).status_code == 409
    assert client.post(url + "/techniques", json=payload).status_code == 409


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
def test_invalid_annotation_does_not_mutate_case(client, login_as, payload):
    login_as("analyst")
    case_id = client.post("/api/incidents", json={"title": "Validation exercise"}).json["id"]
    response = client.post(f"/api/incidents/{case_id}/techniques", json=payload)
    assert response.status_code in {400, 422}
    assert client.get(f"/api/incidents/{case_id}").json["technique_annotations"] == []


def test_case_enum_inputs_are_rejected_without_server_error(client, login_as):
    login_as("analyst")
    case_id = client.post("/api/incidents", json={"title": "Enum validation"}).json["id"]
    url = f"/api/incidents/{case_id}"
    assert client.patch(url, json={"severity": []}).status_code == 422
    assert client.post(url + "/notes", json={"body": "Invalid scope", "visibility": []}).status_code == 422
    task_id = client.get(url).json["tasks"][0]["id"]
    assert client.patch(f"{url}/tasks/{task_id}", json={"status": []}).status_code == 422
    assert client.post(url + "/imports", json={"job_id": True}).status_code == 422


def test_incident_actions_cannot_cross_training_scope(client, login_as):
    login_as("soc_manager")
    scenario_id = client.get("/api/scenarios").json["items"][0]["id"]
    run_id = client.post("/api/training/runs", json={"scenario_id": scenario_id}).json["id"]
    private_id = client.post("/api/incidents", json={"title": "Private incident", "training_run_id": run_id}).json["id"]
    job_id = client.post("/api/imports", json={"filename": "private.jsonl", "training_run_id": run_id, "content": '{"source":"private-case"}'}).json["id"]
    shared_id = client.post("/api/incidents", json={"title": "Shared incident"}).json["id"]
    assert client.post(f"/api/incidents/{shared_id}/imports", json={"job_id": job_id}).status_code == 404
    login_as("analyst")
    assert client.post(f"/api/incidents/{private_id}/imports", json={"job_id": job_id}).status_code == 404
    assert (
        client.post(
            f"/api/incidents/{private_id}/techniques", json={"technique_id": "T1110", "assessment": "suggested", "reason": "Unauthorized finding"}
        ).status_code
        == 404
    )
