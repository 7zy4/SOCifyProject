"""Retained detection work stays inspectable and retries keep their original scope."""

import pytest

from socify.autopsy_worker import run_autopsy_worker_once


def queued(client, case):
    path = f"/api/cases/{case}"
    response = client.post(path + "/detection", json={"version": client.get(path).json["version"], "mode": "rules"})
    assert response.status_code == 202, response.json
    return response.json["id"]


def test_detection_history_retains_result_and_state(autopsy_case, client, app):
    path = f"/api/cases/{autopsy_case}"
    identifier = queued(client, autopsy_case)
    first = client.get(path + "/detection").json
    assert first["items"][0]["can_cancel"] and not first["items"][0]["result_record_id"]
    with app.app_context():
        run_autopsy_worker_once()
    result = client.get(path + f"/jobs/{identifier}").json
    assert result["state"] == "completed" and result["result_record_id"]
    assert not result["can_cancel"] and not result["can_retry"]
    assert "parameters" not in result and "worker_id" not in result
    assert client.get(path + "/detection").json["items"] == [result]
    record = client.get(path + "/records?kind=analysis").json["items"][0]
    assert record["id"] == result["result_record_id"] and record["payload"]["evaluated_events"] == 0


def test_detection_history_pages_without_losing_older_work(autopsy_case, client):
    path = f"/api/cases/{autopsy_case}"
    identifiers = []
    for _ in range(26):
        identifier = queued(client, autopsy_case)
        identifiers.append(identifier)
        assert client.post(path + f"/jobs/{identifier}/cancel").status_code == 200
    first, second = client.get(path + "/detection").json, client.get(path + "/detection?page=2").json
    assert first["has_next"] and len(first["items"]) == 25
    assert not second["has_next"] and [row["id"] for row in second["items"]] == identifiers[:1]
    assert [row["id"] for row in first["items"]] == identifiers[:0:-1]


@pytest.mark.parametrize("query", ["page=0", "page=-1", "page=1000001", "page=abc", "unknown=1"])
def test_detection_history_rejects_invalid_page(autopsy_case, client, query):
    assert client.get(f"/api/cases/{autopsy_case}/detection?{query}").status_code == 422


@pytest.mark.parametrize("change", ["version", "closed"])
def test_retry_rejects_changed_detection_scope(autopsy_case, client, database, change):
    path = f"/api/cases/{autopsy_case}"
    identifier = queued(client, autopsy_case)
    assert client.post(path + f"/jobs/{identifier}/cancel").status_code == 200
    assert client.get(path + f"/jobs/{identifier}").json["can_retry"]
    if change == "version":
        database.execute("UPDATE incident_cases SET version=version+1 WHERE id=?", (autopsy_case,))
    else:
        database.execute("UPDATE incident_cases SET status='closed' WHERE id=?", (autopsy_case,))
    assert not client.get(path + f"/jobs/{identifier}").json["can_retry"]
    assert client.post(path + f"/jobs/{identifier}/retry").status_code == 409
    assert client.get(path + f"/jobs/{identifier}").json["state"] == "cancelled"


def test_detection_control_stays_with_creator_or_manager(autopsy_case, client, login_as):
    login_as("soc_manager")
    identifier = queued(client, autopsy_case)
    path = f"/api/cases/{autopsy_case}/jobs/{identifier}"
    login_as("analyst")
    assert not client.get(path).json["can_cancel"]
    assert client.post(path + "/cancel").status_code == 403
    login_as("soc_manager")
    assert client.post(path + "/cancel").status_code == 200
    assert client.post(path + "/retry").status_code == 200


def test_detection_history_excludes_foreign_case_jobs(autopsy_case, client):
    identifier = queued(client, autopsy_case)
    other = client.post("/api/cases", json={"title": "Independent investigation", "reason": "alert_review", "objective": "Keep analysis evidence scoped"}).json[
        "id"
    ]
    assert client.get(f"/api/cases/{other}/detection").json["items"] == []
    assert client.get(f"/api/cases/{other}/jobs/{identifier}").status_code == 404
