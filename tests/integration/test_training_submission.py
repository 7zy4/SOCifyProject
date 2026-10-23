import sqlite3
from collections.abc import Callable

from flask.testing import FlaskClient


def _start(client: FlaskClient) -> int:
    scenario = client.get("/api/scenarios").json["items"][0]
    response = client.post("/api/training/runs", json={"scenario_id": scenario["id"], "seed": 105})
    assert response.status_code == 201
    return int(response.json["id"])


def _finish_playback(client: FlaskClient, run_id: int) -> dict:
    response = client.post(f"/api/training/runs/{run_id}/play", json={"steps": 50})
    assert response.status_code == 200
    assert response.json["state"] == "awaiting_submission"
    return response.json


def test_submission_is_required_after_playback(client: FlaskClient, login_as: Callable[[str], None], database: sqlite3.Connection) -> None:
    login_as("analyst")
    run_id = _start(client)
    assert client.post(f"/api/training/runs/{run_id}/submit", json={}).status_code == 409
    assert client.get(f"/api/training/runs/{run_id}/score").status_code == 409
    playback = _finish_playback(client, run_id)
    assert "assessment" not in playback
    assert client.get(f"/api/training/runs/{run_id}/score").status_code == 409
    assert database.execute("SELECT COUNT(*) FROM assessment_snapshots WHERE run_id = ?", (run_id,)).fetchone()[0] == 0
    tampered = client.post(
        f"/api/training/runs/{run_id}/submit",
        json={"total_score": 100, "submitted_at": "2000-01-01T00:00:00Z", "ground_truth": {"passed": True}},
    )
    assert tampered.status_code == 422
    assert tampered.json["error"]["code"] == "SUBMISSION_FIELDS_FORBIDDEN"
    ground_truth_tamper = client.post(f"/api/training/runs/{run_id}/ground-truth", json={"expected_detections": []})
    assert ground_truth_tamper.status_code == 405
    denied = database.execute(
        "SELECT resource_type, result, details FROM security_audit_logs WHERE action = 'tamper' AND resource_id = ? ORDER BY id",
        (str(run_id),),
    ).fetchall()
    assert [(row["resource_type"], row["result"]) for row in denied] == [
        ("training_submission", "denied"),
        ("scenario_ground_truth", "denied"),
    ]
    assert "total_score" in denied[0]["details"]
    own = client.get("/api/training/runs")
    assert any(item["id"] == run_id and item["state"] == "awaiting_submission" for item in own.json["items"])
    submitted = client.post(f"/api/training/runs/{run_id}/submit", json={})
    assert submitted.status_code == 200
    assert submitted.json["state"] == "completed"
    assert submitted.json["assessment"]["policy_version"] == "socify-score-v4"
    assert submitted.json["assessment"]["components"]["metrics"]["true_positives"] == 0
    again = client.post(f"/api/training/runs/{run_id}/submit", json={})
    assert again.status_code == 200
    assert again.json["assessment"]["id"] == submitted.json["assessment"]["id"]
    assert database.execute("SELECT COUNT(*) FROM assessment_snapshots WHERE run_id = ?", (run_id,)).fetchone()[0] == 1


def test_training_decisions_not_automated_alerts_earn_detection_credit(
    client: FlaskClient, login_as: Callable[[str], None], database: sqlite3.Connection
) -> None:
    login_as("analyst")
    empty_run = _start(client)
    _finish_playback(client, empty_run)
    empty_score = client.post(f"/api/training/runs/{empty_run}/submit", json={}).json["assessment"]
    assert empty_score["components"]["metrics"]["true_positives"] == 0
    scored_run = _start(client)
    _finish_playback(client, scored_run)
    target = database.execute(
        """SELECT a.id FROM alerts a JOIN rules r ON r.id = a.rule_id
           WHERE a.training_run_id = ? AND r.name = 'Five failed logins in ten minutes'
           LIMIT 1""",
        (scored_run,),
    ).fetchone()
    assert target is not None
    triaged = client.post(f"/api/alerts/{target['id']}/triage", json={"status": "triaged"})
    assert triaged.status_code == 200
    scored = client.post(f"/api/training/runs/{scored_run}/submit", json={})
    assert scored.status_code == 200
    metrics = scored.json["assessment"]["components"]["metrics"]
    assert metrics["true_positives"] >= 1
    assert metrics["detection_recall"] > empty_score["components"]["metrics"]["detection_recall"]
    assert scored.json["assessment"]["total_score"] > empty_score["total_score"]


def test_other_user_cannot_submit_training_run(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("analyst")
    run_id = _start(client)
    _finish_playback(client, run_id)
    login_as("instructor")
    assert client.post(f"/api/training/runs/{run_id}/submit", json={}).status_code == 403
    assert not any(item["id"] == run_id for item in client.get("/api/training/runs").json["items"])


def test_response_credit_requires_expected_action_after_scenario_step(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    def execute_response(run_id: int, key: str) -> None:
        case = client.post("/api/incidents", json={"title": f"Response scoring {key}", "training_run_id": run_id})
        assert case.status_code == 201
        playbook_id = client.get("/api/playbooks").json["items"][0]["id"]
        requested = client.post(
            "/api/playbook-runs",
            headers={"Idempotency-Key": key},
            json={"playbook_id": playbook_id, "case_id": case.json["id"], "training_run_id": run_id, "parameters": {}},
        )
        assert requested.status_code == 201
        login_as("soc_manager")
        approved = client.post(f"/api/playbook-runs/{requested.json['id']}/approve", json={})
        assert approved.status_code == 200
        assert approved.json["state"] == "succeeded"
        login_as("analyst")

    login_as("analyst")
    valid_run = _start(client)
    _finish_playback(client, valid_run)
    execute_response(valid_run, "scoring-valid-response")
    valid = client.post(f"/api/training/runs/{valid_run}/submit", json={}).json["assessment"]
    assert valid["components"]["metrics"]["playbook_compliance"] == 1
    assert valid["components"]["metrics"]["incorrect_response_actions"] == 0
    assert valid["inputs"]["matched_response_actions"] == [["exfiltration", "contain_simulated_exfiltration"]]

    early_run = _start(client)
    execute_response(early_run, "scoring-early-response")
    _finish_playback(client, early_run)
    early = client.post(f"/api/training/runs/{early_run}/submit", json={}).json["assessment"]
    assert early["components"]["metrics"]["playbook_compliance"] == 0
    assert early["components"]["metrics"]["incorrect_response_actions"] == 1
    assert early["inputs"]["matched_response_actions"] == []
