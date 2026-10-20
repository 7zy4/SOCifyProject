import pytest


def make_playbook(client, steps):
    payload = {"name": "Response regression", "steps": steps, "publish": True}
    response = client.post("/api/playbooks", json=payload)
    assert response.status_code == 201
    return response.json["id"], payload


def test_playbook_version_preview_and_context_validation(client, login_as):
    login_as("admin")
    identifier, payload = make_playbook(client, [{"action": "notify_training_team"}])
    assert client.post(f"/api/playbooks/{identifier}/versions", json=payload).json["version"] == 2
    assert client.post(f"/api/playbooks/{identifier}/versions", json={}).status_code == 422
    assert client.post("/api/playbooks/99999/versions", json=payload).status_code == 404
    preview_url = f"/api/playbooks/{identifier}/preview"
    assert client.post(preview_url, json=[]).status_code == 400
    for patch, expected in [({"case_id": "bad"}, 422), ({"case_id": 99999}, 404), ({"training_run_id": 99999}, 404), ({"parameters": []}, 422), ({"parameters": {str(i): i for i in range(31)}}, 422), ({"parameters": {"x": "x" * 10001}}, 422)]:
        assert client.post(preview_url, json=patch).status_code == expected
        assert client.post("/api/playbook-runs", json={"playbook_id": identifier, **patch}).status_code == expected
    assert client.post("/api/playbook-runs", json={"playbook_id": identifier}).status_code == 422
    result = client.post("/api/playbook-runs", json={"playbook_id": identifier, "idempotency_key": "notification-regression"})
    assert result.status_code == 201
    assert result.json["state"] == "succeeded"
    assert result.json["steps"][0]["output"]["after"] == {"notification": "queued"}
    for action in ["approve", "retry", "cancel"]:
        assert client.post(f"/api/playbook-runs/{result.json['id']}/{action}", json={}).status_code == 409


@pytest.mark.parametrize("action", ["approve", "retry", "cancel", "rollback"])
def test_missing_response_runs(client, login_as, action):
    login_as("admin")
    assert client.post(f"/api/playbook-runs/99999/{action}", json={}).status_code == 404
    assert client.get("/api/playbook-runs/99999").status_code == 404


def test_all_simulation_actions_record_real_internal_effects(client, login_as, database):
    login_as("admin")
    case_id = client.post("/api/incidents", json={"title": "Response action coverage"}).json["id"]
    event_id = client.post("/api/events", json={"source": "ioc-fixture", "source_ip": "192.0.2.20"}).json["id"]
    ioc_id = client.post("/api/iocs/extract", json={"event_id": event_id}).json["items"][0]["id"]
    assert client.post("/api/iocs/extract", json={"event_id": event_id}).json["items"][0]["id"] == ioc_id
    assert client.get("/api/iocs").json["items"][0]["id"] == ioc_id
    actions = [
        ("disable_training_account", {"username": "synthetic-user"}, "disabled"),
        ("force_reset_synthetic_credentials", {"username": "synthetic-user"}, "credentials_rotated"),
        ("contain_simulated_exfiltration", {"channel": "training-channel"}, "contained"),
        ("restore_virtual_service", {"service": "virtual-service"}, "available"),
    ]
    steps = [{"action": action, "parameters": parameters} for action, parameters, _ in actions]
    steps += [{"action": "collect_evidence"}, {"action": "escalate_to_manager"}, {"action": "tag_ioc", "parameters": {"ioc_id": ioc_id, "tag": "reviewed"}}]
    identifier, _ = make_playbook(client, steps)
    result = client.post("/api/playbook-runs", json={"playbook_id": identifier, "case_id": case_id, "idempotency_key": "all-actions-regression"})
    assert result.status_code == 201
    assert result.json["state"] == "succeeded"
    for step, (_, _, state) in zip(result.json["steps"][:4], actions, strict=True):
        assert step["output"]["after"]["state"] == state
    detail = client.get(f"/api/incidents/{case_id}").json
    assert detail["status"] == "escalated"
    assert any(item["title"] == "Playbook evidence collection" for item in detail["evidence"])
    assert "reviewed" in client.get("/api/iocs").json["items"][0]["tags"]
    assert database.execute("SELECT COUNT(*) FROM response_simulation_state").fetchone()[0] >= 3
    login_as("analyst")
    assert client.get(f"/api/playbook-runs/{result.json['id']}").status_code == 404


@pytest.mark.parametrize("action,parameters,error", [
    ("collect_evidence", {}, "requires a case"),
    ("escalate_to_manager", {}, "requires a case"),
    ("tag_ioc", {}, "required"),
    ("tag_ioc", {"ioc_id": 99999, "tag": "review"}, "not found"),
])
def test_failed_response_keeps_error_and_limits_retry(client, login_as, action, parameters, error):
    login_as("admin")
    identifier, _ = make_playbook(client, [{"action": action, "parameters": parameters, "retry_limit": 2}])
    result = client.post("/api/playbook-runs", json={"playbook_id": identifier, "idempotency_key": "failure-regression"})
    assert result.status_code == 201
    assert result.json["state"] == "failed"
    assert error in result.json["steps"][0]["error"]
    url = f"/api/playbook-runs/{result.json['id']}"
    assert client.post(url + "/rollback", json={}).status_code == 409
    retried = client.post(url + "/retry", json={})
    assert retried.json["state"] == "failed"
    assert retried.json["steps"][0]["attempt"] == 2
    assert client.post(url + "/retry", json={}).status_code == 409
    assert client.post(url + "/cancel", json={}).json["state"] == "cancelled"


@pytest.mark.parametrize("suffix", ["play", "pause", "resume", "restart", "hints", "ground-truth", "score"])
def test_missing_training_runs_are_hidden(client, login_as, suffix):
    login_as("admin")
    method = "get" if suffix in {"ground-truth", "score"} else "post"
    assert client.open(f"/api/training/runs/99999/{suffix}", method=method, json={}).status_code == 404


def test_training_hints_and_score_read_models(client, login_as, database):
    login_as("analyst")
    scenario = client.get("/api/scenarios").json["items"][0]
    assert client.post("/api/training/runs", json={}).status_code == 422
    assert client.post("/api/training/runs", json={"scenario_id": 99999}).status_code == 404
    assert client.post("/api/training/runs", json={"scenario_id": scenario["id"], "difficulty": "invalid"}).status_code == 422
    run = client.post("/api/training/runs", json={"scenario_id": scenario["id"], "seed": 123}).json
    url = f"/api/training/runs/{run['id']}"
    assert client.get(url + "/score").status_code == 409
    assert client.post(url + "/play", json={"steps": "bad"}).status_code == 422
    hint = client.post(url + "/hints", json={})
    assert hint.status_code == 200
    assert hint.json["hints_used"] == 1
    assert client.post(url + "/hints", json={}).json["hints_used"] == 2
    assert client.post(url + "/pause", json={}).status_code == 200
    assert client.post(url + "/pause", json={}).status_code == 409
    assert client.post(url + "/play", json={}).status_code == 409
    assert client.post(url + "/resume", json={}).status_code == 200
    completed = client.post(url + "/play", json={"steps": 50})
    assert completed.status_code == 200
    score = completed.json["assessment"]
    assert client.get(f"/api/assessments/{score['id']}").json["calculation_fingerprint"] == score["calculation_fingerprint"]
    assert client.get("/api/assessments/99999").status_code == 404
    assert len(client.get("/api/scores/me").json["items"]) == 1
    assert len(client.get(f"/api/leaderboards?scenario_id={scenario['id']}&difficulty=beginner").json["items"]) == 1
    login_as("admin")
    assert client.get(f"/api/assessments/{score['id']}").status_code == 200
    version_id = database.execute("SELECT scenario_version_id FROM training_runs WHERE id = ?", (run["id"],)).fetchone()[0]
    database.execute("UPDATE scenario_steps SET visible_hint = NULL WHERE scenario_version_id = ?", (version_id,))
    assert client.post(url + "/hints", json={}).status_code == 404
