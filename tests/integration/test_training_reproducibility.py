import pytest

from socify import training


def new_run(client, login_as):
    login_as("analyst")
    scenario_id = client.get("/api/scenarios").json["items"][0]["id"]
    response = client.post("/api/training/runs", json={"scenario_id": scenario_id, "seed": 42, "playback_rate": 2})
    assert response.status_code == 201
    return scenario_id, response.json["id"]


def test_restart_pins_original_version_after_new_publication(client, login_as):
    scenario_id, run_id = new_run(client, login_as)
    original = client.get(f"/api/training/runs/{run_id}").json
    login_as("instructor")
    version = client.post(
        f"/api/scenarios/{scenario_id}/versions",
        json={
            "name": "Replacement scenario",
            "description": "Different exercise",
            "objectives": ["Replacement objective"],
            "steps": [{"name": "Replacement step", "event": {"source": "new-version"}}],
        },
    )
    assert version.status_code == 201
    for state in ("validated", "published"):
        assert client.post(f"/api/scenarios/{scenario_id}/transition", json={"state": state}).status_code == 200
    login_as("analyst")
    restarted = client.post(f"/api/training/runs/{run_id}/restart", json={})
    assert restarted.status_code == 201
    replacement = client.get(f"/api/training/runs/{restarted.json['id']}").json
    assert replacement["scenario_version_id"] == original["scenario_version_id"]
    assert replacement["seed"] == 42
    assert replacement["playback_rate"] == 2
    assert replacement["total_steps"] == original["total_steps"] == 6
    assert client.get(f"/api/training/runs/{run_id}").json["state"] == "cancelled"


def test_restart_failure_keeps_original_run_and_no_partial_replacement(client, login_as, database, monkeypatch):
    _, run_id = new_run(client, login_as)
    before = database.execute("SELECT COUNT(*) FROM training_runs").fetchone()[0]

    def failing_audit(*args, **kwargs):
        raise RuntimeError("Injected restart audit failure")

    monkeypatch.setattr(training, "record_audit", failing_audit)
    with pytest.raises(RuntimeError, match="Injected restart"):
        client.post(f"/api/training/runs/{run_id}/restart", json={})
    assert client.get(f"/api/training/runs/{run_id}").json["state"] == "running"
    assert database.execute("SELECT COUNT(*) FROM training_runs").fetchone()[0] == before


def test_analyst_hints_require_consumption_and_audit_failure_rolls_back(client, login_as, database, monkeypatch):
    scenario_id, run_id = new_run(client, login_as)
    assert all(step["visible_hint"] is None for step in client.get(f"/api/scenarios/{scenario_id}").json["steps"])
    url = f"/api/training/runs/{run_id}"
    hint = client.post(url + "/hints", json={})
    assert hint.status_code == 200
    assert hint.json["hint"]
    assert hint.json["hints_used"] == 1

    def failing_action(*args, **kwargs):
        raise RuntimeError("Injected hint audit failure")

    monkeypatch.setattr(training, "record_training_action", failing_action)
    with pytest.raises(RuntimeError, match="Injected hint"):
        client.post(url + "/hints", json={})
    assert client.get(url).json["hints_used"] == 1
    assert database.execute("SELECT COUNT(*) FROM trainee_actions WHERE run_id = ? AND action_type = 'hint_used'", (run_id,)).fetchone()[0] == 1
