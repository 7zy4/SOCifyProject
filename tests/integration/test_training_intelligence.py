import sqlite3
from collections.abc import Callable
from datetime import datetime

from flask.testing import FlaskClient


def scenario_id(client: FlaskClient) -> int:
    response = client.get("/api/scenarios")
    assert response.status_code == 200
    assert response.json["items"]
    return int(response.json["items"][0]["id"])


def start_run(client: FlaskClient, difficulty: str = "beginner", seed: int = 20261019) -> int:
    response = client.post(
        "/api/training/runs",
        json={"scenario_id": scenario_id(client), "difficulty": difficulty, "seed": seed, "auto_play": False},
    )
    assert response.status_code == 201
    return int(response.json["id"])


def complete_run(client: FlaskClient, difficulty: str = "beginner", seed: int = 20261019):
    run_id = start_run(client, difficulty, seed)
    result = client.post(f"/api/training/runs/{run_id}/play", json={"steps": 50})
    assert result.status_code == 200
    assert result.json["state"] == "awaiting_submission"
    submitted = client.post(f"/api/training/runs/{run_id}/submit", json={})
    assert submitted.status_code == 200
    return run_id, {**result.json, **submitted.json}


def test_e2e_27_beginner_chain_persists_events_alerts_and_score(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("analyst")
    run_id, result = complete_run(client)
    assert result["total_steps"] == 6
    assert len(result["event_ids"]) == 10
    assert result["alert_ids"]
    assert result["assessment"]["run_id"] == run_id
    detail = client.get(f"/api/training/runs/{run_id}")
    assert detail.status_code == 200
    assert detail.json["progress"] == 1
    assert len(detail.json["events"]) == 10
    dashboard = client.get("/api/dashboard").json
    assert dashboard["counts"]["events"] == 10
    assert dashboard["counts"]["open_alerts"] >= 1


def test_e2e_28_difficulty_changes_noise_not_only_label(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("analyst")
    beginner_id, beginner = complete_run(client, "beginner", 77)
    intermediate_id, intermediate = complete_run(client, "intermediate", 77)
    advanced_id, advanced = complete_run(client, "advanced", 77)
    assert len(beginner["event_ids"]) == 10
    assert len(intermediate["event_ids"]) == 16
    assert len(advanced["event_ids"]) == 28
    beginner_events = client.get(f"/api/training/runs/{beginner_id}").json["events"]
    intermediate_events = client.get(f"/api/training/runs/{intermediate_id}").json["events"]
    advanced_events = client.get(f"/api/training/runs/{advanced_id}").json["events"]
    assert not any(item["step_id"].startswith("noise-") for item in beginner_events)
    assert sum(item["step_id"].startswith("noise-") for item in intermediate_events) == 6
    assert sum(item["step_id"].startswith("noise-") for item in advanced_events) == 18


def test_seeded_run_reproduces_event_sequence_and_detection_outcomes(
    client: FlaskClient,
    login_as: Callable[[str], None],
    database: sqlite3.Connection,
) -> None:
    login_as("analyst")
    first_id = start_run(client, "advanced", 4242)
    second_id = start_run(client, "advanced", 4242)
    different_id = start_run(client, "advanced", 4243)
    for run_id in (first_id, second_id, different_id):
        response = client.post(f"/api/training/runs/{run_id}/play", json={"steps": 50})
        assert response.status_code == 200
        assert response.json["state"] == "awaiting_submission"

    def event_signature(run_id: int) -> list[tuple[object, ...]]:
        started_at = datetime.fromisoformat(
            database.execute("SELECT started_at FROM training_runs WHERE id = ?", (run_id,)).fetchone()[0].replace("Z", "+00:00")
        )
        rows = database.execute(
            """SELECT tre.step_id, tre.sequence_number, e.event_time, e.source, e.event_type,
                      e.source_ip, e.username, e.title, e.severity, e.tags, e.mitre_ids
               FROM training_run_events tre
               JOIN security_events e ON e.id = tre.event_id
               WHERE tre.run_id = ? ORDER BY tre.sequence_number, e.id""",
            (run_id,),
        ).fetchall()
        return [
            (
                row["step_id"],
                row["sequence_number"],
                (datetime.fromisoformat(row["event_time"].replace("Z", "+00:00")) - started_at).total_seconds(),
                row["source"],
                row["event_type"],
                row["source_ip"],
                row["username"],
                row["title"],
                row["severity"],
                row["tags"],
                row["mitre_ids"],
            )
            for row in rows
        ]

    def alert_signature(run_id: int) -> list[tuple[object, ...]]:
        rows = database.execute(
            """SELECT rule_id, rule_version, reason, severity, confidence, mitre_technique_ids
               FROM alerts WHERE training_run_id = ?
               ORDER BY rule_id, rule_version, reason, severity, confidence, mitre_technique_ids""",
            (run_id,),
        ).fetchall()
        return [tuple(row) for row in rows]

    first_detail = client.get(f"/api/training/runs/{first_id}").json
    second_detail = client.get(f"/api/training/runs/{second_id}").json
    assert first_detail["snapshot"] == second_detail["snapshot"] == {"scenario_version": 1, "difficulty": "advanced", "seed": 4242}
    assert event_signature(first_id) == event_signature(second_id)
    assert alert_signature(first_id) == alert_signature(second_id)
    assert event_signature(first_id) != event_signature(different_id)


def test_e2e_29_pause_resume_restart_and_replay_are_idempotent(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("analyst")
    run_id = start_run(client, seed=8080)
    first = client.post(f"/api/training/runs/{run_id}/play", json={"steps": 2})
    assert first.json["current_step"] == 2
    assert client.post(f"/api/training/runs/{run_id}/pause", json={}).json["state"] == "paused"
    assert client.post(f"/api/training/runs/{run_id}/play", json={"steps": 1}).status_code == 409
    assert client.post(f"/api/training/runs/{run_id}/resume", json={}).json["state"] == "running"
    second = client.post(f"/api/training/runs/{run_id}/play", json={"steps": 50})
    assert second.json["state"] == "awaiting_submission"
    before = len(client.get(f"/api/training/runs/{run_id}").json["events"])
    assert client.post(f"/api/training/runs/{run_id}/play", json={"steps": 50}).status_code == 409
    assert len(client.get(f"/api/training/runs/{run_id}").json["events"]) == before
    restarted = client.post(f"/api/training/runs/{run_id}/restart", json={})
    assert restarted.status_code == 201
    assert restarted.json["id"] != run_id
    assert restarted.json["seed"] == 8080


def test_e2e_30_ground_truth_is_not_exposed_to_analyst(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("analyst")
    run_id = start_run(client)
    scenario = client.get(f"/api/scenarios/{scenario_id(client)}")
    assert "ground_truth" not in scenario.get_data(as_text=True)
    assert client.get(f"/api/training/runs/{run_id}/ground-truth").status_code == 403
    login_as("instructor")
    truth = client.get(f"/api/training/runs/{run_id}/ground-truth")
    assert truth.status_code == 200
    assert len(truth.json["items"]) == 6


def test_e2e_31_and_32_attack_matrix_uses_versioned_offline_evidence(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("analyst")
    complete_run(client)
    matrix = client.get("/api/attack/matrix")
    assert matrix.status_code == 200
    assert matrix.json["attack_version"] == "20.0"
    assert matrix.json["offline_snapshot"] is True
    assert matrix.json["snapshot_count"] == 706
    assert len(matrix.json["tactics"]) == 15
    techniques = client.get("/api/attack/techniques")
    assert techniques.status_code == 200
    assert len(techniques.json["items"]) == 706
    assert sum(not item["is_subtechnique"] for item in techniques.json["items"]) == 227
    assert sum(item["is_subtechnique"] for item in techniques.json["items"]) == 479
    brute_force = client.get("/api/attack/techniques/T1110")
    assert brute_force.status_code == 200
    assert brute_force.json["technique_id"] == "T1110"
    assert brute_force.json["coverage"]["seen"] == 5
    assert brute_force.json["coverage"]["detected_in_run"] >= 1
    assert "does not independently prove" in brute_force.json["interpretation_notice"]
    layer = client.get("/api/attack/navigator-layer")
    assert layer.status_code == 200
    assert layer.json["domain"] == "enterprise-attack"
    assert any(item["techniqueID"] == "T1110" for item in layer.json["techniques"])


def test_e2e_33_hunt_query_save_reload_permissions_and_delete(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("analyst")
    run_id, _ = complete_run(client)
    result = client.post(
        "/api/hunt/query",
        json={"query": f"source_ip=198.51.100.20 AND event_type=failed_login AND training_run_id={run_id}", "page": 1, "page_size": 2},
    )
    assert result.status_code == 200
    assert result.json["total"] == 5
    assert len(result.json["items"]) == 2
    assert result.json["query_plan"]["parameterized"] is True
    saved = client.post(
        "/api/hunt/saved-queries",
        json={
            "name": "Failed login acceptance",
            "description": "Parameterized fixture query",
            "query": "source_ip=198.51.100.20 AND event_type=failed_login",
            "tags": ["training"],
            "visibility": "private",
        },
    )
    assert saved.status_code == 201
    listed = client.get("/api/hunt/saved-queries")
    assert any(item["id"] == saved.json["id"] for item in listed.json["items"])
    forbidden_share = client.post(
        "/api/hunt/saved-queries",
        json={"name": "Forbidden share", "query": "event_type=failed_login", "visibility": "workspace"},
    )
    assert forbidden_share.status_code == 403
    assert client.delete(f"/api/hunt/saved-queries/{saved.json['id']}").status_code == 204


def test_e2e_34_ioc_extraction_and_offline_enrichment(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("analyst")
    run_id = start_run(client)
    result = client.post(f"/api/training/runs/{run_id}/play", json={"steps": 3})
    failed_event_id = result.json["event_ids"][-1]
    extracted = client.post("/api/iocs/extract", json={"event_id": failed_event_id})
    assert extracted.status_code == 200
    source = next(item for item in extracted.json["items"] if item["value"] == "198.51.100.20")
    enrichment = client.post(f"/api/iocs/{source['id']}/enrich")
    assert enrichment.status_code == 200
    assert enrichment.json["status"] == "successful"
    assert enrichment.json["training_synthetic"] is True
    assert enrichment.json["verdict"] == "suspicious"
    unavailable = client.post(f"/api/iocs/{source['id']}/enrich?provider=external-fixture")
    assert unavailable.status_code == 200
    assert unavailable.json["status"] == "not_configured"


def test_e2e_35_graph_and_timeline_have_traceable_relations(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("analyst")
    run_id, result = complete_run(client)
    alert_id = result["alert_ids"][0]
    case = client.post(f"/api/alerts/{alert_id}/case", json={})
    assert case.status_code == 201
    graph = client.get(f"/api/visualizations/graph?training_run_id={run_id}&limit=100")
    timeline = client.get(f"/api/visualizations/timeline?training_run_id={run_id}&limit=100")
    assert graph.status_code == 200
    assert timeline.status_code == 200
    node_types = {item["type"] for item in graph.json["nodes"]}
    edge_types = {item["type"] for item in graph.json["edges"]}
    assert {"Event", "IP", "User", "Host", "Technique", "Alert", "Incident"}.issubset(node_types)
    assert {"observed_on", "related_to", "triggered_rule", "attached_to_case"}.issubset(edge_types)
    assert all(item["reference_id"] is not None and item["provenance"] for item in graph.json["nodes"])
    assert len(timeline.json["items"]) == 10
    exported = client.get(f"/api/visualizations/graph/export?training_run_id={run_id}")
    assert exported.status_code == 200
    assert exported.headers["Content-Disposition"].endswith("socify-attack-graph.json")


def test_e2e_37_sse_replay_uses_monotonic_cursor(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("analyst")
    run_id = start_run(client)
    client.post(f"/api/training/runs/{run_id}/play", json={"steps": 1})
    first = client.get("/api/stream/events?once=1")
    assert first.status_code == 200
    body = first.get_data(as_text=True)
    ids = [int(line.removeprefix("id: ")) for line in body.splitlines() if line.startswith("id: ")]
    assert ids == sorted(set(ids))
    assert "event: event.created" in body
    resumed = client.get("/api/stream/events?once=1", headers={"Last-Event-ID": str(ids[-1])})
    assert "event: heartbeat" in resumed.get_data(as_text=True)


def test_e2e_38_playbook_approval_effect_and_rollback(
    client: FlaskClient,
    login_as: Callable[[str], None],
    database: sqlite3.Connection,
) -> None:
    login_as("analyst")
    run_id = start_run(client)
    case = client.post("/api/incidents", json={"title": "Playbook acceptance case", "training_run_id": run_id})
    assert case.status_code == 201
    playbook = client.get("/api/playbooks").json["items"][0]
    preview = client.post(
        f"/api/playbooks/{playbook['id']}/preview",
        json={"case_id": case.json["id"], "training_run_id": run_id, "parameters": {}},
    )
    assert preview.status_code == 200
    assert preview.json["external_effects"] is False
    assert preview.json["confirmation_required"] is True
    requested = client.post(
        "/api/playbook-runs",
        headers={"Idempotency-Key": "acceptance-playbook-approval"},
        json={"playbook_id": playbook["id"], "case_id": case.json["id"], "training_run_id": run_id, "parameters": {}},
    )
    assert requested.status_code == 201
    assert requested.json["state"] == "awaiting_approval"
    duplicate = client.post(
        "/api/playbook-runs",
        headers={"Idempotency-Key": "acceptance-playbook-approval"},
        json={"playbook_id": playbook["id"], "case_id": case.json["id"], "training_run_id": run_id, "parameters": {}},
    )
    assert duplicate.json["duplicate"] is True
    assert client.post(f"/api/playbook-runs/{requested.json['id']}/approve", json={}).status_code == 403
    login_as("soc_manager")
    approved = client.post(f"/api/playbook-runs/{requested.json['id']}/approve", json={})
    assert approved.status_code == 200
    assert approved.json["state"] == "succeeded"
    host_state = database.execute(
        "SELECT state FROM response_simulation_state WHERE training_run_id = ? AND entity_type = 'host' AND entity_id = 'file-training-01'",
        (run_id,),
    ).fetchone()[0]
    assert host_state == "isolated"
    assert (
        database.execute("SELECT COUNT(*) FROM case_evidence WHERE case_id = ? AND evidence_type = 'training_artifact'", (case.json["id"],)).fetchone()[0] == 1
    )
    rolled_back = client.post(f"/api/playbook-runs/{requested.json['id']}/rollback", json={})
    assert rolled_back.status_code == 200
    assert rolled_back.json["state"] == "rolled_back"
    restored = database.execute(
        "SELECT state FROM response_simulation_state WHERE training_run_id = ? AND entity_type = 'host' AND entity_id = 'file-training-01'",
        (run_id,),
    ).fetchone()[0]
    assert restored == "normal"


def test_e2e_39_playbook_failure_retry_limit_and_cancel(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("soc_manager")
    playbook = client.post(
        "/api/playbooks",
        json={
            "name": "Failure acceptance playbook",
            "description": "Safe failure caused by a missing simulated parameter",
            "publish": True,
            "steps": [{"position": 1, "action": "block_simulated_ip", "parameters": {}, "retry_limit": 2}],
        },
    )
    assert playbook.status_code == 201
    login_as("analyst")
    requested = client.post(
        "/api/playbook-runs",
        headers={"Idempotency-Key": "acceptance-failing-playbook"},
        json={"playbook_id": playbook.json["id"], "parameters": {}},
    )
    assert requested.status_code == 201
    assert requested.json["state"] == "failed"
    retry = client.post(f"/api/playbook-runs/{requested.json['id']}/retry", json={})
    assert retry.status_code == 200
    assert retry.json["state"] == "failed"
    exhausted = client.post(f"/api/playbook-runs/{requested.json['id']}/retry", json={})
    assert exhausted.status_code == 409
    cancelled = client.post(f"/api/playbook-runs/{requested.json['id']}/cancel", json={})
    assert cancelled.status_code == 200
    assert cancelled.json["state"] == "cancelled"


def test_e2e_40_and_41_score_snapshot_is_deterministic(client: FlaskClient, login_as: Callable[[str], None], database: sqlite3.Connection) -> None:
    login_as("analyst")
    run_id, completed = complete_run(client)
    first = client.get(f"/api/training/runs/{run_id}/score")
    second = client.get(f"/api/training/runs/{run_id}/score")
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json["calculation_fingerprint"] == second.json["calculation_fingerprint"]
    assert first.json["total_score"] == completed["assessment"]["total_score"]
    assert sum(first.json["weights"].values()) == 100
    assert {
        "detection_recall",
        "detection_precision",
        "false_positive_rate",
        "elapsed_seconds",
        "machine_detection_latency_seconds",
        "learner_discovery_latency_seconds",
        "mean_time_to_acknowledge_seconds",
        "mean_time_to_resolve_seconds",
        "classification_accuracy",
        "evidence_completeness",
        "response_decision_quality",
        "playbook_compliance",
    }.issubset(first.json["components"]["metrics"])
    report = first.json["components"]["report"]
    assert report["timeline"][-1]["action_type"] == "run_submitted"
    assert report["missed_detection_targets"]
    assert report["suggested_learning_path"]
    assert "machine_detection_latency_seconds" in report["timestamp_definitions"]
    html_report = client.get(f"/api/assessments/{first.json['id']}/report")
    assert html_report.status_code == 200
    assert html_report.mimetype == "text/html"
    assert "attachment;" in html_report.headers["Content-Disposition"]
    assert html_report.headers["Digest"].startswith("sha-256=")
    assert "تقرير تقييم SOCify" in html_report.text
    json_report = client.get(f"/api/assessments/{first.json['id']}/report?format=json")
    assert json_report.status_code == 200
    assert json_report.json["calculation_fingerprint"] == first.json["calculation_fingerprint"]
    assert client.get(f"/api/assessments/{first.json['id']}/report?format=pdf").status_code == 422
    tamper = client.post(f"/api/assessments/{first.json['id']}", json={"total_score": 100})
    assert tamper.status_code == 405
    audit = database.execute(
        "SELECT result, details FROM security_audit_logs WHERE action = 'tamper' AND resource_type = 'assessment' AND resource_id = ?",
        (str(first.json["id"]),),
    ).fetchone()
    assert audit["result"] == "denied"
    assert "total_score" in audit["details"]


def test_e2e_42_leaderboard_masks_other_identity(client: FlaskClient, login_as: Callable[[str], None], database: sqlite3.Connection) -> None:
    login_as("analyst")
    private = client.get("/api/leaderboards")
    assert private.status_code == 200
    assert private.json["opted_in"] is False
    assert private.json["items"] == []
    assert client.put("/api/profile/leaderboard", json={"opt_in": "yes"}).status_code == 422
    preference = client.put("/api/profile/leaderboard", json={"opt_in": True})
    assert preference.status_code == 200
    assert preference.json["opt_in"] is True
    assert client.get("/api/profile").json["user"]["leaderboard_opt_in"] is True
    _, own = complete_run(client, seed=101)
    teammate_id = database.execute("SELECT id FROM users WHERE role = 'soc_manager'").fetchone()[0]
    instructor_id = database.execute("SELECT id FROM users WHERE role = 'instructor'").fetchone()[0]
    database.execute("UPDATE users SET leaderboard_opt_in = 1 WHERE id IN (?, ?)", (teammate_id, instructor_id))
    scenario_version = database.execute("SELECT id FROM scenario_versions LIMIT 1").fetchone()[0]
    database.execute(
        "INSERT INTO training_runs (run_id, workspace_id, scenario_version_id, user_id, difficulty, seed, state, current_step, playback_rate, started_at, completed_at, snapshot) VALUES ('RUN-OTHER', 1, ?, ?, 'beginner', 3, 'completed', 6, 1, '2026-10-19T10:00:00Z', '2026-10-19T10:05:00Z', '{}')",
        (scenario_version, teammate_id),
    )
    other_run = database.execute("SELECT id FROM training_runs WHERE run_id = 'RUN-OTHER'").fetchone()[0]
    database.execute(
        "INSERT INTO assessment_snapshots (assessment_id, workspace_id, run_id, user_id, policy_version, weights, inputs, components, total_score, created_at) VALUES ('ASM-OTHER', 1, ?, ?, 'socify-score-v1', '{}', '{}', '{}', 99, '2026-10-19T10:06:00Z')",
        (other_run, teammate_id),
    )
    database.execute(
        "INSERT INTO training_runs (run_id, workspace_id, scenario_version_id, user_id, difficulty, seed, state, current_step, playback_rate, started_at, completed_at, snapshot) VALUES ('RUN-OTHER-COHORT', 1, ?, ?, 'beginner', 4, 'completed', 6, 1, '2026-10-19T10:00:00Z', '2026-10-19T10:05:00Z', '{}')",
        (scenario_version, instructor_id),
    )
    other_cohort_run = database.execute("SELECT id FROM training_runs WHERE run_id = 'RUN-OTHER-COHORT'").fetchone()[0]
    database.execute(
        "INSERT INTO assessment_snapshots (assessment_id, workspace_id, run_id, user_id, policy_version, weights, inputs, components, total_score, created_at) VALUES ('ASM-OTHER-COHORT', 1, ?, ?, 'socify-score-v1', '{}', '{}', '{}', 98, '2026-10-19T10:06:00Z')",
        (other_cohort_run, instructor_id),
    )
    leaderboard = client.get("/api/leaderboards")
    assert leaderboard.status_code == 200
    other = next(item for item in leaderboard.json["items"] if item["score"] == 99)
    current = next(item for item in leaderboard.json["items"] if item["score"] == own["assessment"]["total_score"])
    assert other["name"].startswith("متدرب-")
    assert other["assessment_id"] is None
    assert other["cohort"] == "فريق SOC"
    assert current["is_current_user"] is True
    assert all(item["score"] != 98 for item in leaderboard.json["items"])
    assert client.put("/api/profile/leaderboard", json={"opt_in": False}).status_code == 200
    assert client.get("/api/leaderboards").json["items"] == []
