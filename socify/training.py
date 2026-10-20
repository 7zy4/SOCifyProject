import hashlib
import json
import math
import sqlite3
from datetime import timedelta
from typing import Any

from flask import Blueprint, jsonify, request

from .audit import record_audit, record_training_action
from .db import get_db, inserted_id, transaction
from .events import ingest_event
from .schema import insert_outbox, public_id
from .security import actor_id, current_user, error_response, has_permission, require_permission, workspace_id
from .timeutils import iso_now, parse_timestamp

training_api = Blueprint("training", __name__)

SCENARIO_STATES = {
    "draft": {"validated", "archived"},
    "validated": {"published", "draft", "archived"},
    "published": {"ready", "archived"},
    "ready": {"published", "archived"},
    "archived": set(),
}
RUN_STATES = {
    "ready": {"running", "cancelled"},
    "running": {"paused", "awaiting_submission", "failed", "cancelled"},
    "awaiting_submission": {"completed", "cancelled"},
    "paused": {"running", "cancelled"},
    "completed": {"archived"},
    "failed": {"archived"},
    "cancelled": {"archived"},
    "archived": set(),
}
DIFFICULTIES = {"beginner", "intermediate", "advanced"}


def _scenario_version(scenario_id: int, version: int | None = None) -> sqlite3.Row | None:
    if version is None:
        return get_db().execute("SELECT sv.* FROM scenario_versions sv JOIN attack_scenarios s ON s.id = sv.scenario_id WHERE s.id = ? AND s.workspace_id = ? AND sv.version = s.active_version", (scenario_id, workspace_id())).fetchone()
    return get_db().execute("SELECT sv.* FROM scenario_versions sv JOIN attack_scenarios s ON s.id = sv.scenario_id WHERE s.id = ? AND s.workspace_id = ? AND sv.version = ?", (scenario_id, workspace_id(), version)).fetchone()


def _required_version(row: sqlite3.Row | None) -> sqlite3.Row:
    if row is None:
        raise RuntimeError("scenario version disappeared during request")
    return row


def _scenario_view(row: sqlite3.Row | None) -> dict[str, Any]:
    row = _required_version(row)
    item = dict(row)
    for field in ("objectives", "roles", "environment", "scoring_policy"):
        if field in item:
            item[field] = json.loads(item[field])
    return item


@training_api.get("/api/scenarios")
@require_permission("training.run")
def list_scenarios():
    user = current_user()
    states = ("published", "ready") if not has_permission(user, "training.manage") else ("draft", "validated", "published", "ready", "archived")
    placeholders = ",".join("?" for _ in states)
    rows = get_db().execute(
        f"""SELECT s.*, sv.difficulty, sv.duration_minutes, sv.objectives, sv.roles, sv.environment, sv.scoring_policy,
        (SELECT COUNT(*) FROM scenario_steps st WHERE st.scenario_version_id = sv.id) AS step_count,
        (SELECT COUNT(*) FROM training_runs tr WHERE tr.scenario_version_id = sv.id AND tr.user_id = ?) AS attempt_count
        FROM attack_scenarios s JOIN scenario_versions sv ON sv.scenario_id = s.id AND sv.version = s.active_version
        WHERE s.workspace_id = ? AND s.state IN ({placeholders}) ORDER BY s.name""",
        (actor_id(), workspace_id(), *states),
    ).fetchall()
    return jsonify({"items": [_scenario_view(row) for row in rows]})


@training_api.get("/api/scenarios/<int:scenario_id>")
@require_permission("training.run")
def scenario_detail(scenario_id: int):
    row = get_db().execute("SELECT * FROM attack_scenarios WHERE id = ? AND workspace_id = ?", (scenario_id, workspace_id())).fetchone()
    if not row or row["state"] not in {"published", "ready"} and not has_permission(current_user(), "training.manage"):
        return error_response("SCENARIO_NOT_FOUND", "السيناريو غير موجود", 404)
    version = _required_version(_scenario_version(scenario_id))
    item = {**dict(row), **_scenario_view(version)}
    steps = get_db().execute("SELECT step_id, position, name, mitre_ids, visible_hint FROM scenario_steps WHERE scenario_version_id = ? ORDER BY position", (version["id"],)).fetchall()
    item["steps"] = [{**dict(step), "mitre_ids": json.loads(step["mitre_ids"]), "visible_hint": step["visible_hint"] if version["difficulty"] == "beginner" else None} for step in steps]
    return jsonify(item)


def _validate_scenario(data: dict[str, Any]) -> tuple[dict[str, Any] | None, object | None]:
    name = data.get("name")
    description = data.get("description")
    difficulty = data.get("difficulty", "beginner")
    objectives = data.get("objectives", [])
    steps = data.get("steps", [])
    scoring = data.get("scoring_policy", {"detection": 25, "investigation": 25, "response": 20, "evidence": 15, "time": 10, "false_positive": 5})
    if not isinstance(name, str) or not 3 <= len(name.strip()) <= 180 or not isinstance(description, str) or len(description) > 5000:
        return None, error_response("INVALID_SCENARIO", "اسم السيناريو ووصفه غير صالحين", 422)
    if not isinstance(difficulty, str) or difficulty not in DIFFICULTIES or not isinstance(objectives, list) or not objectives or any(not isinstance(item, str) for item in objectives):
        return None, error_response("INVALID_SCENARIO", "الصعوبة أو الأهداف غير صالحة", 422)
    if not isinstance(steps, list) or not 1 <= len(steps) <= 50:
        return None, error_response("INVALID_SCENARIO_STEPS", "يلزم من خطوة واحدة إلى 50 خطوة", 422)
    positions = set()
    normalized_steps = []
    for index, step in enumerate(steps, 1):
        if not isinstance(step, dict) or not isinstance(step.get("name"), str) or not isinstance(step.get("event"), dict):
            return None, error_response("INVALID_SCENARIO_STEP", f"الخطوة {index} غير صالحة", 422)
        position = step.get("position", index)
        if type(position) is not int or position < 1 or position in positions:
            return None, error_response("INVALID_SCENARIO_STEP", "ترتيب الخطوات غير صالح", 422)
        truth = step.get("ground_truth", {})
        if not isinstance(truth, dict):
            return None, error_response("INVALID_SCENARIO_STEP", "معايير الخطوة غير صالحة", 422)
        weight = truth.get("score_weight", 1)
        if type(weight) not in (int, float) or not math.isfinite(weight) or weight <= 0:
            return None, error_response("INVALID_SCENARIO_STEP", "وزن الخطوة غير صالح", 422)
        for field in ("expected_detections", "relevant_evidence", "allowed_responses"):
            values = truth.get(field, [])
            if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                return None, error_response("INVALID_SCENARIO_STEP", "معايير الخطوة غير صالحة", 422)
        repeat = step["event"].get("repeat", 1)
        if type(repeat) is not int or not 1 <= repeat <= 50:
            return None, error_response("INVALID_SCENARIO_STEP", "تكرار الخطوة غير صالح", 422)
        for values in (step.get("mitre_ids", []), step["event"].get("tags", [])):
            if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                return None, error_response("INVALID_SCENARIO_STEP", "وسوم الخطوة غير صالحة", 422)
        serialized = json.dumps(step["event"], ensure_ascii=False)
        if any(token in serialized.casefold() for token in ("http://", "https://", "password=", "authorization")):
            return None, error_response("UNSAFE_SCENARIO_STEP", "لا يسمح السيناريو باتصالات أو بيانات اعتماد خارجية", 422)
        positions.add(position)
        normalized_steps.append({**step, "position": position, "step_id": str(step.get("step_id") or f"step-{position}")[:80]})
    if positions != set(range(1, len(steps) + 1)):
        return None, error_response("INVALID_SCENARIO_STEP", "ترتيب الخطوات غير صالح", 422)
    if not isinstance(scoring, dict) or any(type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 100 for value in scoring.values()) or sum(scoring.values()) != 100:
        return None, error_response("INVALID_SCORING_POLICY", "يجب أن يساوي مجموع أوزان التقييم 100", 422)
    duration = data.get("duration_minutes", 30)
    if type(duration) is not int or not 1 <= duration <= 1440:
        return None, error_response("INVALID_SCENARIO", "مدة السيناريو غير صالحة", 422)
    return {"name": name.strip(), "description": description.strip(), "difficulty": difficulty, "objectives": objectives, "steps": normalized_steps, "scoring_policy": scoring, "duration_minutes": duration, "roles": data.get("roles", ["analyst"]), "environment": data.get("environment", {"mode": "isolated_training"}), "visibility": data.get("visibility", "workspace")}, None


@training_api.post("/api/scenarios")
@require_permission("training.manage")
def create_scenario():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error_response("INVALID_JSON", "يلزم إرسال كائن JSON صالح", 400)
    payload, failure = _validate_scenario(data)
    if failure:
        return failure
    if payload is None:
        raise RuntimeError("scenario payload validation did not return data")
    now = iso_now()
    with transaction():
        cursor = get_db().execute("INSERT INTO attack_scenarios (scenario_id, workspace_id, name, description, active_version, state, visibility, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, 1, 'draft', ?, ?, ?, ?)", (public_id("SCN"), workspace_id(), payload["name"], payload["description"], payload["visibility"], actor_id(), now, now))
        scenario_id = inserted_id(cursor)
        version_cursor = get_db().execute("INSERT INTO scenario_versions (scenario_id, version, objectives, roles, difficulty, duration_minutes, environment, scoring_policy, created_by, created_at) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)", (scenario_id, json.dumps(payload["objectives"], ensure_ascii=False), json.dumps(payload["roles"]), payload["difficulty"], payload["duration_minutes"], json.dumps(payload["environment"]), json.dumps(payload["scoring_policy"]), actor_id(), now))
        version_id = inserted_id(version_cursor)
        for step in payload["steps"]:
            get_db().execute("INSERT INTO scenario_steps (scenario_version_id, step_id, position, name, event_template, artifact, mitre_ids, visible_hint) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (version_id, step["step_id"], step["position"], step["name"], json.dumps(step["event"], ensure_ascii=False), json.dumps(step.get("artifact", {}), ensure_ascii=False), json.dumps(step.get("mitre_ids", [])), step.get("hint")))
            ground_truth = step.get("ground_truth", {})
            get_db().execute("INSERT INTO scenario_ground_truth (scenario_version_id, step_id, expected_detections, relevant_evidence, allowed_responses, score_weight) VALUES (?, ?, ?, ?, ?, ?)", (version_id, step["step_id"], json.dumps(ground_truth.get("expected_detections", [])), json.dumps(ground_truth.get("relevant_evidence", [])), json.dumps(ground_truth.get("allowed_responses", [])), float(ground_truth.get("score_weight", 1))))
        record_audit(get_db(), "create", "scenario", scenario_id, details={"version": 1, "steps": len(payload["steps"])})
    return jsonify({"id": scenario_id, "state": "draft", "version": 1}), 201


@training_api.post("/api/scenarios/<int:scenario_id>/transition")
@require_permission("training.manage")
def transition_scenario(scenario_id: int):
    row = get_db().execute("SELECT * FROM attack_scenarios WHERE id = ? AND workspace_id = ?", (scenario_id, workspace_id())).fetchone()
    data = request.get_json(silent=True)
    target = data.get("state") if isinstance(data, dict) else None
    if not row:
        return error_response("SCENARIO_NOT_FOUND", "السيناريو غير موجود", 404)
    if not isinstance(target, str) or target not in SCENARIO_STATES.get(row["state"], set()):
        return error_response("ILLEGAL_SCENARIO_TRANSITION", "انتقال حالة السيناريو غير مسموح", 409)
    if target == "validated":
        steps = int(get_db().execute("SELECT COUNT(*) FROM scenario_steps s JOIN scenario_versions v ON v.id = s.scenario_version_id WHERE v.scenario_id = ? AND v.version = ?", (scenario_id, row["active_version"])).fetchone()[0])
        if steps == 0:
            return error_response("SCENARIO_HAS_NO_STEPS", "لا يمكن اعتماد سيناريو بلا خطوات", 409)
    get_db().execute("UPDATE attack_scenarios SET state = ?, updated_at = ? WHERE id = ?", (target, iso_now(), scenario_id))
    record_audit(get_db(), "transition", "scenario", scenario_id, details={"from": row["state"], "to": target})
    return jsonify({"id": scenario_id, "state": target})


@training_api.post("/api/scenarios/<int:scenario_id>/versions")
@require_permission("training.manage")
def create_scenario_version(scenario_id: int):
    scenario = get_db().execute("SELECT * FROM attack_scenarios WHERE id = ? AND workspace_id = ?", (scenario_id, workspace_id())).fetchone()
    if not scenario:
        return error_response("SCENARIO_NOT_FOUND", "السيناريو غير موجود", 404)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error_response("INVALID_JSON", "يلزم إرسال كائن JSON صالح", 400)
    payload, failure = _validate_scenario(data)
    if failure:
        return failure
    if payload is None:
        raise RuntimeError("scenario payload validation did not return data")
    version = int(scenario["active_version"]) + 1
    now = iso_now()
    with transaction():
        version_cursor = get_db().execute("INSERT INTO scenario_versions (scenario_id, version, objectives, roles, difficulty, duration_minutes, environment, scoring_policy, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (scenario_id, version, json.dumps(payload["objectives"], ensure_ascii=False), json.dumps(payload["roles"]), payload["difficulty"], payload["duration_minutes"], json.dumps(payload["environment"]), json.dumps(payload["scoring_policy"]), actor_id(), now))
        version_id = inserted_id(version_cursor)
        for step in payload["steps"]:
            get_db().execute("INSERT INTO scenario_steps (scenario_version_id, step_id, position, name, event_template, artifact, mitre_ids, visible_hint) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (version_id, step["step_id"], step["position"], step["name"], json.dumps(step["event"], ensure_ascii=False), json.dumps(step.get("artifact", {}), ensure_ascii=False), json.dumps(step.get("mitre_ids", [])), step.get("hint")))
            ground_truth = step.get("ground_truth", {})
            get_db().execute("INSERT INTO scenario_ground_truth (scenario_version_id, step_id, expected_detections, relevant_evidence, allowed_responses, score_weight) VALUES (?, ?, ?, ?, ?, ?)", (version_id, step["step_id"], json.dumps(ground_truth.get("expected_detections", [])), json.dumps(ground_truth.get("relevant_evidence", [])), json.dumps(ground_truth.get("allowed_responses", [])), float(ground_truth.get("score_weight", 1))))
        get_db().execute("UPDATE attack_scenarios SET name = ?, description = ?, active_version = ?, state = 'draft', visibility = ?, updated_at = ? WHERE id = ?", (payload["name"], payload["description"], version, payload["visibility"], now, scenario_id))
        record_audit(get_db(), "version", "scenario", scenario_id, details={"from": scenario["active_version"], "to": version})
    return jsonify({"id": scenario_id, "version": version, "state": "draft"}), 201


@training_api.post("/api/scenarios/<int:scenario_id>/clone")
@require_permission("training.manage")
def clone_scenario(scenario_id: int):
    scenario = get_db().execute("SELECT * FROM attack_scenarios WHERE id = ? AND workspace_id = ?", (scenario_id, workspace_id())).fetchone()
    version = _scenario_version(scenario_id) if scenario else None
    if not scenario or not version:
        return error_response("SCENARIO_NOT_FOUND", "السيناريو غير موجود", 404)
    request_data = request.get_json(silent=True)
    requested_name = request_data.get("name") if isinstance(request_data, dict) else None
    name = requested_name.strip() if isinstance(requested_name, str) and 3 <= len(requested_name.strip()) <= 180 else f"{scenario['name']} copy"
    now = iso_now()
    with transaction():
        cursor = get_db().execute("INSERT INTO attack_scenarios (scenario_id, workspace_id, name, description, active_version, state, visibility, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, 1, 'draft', ?, ?, ?, ?)", (public_id("SCN"), workspace_id(), name, scenario["description"], scenario["visibility"], actor_id(), now, now))
        cloned_id = inserted_id(cursor)
        version_cursor = get_db().execute("INSERT INTO scenario_versions (scenario_id, version, objectives, roles, difficulty, duration_minutes, environment, scoring_policy, created_by, created_at) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)", (cloned_id, version["objectives"], version["roles"], version["difficulty"], version["duration_minutes"], version["environment"], version["scoring_policy"], actor_id(), now))
        cloned_version_id = inserted_id(version_cursor)
        steps = get_db().execute("SELECT * FROM scenario_steps WHERE scenario_version_id = ? ORDER BY position", (version["id"],)).fetchall()
        for step in steps:
            get_db().execute("INSERT INTO scenario_steps (scenario_version_id, step_id, position, name, event_template, artifact, mitre_ids, visible_hint) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (cloned_version_id, step["step_id"], step["position"], step["name"], step["event_template"], step["artifact"], step["mitre_ids"], step["visible_hint"]))
        truths = get_db().execute("SELECT * FROM scenario_ground_truth WHERE scenario_version_id = ?", (version["id"],)).fetchall()
        for truth in truths:
            get_db().execute("INSERT INTO scenario_ground_truth (scenario_version_id, step_id, expected_detections, relevant_evidence, allowed_responses, score_weight) VALUES (?, ?, ?, ?, ?, ?)", (cloned_version_id, truth["step_id"], truth["expected_detections"], truth["relevant_evidence"], truth["allowed_responses"], truth["score_weight"]))
        record_audit(get_db(), "clone", "scenario", cloned_id, details={"source_scenario_id": scenario_id})
    return jsonify({"id": cloned_id, "version": 1, "state": "draft"}), 201


def _run_access(run_id: int) -> sqlite3.Row | None:
    user = current_user()
    if has_permission(user, "training.manage") or has_permission(user, "scores.read_team"):
        return get_db().execute("SELECT * FROM training_runs WHERE id = ? AND workspace_id = ?", (run_id, workspace_id())).fetchone()
    return get_db().execute("SELECT * FROM training_runs WHERE id = ? AND workspace_id = ? AND user_id = ?", (run_id, workspace_id(), actor_id())).fetchone()


@training_api.get("/api/training/runs")
@require_permission("training.run")
def list_my_runs():
    rows = get_db().execute(
        """SELECT tr.id, tr.run_id, tr.difficulty, tr.state, tr.started_at,
                  tr.completed_at, tr.submitted_at, tr.current_step, s.name AS scenario_name
           FROM training_runs tr
           JOIN scenario_versions sv ON sv.id = tr.scenario_version_id
           JOIN attack_scenarios s ON s.id = sv.scenario_id
           WHERE tr.workspace_id = ? AND tr.user_id = ?
           ORDER BY tr.id DESC LIMIT 50""",
        (workspace_id(), actor_id()),
    ).fetchall()
    return jsonify({"items": [dict(row) for row in rows]})


@training_api.post("/api/training/runs")
@require_permission("training.run")
def start_run():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("scenario_id"), int):
        return error_response("SCENARIO_REQUIRED", "حدد السيناريو المطلوب", 422)
    return _start_run(data)


def _start_run(data: dict[str, Any]):
    scenario = get_db().execute("SELECT * FROM attack_scenarios WHERE id = ? AND workspace_id = ? AND state IN ('published', 'ready')", (data["scenario_id"], workspace_id())).fetchone()
    if not scenario:
        return error_response("SCENARIO_NOT_AVAILABLE", "السيناريو غير منشور أو غير موجود", 404)
    version = _scenario_version(int(scenario["id"]), data.get("version") if isinstance(data.get("version"), int) else None)
    if version is None:
        return error_response("SCENARIO_NOT_AVAILABLE", "نسخة السيناريو غير موجودة", 404)
    difficulty = data.get("difficulty", version["difficulty"])
    if not isinstance(difficulty, str) or difficulty not in DIFFICULTIES:
        return error_response("INVALID_DIFFICULTY", "مستوى الصعوبة غير صالح", 422)
    rate = data.get("playback_rate", 1)
    if type(rate) not in (int, float) or not math.isfinite(rate) or not 0 < rate <= 100:
        return error_response("INVALID_PLAYBACK_RATE", "سرعة التشغيل غير صالحة", 422)
    seed = data.get("seed")
    if not isinstance(seed, int):
        seed = int(hashlib.sha256(f"{version['id']}:{actor_id()}:{iso_now()}".encode()).hexdigest()[:8], 16)
    now = iso_now()
    with transaction():
        cursor = get_db().execute("INSERT INTO training_runs (run_id, workspace_id, scenario_version_id, user_id, difficulty, seed, state, current_step, playback_rate, started_at, snapshot) VALUES (?, ?, ?, ?, ?, ?, 'running', 0, ?, ?, ?)", (public_id("RUN"), workspace_id(), version["id"], actor_id(), difficulty, seed, float(data.get("playback_rate", 1)), now, json.dumps({"scenario_version": version["version"], "difficulty": difficulty, "seed": seed})))
        run_id = inserted_id(cursor)
        record_audit(get_db(), "start", "training_run", run_id, details={"scenario": scenario["scenario_id"], "seed": seed, "difficulty": difficulty})
        record_training_action(get_db(), run_id, actor_id(), "run_started", "training_run", run_id, {}, f"run-start:{run_id}")
        insert_outbox(get_db(), workspace_id(), "training_run.started", {"id": run_id})
    if data.get("auto_play"):
        return _play_run(run_id, 50)
    return jsonify({"id": run_id, "state": "running", "seed": seed, "difficulty": difficulty}), 201, {"Location": f"/api/training/runs/{run_id}"}


def _noise_event(run: sqlite3.Row, position: int, index: int, event_time: str) -> dict[str, Any]:
    digest = hashlib.sha256(f"{run['seed']}:{position}:{index}".encode()).digest()
    source_ip = f"198.51.100.{20 + int.from_bytes(digest[:2], 'big') % 201}"
    username = f"training-user-{1 + digest[2] % 12}"
    return {"source": "scenario-noise", "source_type": "training", "severity": "low", "category": "benign", "event_type": "routine_activity", "title": "Routine training activity", "description": "Deterministic background event", "event_time": event_time, "source_ip": source_ip, "username": username, "raw_payload": {"synthetic": True, "noise": True}, "tags": ["training", "noise"], "idempotency_key": f"run:{run['id']}:noise:{position}:{index}"}


def _materialize_step(connection: sqlite3.Connection, run: sqlite3.Row, step: sqlite3.Row) -> tuple[list[int], list[int]]:
    template = json.loads(step["event_template"])
    repeat = int(template.pop("repeat", 1))
    repeat = min(max(repeat, 1), 50)
    base_time = parse_timestamp(run["started_at"]) + timedelta(seconds=int(step["position"]) * 60)
    event_ids: list[int] = []
    alert_ids: list[int] = []
    for index in range(repeat):
        event = dict(template)
        event["event_time"] = (base_time + timedelta(seconds=index)).isoformat().replace("+00:00", "Z")
        event["idempotency_key"] = f"run:{run['id']}:step:{step['step_id']}:{index}"
        event["tags"] = list(set(event.get("tags", []) + ["training", f"difficulty:{run['difficulty']}"]))
        event["mitre_ids"] = json.loads(step["mitre_ids"])
        event["provenance"] = {"scenario_step": step["step_id"], "seed": run["seed"], "synthetic": True}
        event_id, alerts, _ = ingest_event(connection, event, run["user_id"], run["workspace_id"], run["id"])
        connection.execute("INSERT OR IGNORE INTO training_run_events (run_id, step_id, event_id, sequence_number) VALUES (?, ?, ?, ?)", (run["id"], step["step_id"], event_id, int(step["position"]) * 100 + index))
        event_ids.append(event_id)
        alert_ids.extend(alerts)
    noise_count = {"beginner": 0, "intermediate": 1, "advanced": 3}[run["difficulty"]]
    for index in range(noise_count):
        event = _noise_event(run, int(step["position"]), index, (base_time + timedelta(seconds=20 + index)).isoformat().replace("+00:00", "Z"))
        event_id, alerts, _ = ingest_event(connection, event, run["user_id"], run["workspace_id"], run["id"])
        connection.execute("INSERT OR IGNORE INTO training_run_events (run_id, step_id, event_id, sequence_number) VALUES (?, ?, ?, ?)", (run["id"], f"noise-{step['step_id']}", event_id, int(step["position"]) * 100 + 50 + index))
        event_ids.append(event_id)
        alert_ids.extend(alerts)
    return event_ids, alert_ids


def _play_run(run_id: int, steps_requested: int):
    run = _run_access(run_id)
    if not run:
        return error_response("RUN_NOT_FOUND", "جلسة التدريب غير موجودة", 404)
    if run["state"] != "running":
        return error_response("RUN_NOT_RUNNING", "جلسة التدريب ليست في حالة تشغيل", 409)
    steps = get_db().execute("SELECT * FROM scenario_steps WHERE scenario_version_id = ? AND position > ? ORDER BY position LIMIT ?", (run["scenario_version_id"], run["current_step"], min(max(steps_requested, 1), 50))).fetchall()
    generated_events: list[int] = []
    generated_alerts: list[int] = []
    with transaction():
        for step in steps:
            events, alerts = _materialize_step(get_db(), run, step)
            generated_events.extend(events)
            generated_alerts.extend(alerts)
            get_db().execute("UPDATE training_runs SET current_step = ? WHERE id = ?", (step["position"], run_id))
        total_steps = int(get_db().execute("SELECT COUNT(*) FROM scenario_steps WHERE scenario_version_id = ?", (run["scenario_version_id"],)).fetchone()[0])
        current = int(get_db().execute("SELECT current_step FROM training_runs WHERE id = ?", (run_id,)).fetchone()[0])
        completed = current >= total_steps
        if completed:
            get_db().execute("UPDATE training_runs SET state = 'awaiting_submission', completed_at = ? WHERE id = ?", (iso_now(), run_id))
            record_training_action(get_db(), run_id, run["user_id"], "playback_finished", "training_run", run_id, {}, f"playback-finish:{run_id}")
        record_audit(get_db(), "play", "training_run", run_id, details={"steps": len(steps), "events": len(generated_events), "alerts": len(generated_alerts), "completed": completed})
        insert_outbox(get_db(), run["workspace_id"], "training_run.updated", {"id": run_id, "current_step": current, "completed": completed})
    response: dict[str, Any] = {"id": run_id, "state": "awaiting_submission" if completed else "running", "current_step": current, "total_steps": total_steps, "event_ids": generated_events, "alert_ids": generated_alerts}
    if completed:
        response["assessment_status"] = "awaiting_submission"
    return jsonify(response)


@training_api.post("/api/training/runs/<int:run_id>/submit")
@require_permission("training.run")
def submit_run(run_id: int):
    run = _run_access(run_id)
    if not run:
        return error_response("RUN_NOT_FOUND", "جلسة التدريب غير موجودة", 404)
    if int(run["user_id"]) != actor_id():
        return error_response("PERMISSION_DENIED", "لا يمكنك تسليم جلسة متدرب آخر", 403)
    if run["state"] not in {"awaiting_submission", "completed"}:
        return error_response("RUN_NOT_READY_FOR_SUBMISSION", "يجب إنهاء عرض السيناريو أولًا", 409)
    from .scoring import calculate_assessment
    if run["state"] == "completed" and run["submitted_at"]:
        return jsonify({"state": "completed", "assessment": calculate_assessment(get_db(), run_id)})
    with transaction():
        updated = get_db().execute(
            "UPDATE training_runs SET state = 'completed', submitted_at = ? WHERE id = ? AND state = 'awaiting_submission' AND submitted_at IS NULL",
            (iso_now(), run_id),
        )
        if updated.rowcount != 1:
            return error_response("RUN_SUBMISSION_CONFLICT", "تم تسليم المحاولة سابقًا أو تغيّرت حالتها", 409)
        record_training_action(get_db(), run_id, actor_id(), "run_submitted", "training_run", run_id, {}, f"run-submit:{run_id}")
        assessment = calculate_assessment(get_db(), run_id)
        record_audit(get_db(), "submit", "training_run", run_id, details={"assessment_id": assessment["id"]})
        insert_outbox(get_db(), workspace_id(), "training_run.submitted", {"id": run_id, "assessment_id": assessment["id"]})
    return jsonify({"state": "completed", "assessment": assessment})


@training_api.post("/api/training/runs/<int:run_id>/play")
@require_permission("training.run")
def play_run(run_id: int):
    data = request.get_json(silent=True)
    requested = data.get("steps", 1) if isinstance(data, dict) else 1
    if not isinstance(requested, int):
        return error_response("INVALID_STEP_COUNT", "عدد الخطوات غير صالح", 422)
    return _play_run(run_id, requested)


def _run_transition(run_id: int, target: str):
    run = _run_access(run_id)
    if not run:
        return error_response("RUN_NOT_FOUND", "جلسة التدريب غير موجودة", 404)
    if target not in RUN_STATES.get(run["state"], set()):
        return error_response("ILLEGAL_RUN_TRANSITION", "انتقال حالة التدريب غير مسموح", 409)
    updates: dict[str, Any] = {"state": target}
    if target == "paused":
        updates["paused_at"] = iso_now()
    if target == "running":
        updates["paused_at"] = None
    assignments = ", ".join(f"{key} = ?" for key in updates)
    get_db().execute(f"UPDATE training_runs SET {assignments} WHERE id = ?", (*updates.values(), run_id))
    record_audit(get_db(), target, "training_run", run_id)
    return jsonify({"id": run_id, **updates})


@training_api.post("/api/training/runs/<int:run_id>/pause")
@require_permission("training.run")
def pause_run(run_id: int):
    return _run_transition(run_id, "paused")


@training_api.post("/api/training/runs/<int:run_id>/resume")
@require_permission("training.run")
def resume_run(run_id: int):
    return _run_transition(run_id, "running")


@training_api.post("/api/training/runs/<int:run_id>/restart")
@require_permission("training.run")
def restart_run(run_id: int):
    run = _run_access(run_id)
    if not run:
        return error_response("RUN_NOT_FOUND", "جلسة التدريب غير موجودة", 404)
    get_db().execute("UPDATE training_runs SET state = 'cancelled' WHERE id = ? AND state IN ('running', 'paused', 'ready')", (run_id,))
    scenario = get_db().execute("SELECT scenario_id FROM scenario_versions WHERE id = ?", (run["scenario_version_id"],)).fetchone()
    data = {"scenario_id": scenario["scenario_id"], "difficulty": run["difficulty"], "seed": run["seed"], "playback_rate": run["playback_rate"], "auto_play": False}
    return _start_run(data)


@training_api.post("/api/training/runs/<int:run_id>/hints")
@require_permission("training.run")
def consume_hint(run_id: int):
    run = _run_access(run_id)
    if not run:
        return error_response("RUN_NOT_FOUND", "جلسة التدريب غير موجودة", 404)
    step = get_db().execute("SELECT visible_hint FROM scenario_steps WHERE scenario_version_id = ? AND position = ?", (run["scenario_version_id"], max(int(run["current_step"]), 1))).fetchone()
    if not step or not step["visible_hint"]:
        return error_response("HINT_NOT_AVAILABLE", "لا يتوفر تلميح لهذه الخطوة", 404)
    get_db().execute("UPDATE training_runs SET hints_used = hints_used + 1 WHERE id = ?", (run_id,))
    record_training_action(get_db(), run_id, actor_id(), "hint_used", "training_run", run_id, {}, f"hint:{run_id}:{int(run['hints_used']) + 1}")
    return jsonify({"hint": step["visible_hint"], "hints_used": int(run["hints_used"]) + 1})


@training_api.get("/api/training/runs/<int:run_id>")
@require_permission("training.run")
def run_detail(run_id: int):
    run = _run_access(run_id)
    if not run:
        return error_response("RUN_NOT_FOUND", "جلسة التدريب غير موجودة", 404)
    item = dict(run)
    item["snapshot"] = json.loads(item["snapshot"])
    item["events"] = [dict(row) for row in get_db().execute("SELECT tre.step_id, tre.sequence_number, e.id, e.event_id, e.event_time, e.severity, e.event_type, e.title FROM training_run_events tre JOIN security_events e ON e.id = tre.event_id WHERE tre.run_id = ? ORDER BY tre.sequence_number", (run_id,)).fetchall()]
    total_steps = int(get_db().execute("SELECT COUNT(*) FROM scenario_steps WHERE scenario_version_id = ?", (run["scenario_version_id"],)).fetchone()[0])
    item["total_steps"] = total_steps
    item["progress"] = int(run["current_step"]) / total_steps if total_steps else 0
    item["ground_truth_visible"] = has_permission(current_user(), "ground_truth.read") or run["state"] == "completed" and has_permission(current_user(), "training.manage")
    return jsonify(item)


@training_api.get("/api/training/runs/<int:run_id>/ground-truth")
@require_permission("ground_truth.read")
def run_ground_truth(run_id: int):
    run = _run_access(run_id)
    if not run:
        return error_response("RUN_NOT_FOUND", "جلسة التدريب غير موجودة", 404)
    rows = get_db().execute("SELECT step_id, expected_detections, relevant_evidence, allowed_responses, score_weight FROM scenario_ground_truth WHERE scenario_version_id = ? ORDER BY id", (run["scenario_version_id"],)).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        for field in ("expected_detections", "relevant_evidence", "allowed_responses"):
            item[field] = json.loads(item[field])
        items.append(item)
    return jsonify({"items": items})
