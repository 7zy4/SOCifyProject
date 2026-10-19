import hashlib
import json
import sqlite3
from typing import Any

from flask import Blueprint, jsonify, request

from .audit import record_audit
from .db import get_db, inserted_id
from .schema import public_id
from .security import actor_id, current_user, error_response, has_permission, require_permission, workspace_id
from .timeutils import iso_now, parse_timestamp

scoring_api = Blueprint("scoring", __name__)

DEFAULT_WEIGHTS = {"detection": 25.0, "investigation": 25.0, "response": 20.0, "evidence": 15.0, "time": 10.0, "false_positive": 5.0}


def _bounded(value: float) -> float:
    return round(min(max(value, 0.0), 100.0), 4)


def calculate_assessment(connection: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    existing = connection.execute("SELECT * FROM assessment_snapshots WHERE run_id = ? AND policy_version = 'socify-score-v1' ORDER BY revision DESC LIMIT 1", (run_id,)).fetchone()
    if existing:
        return assessment_view(existing)
    run = connection.execute("SELECT * FROM training_runs WHERE id = ?", (run_id,)).fetchone()
    if not run or run["state"] != "completed":
        raise ValueError("training run must be completed before scoring")
    version = connection.execute("SELECT * FROM scenario_versions WHERE id = ?", (run["scenario_version_id"],)).fetchone()
    if version is None:
        raise RuntimeError("scenario version is missing for completed training run")
    ground_truth = connection.execute("SELECT * FROM scenario_ground_truth WHERE scenario_version_id = ?", (run["scenario_version_id"],)).fetchall()
    expected_detections = sum(len(json.loads(row["expected_detections"])) for row in ground_truth)
    expected_evidence = sum(len(json.loads(row["relevant_evidence"])) for row in ground_truth)
    expected_responses = sum(len(json.loads(row["allowed_responses"])) for row in ground_truth)
    alert_rows = connection.execute("SELECT status FROM alerts WHERE training_run_id = ?", (run_id,)).fetchall()
    detected = len(alert_rows)
    false_positives = sum(1 for row in alert_rows if row["status"] == "false_positive")
    cases = connection.execute("SELECT id, status, created_at, closed_at FROM incident_cases WHERE training_run_id = ?", (run_id,)).fetchall()
    case_ids = [int(row["id"]) for row in cases]
    evidence_count = 0
    if case_ids:
        placeholders = ",".join("?" for _ in case_ids)
        evidence_count = int(connection.execute(f"SELECT COUNT(*) FROM case_evidence WHERE case_id IN ({placeholders})", case_ids).fetchone()[0])
    response_count = int(connection.execute("SELECT COUNT(*) FROM playbook_runs WHERE training_run_id = ? AND state = 'succeeded'", (run_id,)).fetchone()[0])
    actions = int(connection.execute("SELECT COUNT(*) FROM trainee_actions WHERE run_id = ?", (run_id,)).fetchone()[0])
    hints = int(run["hints_used"] or 0)
    detection_recall = min(detected / expected_detections, 1.0) if expected_detections else 1.0
    detection_precision = max((detected - false_positives) / detected, 0.0) if detected else 0.0
    detection_score = _bounded(100 * detection_recall * detection_precision)
    closed_cases = sum(1 for row in cases if row["status"] == "closed")
    investigation_score = _bounded(100.0 if closed_cases else 70.0 if cases else 0.0)
    evidence_score = _bounded(100 * min(evidence_count / max(expected_evidence, 1), 1.0))
    response_score = _bounded(100 * min(response_count / max(expected_responses, 1), 1.0))
    allowed_seconds = int(version["duration_minutes"]) * 60
    elapsed_seconds = max((parse_timestamp(run["completed_at"]) - parse_timestamp(run["started_at"])).total_seconds(), 0)
    time_score = _bounded(100 if elapsed_seconds <= allowed_seconds else 100 * allowed_seconds / max(elapsed_seconds, 1))
    time_score = _bounded(time_score - hints * 5)
    false_positive_score = _bounded(100 * (1 - false_positives / max(detected, 1)))
    components: dict[str, Any] = {
        "detection": detection_score,
        "investigation": investigation_score,
        "response": response_score,
        "evidence": evidence_score,
        "time": time_score,
        "false_positive": false_positive_score,
        "metrics": {
            "detection_recall": round(detection_recall, 4),
            "detection_precision": round(detection_precision, 4),
            "false_positive_rate": round(false_positives / max(detected, 1), 4),
            "elapsed_seconds": round(elapsed_seconds, 3),
            "actions": actions,
            "hints_used": hints,
        },
    }
    configured_weights = json.loads(version["scoring_policy"] or "{}")
    weights = {key: float(configured_weights.get(key, value)) for key, value in DEFAULT_WEIGHTS.items()}
    if round(sum(weights.values()), 6) != 100:
        weights = dict(DEFAULT_WEIGHTS)
    total = _bounded(sum(float(components[key]) * weight / 100 for key, weight in weights.items()))
    inputs = {
        "run_id": run_id,
        "scenario_version_id": run["scenario_version_id"],
        "difficulty": run["difficulty"],
        "expected_detections": expected_detections,
        "expected_evidence": expected_evidence,
        "expected_responses": expected_responses,
        "detected_alerts": detected,
        "false_positives": false_positives,
        "cases": len(cases),
        "closed_cases": closed_cases,
        "evidence_count": evidence_count,
        "response_count": response_count,
    }
    cursor = connection.execute(
        """INSERT INTO assessment_snapshots
        (assessment_id, workspace_id, run_id, user_id, policy_version, weights, inputs, components, total_score, created_at)
        VALUES (?, ?, ?, ?, 'socify-score-v1', ?, ?, ?, ?, ?)""",
        (
            public_id("ASM"), run["workspace_id"], run_id, run["user_id"], json.dumps(weights, sort_keys=True, separators=(",", ":")),
            json.dumps(inputs, sort_keys=True, separators=(",", ":")), json.dumps(components, sort_keys=True, separators=(",", ":")), total, iso_now(),
        ),
    )
    assessment_id = inserted_id(cursor)
    assessment = connection.execute("SELECT * FROM assessment_snapshots WHERE id = ?", (assessment_id,)).fetchone()
    record_audit(connection, "create", "assessment", assessment_id, details={"run_id": run_id, "score": total}, actor=run["user_id"], workspace=run["workspace_id"])
    if assessment is None:
        raise RuntimeError("assessment disappeared during request")
    return assessment_view(assessment)


def assessment_view(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    for field in ("weights", "inputs", "components"):
        item[field] = json.loads(item[field])
    fingerprint = hashlib.sha256(json.dumps({"weights": item["weights"], "inputs": item["inputs"], "components": item["components"], "total": item["total_score"]}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    item["calculation_fingerprint"] = fingerprint
    return item


def _assessment_access(assessment_id: int) -> sqlite3.Row | None:
    user = current_user()
    if has_permission(user, "scores.read_team"):
        return get_db().execute("SELECT * FROM assessment_snapshots WHERE id = ? AND workspace_id = ?", (assessment_id, workspace_id())).fetchone()
    return get_db().execute("SELECT * FROM assessment_snapshots WHERE id = ? AND workspace_id = ? AND user_id = ?", (assessment_id, workspace_id(), actor_id())).fetchone()


@scoring_api.get("/api/scores/me")
@require_permission("scores.read_own")
def my_scores():
    rows = get_db().execute(
        """SELECT a.*, tr.difficulty, s.name AS scenario_name
        FROM assessment_snapshots a JOIN training_runs tr ON tr.id = a.run_id
        JOIN scenario_versions sv ON sv.id = tr.scenario_version_id JOIN attack_scenarios s ON s.id = sv.scenario_id
        WHERE a.workspace_id = ? AND a.user_id = ? ORDER BY a.created_at DESC""",
        (workspace_id(), actor_id()),
    ).fetchall()
    return jsonify({"items": [assessment_view(row) | {"difficulty": row["difficulty"], "scenario_name": row["scenario_name"]} for row in rows]})


@scoring_api.get("/api/assessments/<int:assessment_id>")
@require_permission("scores.read_own")
def assessment_detail(assessment_id: int):
    row = _assessment_access(assessment_id)
    if not row:
        return error_response("ASSESSMENT_NOT_FOUND", "نتيجة التقييم غير موجودة", 404)
    return jsonify(assessment_view(row))


@scoring_api.get("/api/training/runs/<int:run_id>/score")
@require_permission("scores.read_own")
def run_score(run_id: int):
    run = get_db().execute("SELECT * FROM training_runs WHERE id = ? AND workspace_id = ?", (run_id, workspace_id())).fetchone()
    if not run or run["user_id"] != actor_id() and not has_permission(current_user(), "scores.read_team"):
        return error_response("RUN_NOT_FOUND", "جلسة التدريب غير موجودة", 404)
    try:
        result = calculate_assessment(get_db(), run_id)
    except ValueError as exc:
        return error_response("ASSESSMENT_NOT_READY", str(exc), 409)
    return jsonify(result)


@scoring_api.get("/api/leaderboards")
@require_permission("scores.read_own")
def leaderboard():
    scenario_id = request.args.get("scenario_id")
    difficulty = request.args.get("difficulty")
    clauses = ["a.workspace_id = ?"]
    parameters: list[object] = [workspace_id()]
    if scenario_id:
        clauses.append("s.id = ?")
        parameters.append(scenario_id)
    if difficulty:
        clauses.append("tr.difficulty = ?")
        parameters.append(difficulty)
    rows = get_db().execute(
        f"""SELECT a.id, a.user_id, a.total_score, a.created_at, tr.difficulty, s.id AS scenario_id, s.name AS scenario_name, u.name
        FROM assessment_snapshots a JOIN training_runs tr ON tr.id = a.run_id
        JOIN scenario_versions sv ON sv.id = tr.scenario_version_id JOIN attack_scenarios s ON s.id = sv.scenario_id
        JOIN users u ON u.id = a.user_id WHERE {' AND '.join(clauses)}
        ORDER BY a.total_score DESC, a.created_at ASC LIMIT 100""",
        parameters,
    ).fetchall()
    manager = has_permission(current_user(), "scores.read_team")
    items = []
    for rank, row in enumerate(rows, 1):
        pseudonym = "متدرب-" + hashlib.sha256(f"{workspace_id()}:{row['user_id']}".encode()).hexdigest()[:8]
        items.append({"rank": rank, "assessment_id": row["id"] if manager or row["user_id"] == actor_id() else None, "name": row["name"] if manager or row["user_id"] == actor_id() else pseudonym, "score": row["total_score"], "difficulty": row["difficulty"], "scenario_id": row["scenario_id"], "scenario_name": row["scenario_name"], "is_current_user": row["user_id"] == actor_id()})
    return jsonify({"items": items, "grouping": ["scenario_id", "difficulty"]})
