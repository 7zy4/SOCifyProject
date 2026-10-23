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


def _training_ground_truth(connection: sqlite3.Connection, scenario_version_id: int) -> tuple[set[tuple[str, str]], set[tuple[str, str]], set[str]]:
    rows = connection.execute(
        "SELECT step_id, expected_detections, relevant_evidence, allowed_responses FROM scenario_ground_truth WHERE scenario_version_id = ?",
        (scenario_version_id,),
    ).fetchall()
    detection_targets: set[tuple[str, str]] = set()
    evidence_targets: set[tuple[str, str]] = set()
    response_targets: set[str] = set()
    for row in rows:
        detection_targets.update((row["step_id"], str(value)) for value in json.loads(row["expected_detections"]))
        evidence_targets.update((row["step_id"], str(value)) for value in json.loads(row["relevant_evidence"]))
        response_targets.update(str(value) for value in json.loads(row["allowed_responses"]))
    return detection_targets, evidence_targets, response_targets


def _learner_detection_results(
    connection: sqlite3.Connection,
    run_id: int,
    user_id: int,
    expected: set[tuple[str, str]],
) -> tuple[set[tuple[str, str]], int, int, list[float]]:
    rows = connection.execute(
        """SELECT a.id AS alert_id, a.detected_at, r.name AS rule_name,
                  tre.step_id, ta.action_type, ta.payload, ta.occurred_at, ta.id AS action_id
           FROM alerts a JOIN rules r ON r.id = a.rule_id
           LEFT JOIN alert_events ae ON ae.alert_id = a.id
           LEFT JOIN training_run_events tre ON tre.event_id = ae.event_id AND tre.run_id = ?
           LEFT JOIN trainee_actions ta ON ta.run_id = ? AND ta.user_id = ?
                AND ta.target_type = 'alert' AND ta.target_id = CAST(a.id AS TEXT)
                AND ta.action_type = 'alert_triage'
           WHERE a.training_run_id = ?
           ORDER BY a.id, ta.id""",
        (run_id, run_id, user_id, run_id),
    ).fetchall()
    alerts: dict[int, dict[str, Any]] = {}
    for row in rows:
        item = alerts.setdefault(
            int(row["alert_id"]),
            {"name": str(row["rule_name"]), "steps": set(), "decision": None, "detected_at": row["detected_at"], "triaged_at": None},
        )
        if row["step_id"]:
            item["steps"].add(str(row["step_id"]))
        if row["action_id"] is not None and (item["decision"] is None or int(row["action_id"]) >= int(item["decision"][0])):
            payload = json.loads(row["payload"])
            item["decision"] = (int(row["action_id"]), payload.get("status"))
            item["triaged_at"] = row["occurred_at"]
    matched: set[tuple[str, str]] = set()
    true_positive = 0
    false_positive = 0
    analyst_latency: list[float] = []
    for item in alerts.values():
        if item["decision"] is None or item["decision"][1] not in {"triaged", "investigating", "closed"}:
            continue
        candidates = {(step, item["name"]) for step in item["steps"]} & expected
        unused = candidates - matched
        if unused:
            matched.add(sorted(unused)[0])
            true_positive += 1
        else:
            false_positive += 1
        if item["triaged_at"] and item["detected_at"]:
            seconds = (parse_timestamp(item["triaged_at"]) - parse_timestamp(item["detected_at"])).total_seconds()
            analyst_latency.append(max(seconds, 0.0))
    return matched, true_positive, false_positive, analyst_latency


def _learner_evidence(
    connection: sqlite3.Connection,
    run_id: int,
    user_id: int,
    expected: set[tuple[str, str]],
) -> set[tuple[str, str]]:
    rows = connection.execute(
        """SELECT ta.target_id, tre.step_id, e.source_ip, e.destination_ip, e.username,
                  e.hostname, e.process_name, e.parent_process, e.file_hash, e.raw_data
           FROM trainee_actions ta
           JOIN training_run_events tre ON tre.run_id = ta.run_id AND
                CAST(tre.event_id AS TEXT) = ta.target_id
           JOIN security_events e ON e.id = tre.event_id
           WHERE ta.run_id = ? AND ta.user_id = ?
             AND ta.action_type = 'evidence_added' AND ta.target_type = 'event'""",
        (run_id, user_id),
    ).fetchall()
    matched: set[tuple[str, str]] = set()
    for row in rows:
        raw = json.loads(row["raw_data"] or "{}")
        available_fields = set(row.keys())
        for step, field in expected:
            if step != row["step_id"]:
                continue
            if (field in available_fields and row[field] not in (None, "")) or (isinstance(raw, dict) and raw.get(field) not in (None, "")):
                matched.add((step, field))
    return matched


def _learner_responses(connection: sqlite3.Connection, run_id: int, user_id: int) -> set[str]:
    rows = connection.execute(
        """SELECT DISTINCT ps.action_type
           FROM playbook_runs pr
           JOIN playbook_step_runs psr ON psr.run_id = pr.id AND psr.status = 'succeeded'
           JOIN playbook_steps ps ON ps.id = psr.step_id
           WHERE pr.training_run_id = ? AND pr.requested_by = ? AND pr.state = 'succeeded'""",
        (run_id, user_id),
    ).fetchall()
    return {str(row["action_type"]) for row in rows}


def calculate_assessment(connection: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    policy_version = "socify-score-v2"
    existing = connection.execute(
        "SELECT * FROM assessment_snapshots WHERE run_id = ? AND policy_version = ? ORDER BY revision DESC LIMIT 1",
        (run_id, policy_version),
    ).fetchone()
    if existing:
        return assessment_view(existing)
    run = connection.execute("SELECT * FROM training_runs WHERE id = ?", (run_id,)).fetchone()
    if not run or run["state"] != "completed" or not run["submitted_at"]:
        raise ValueError("training run requires explicit learner submission before scoring")
    version = connection.execute("SELECT * FROM scenario_versions WHERE id = ?", (run["scenario_version_id"],)).fetchone()
    if version is None:
        raise RuntimeError("scenario version is missing")
    expected_detection, expected_evidence, expected_responses = _training_ground_truth(connection, int(run["scenario_version_id"]))
    detected, true_positives, false_positives, latencies = _learner_detection_results(connection, run_id, int(run["user_id"]), expected_detection)
    false_negatives = len(expected_detection - detected)
    precision = true_positives / (true_positives + false_positives) if true_positives + false_positives else 0.0
    recall = true_positives / len(expected_detection) if expected_detection else 1.0
    evidence_found = _learner_evidence(connection, run_id, int(run["user_id"]), expected_evidence)
    response_found = _learner_responses(connection, run_id, int(run["user_id"])) & expected_responses
    cases = connection.execute(
        "SELECT status, created_at, closed_at FROM incident_cases WHERE training_run_id = ? AND workspace_id = ?",
        (run_id, run["workspace_id"]),
    ).fetchall()
    actions = connection.execute(
        "SELECT action_type, payload FROM trainee_actions WHERE run_id = ? AND user_id = ? ORDER BY id",
        (run_id, run["user_id"]),
    ).fetchall()
    transitions = [json.loads(action["payload"]).get("to") for action in actions if action["action_type"] == "case_transition"]
    closed_cases = [case for case in cases if case["status"] == "closed"]
    investigation_progress = (
        (0.40 if cases else 0.0)
        + (0.30 if any(status in {"triaged", "investigating", "contained", "recovered"} for status in transitions) else 0.0)
        + (0.30 if closed_cases else 0.0)
    )
    completed_at = parse_timestamp(run["submitted_at"])
    started_at = parse_timestamp(run["started_at"])
    elapsed_seconds = max((completed_at - started_at).total_seconds(), 0.0)
    allowed_seconds = max(int(version["duration_minutes"]) * 60, 1)
    hints = int(run["hints_used"] or 0)
    timing = _bounded((100 if elapsed_seconds <= allowed_seconds else 100 * allowed_seconds / max(elapsed_seconds, 1)) - 5 * hints)
    false_positive_accuracy = _bounded(100 * (1 - false_positives / max(true_positives + false_positives, 1))) if true_positives + false_positives else 0.0
    case_resolution_seconds = [
        max((parse_timestamp(case["closed_at"]) - parse_timestamp(case["created_at"])).total_seconds(), 0.0) for case in closed_cases if case["closed_at"]
    ]
    metrics: dict[str, Any] = {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "detection_precision": round(precision, 4),
        "detection_recall": round(recall, 4),
        "false_positive_rate": round(false_positives / max(true_positives + false_positives, 1), 4),
        "analyst_triage_latency_seconds": round(sum(latencies) / len(latencies), 3) if latencies else None,
        "case_resolution_seconds": round(sum(case_resolution_seconds) / len(case_resolution_seconds), 3) if case_resolution_seconds else None,
        "elapsed_seconds": round(elapsed_seconds, 3),
        "actions": len(actions),
        "hints_used": hints,
    }
    components: dict[str, Any] = {
        "detection": _bounded(100 * precision * recall),
        "investigation": _bounded(100 * investigation_progress),
        "response": _bounded(100 * len(response_found) / len(expected_responses)) if expected_responses else 100.0,
        "evidence": _bounded(100 * len(evidence_found) / len(expected_evidence)) if expected_evidence else 100.0,
        "time": timing,
        "false_positive": false_positive_accuracy,
        "metrics": metrics,
    }
    configured_weights = json.loads(version["scoring_policy"] or "{}")
    weights = {key: float(configured_weights.get(key, value)) for key, value in DEFAULT_WEIGHTS.items()}
    if round(sum(weights.values()), 6) != 100 or any(weight < 0 or weight > 100 for weight in weights.values()):
        weights = dict(DEFAULT_WEIGHTS)
    total = _bounded(sum(float(components[key]) * weight / 100 for key, weight in weights.items()))
    inputs = {
        "run_id": run_id,
        "scenario_version_id": run["scenario_version_id"],
        "difficulty": run["difficulty"],
        "expected_detections": len(expected_detection),
        "expected_evidence": len(expected_evidence),
        "expected_responses": len(expected_responses),
        "matched_detection_targets": sorted([list(item) for item in detected]),
        "matched_evidence_targets": sorted([list(item) for item in evidence_found]),
        "matched_response_actions": sorted(response_found),
        "false_negatives": false_negatives,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "cases": len(cases),
        "closed_cases": len(closed_cases),
        "submitted_at": run["submitted_at"],
    }
    cursor = connection.execute(
        """INSERT INTO assessment_snapshots
           (assessment_id, workspace_id, run_id, user_id, policy_version, weights, inputs, components, total_score, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            public_id("ASM"),
            run["workspace_id"],
            run_id,
            run["user_id"],
            policy_version,
            json.dumps(weights, sort_keys=True, separators=(",", ":")),
            json.dumps(inputs, sort_keys=True, separators=(",", ":")),
            json.dumps(components, sort_keys=True, separators=(",", ":")),
            total,
            iso_now(),
        ),
    )
    assessment_id = inserted_id(cursor)
    row = connection.execute("SELECT * FROM assessment_snapshots WHERE id = ?", (assessment_id,)).fetchone()
    if row is None:
        raise RuntimeError("assessment disappeared during request")
    record_audit(
        connection, "create", "assessment", assessment_id, details={"run_id": run_id, "score": total}, actor=run["user_id"], workspace=run["workspace_id"]
    )
    return assessment_view(row)


def assessment_view(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    for field in ("weights", "inputs", "components"):
        item[field] = json.loads(item[field])
    fingerprint = hashlib.sha256(
        json.dumps(
            {"weights": item["weights"], "inputs": item["inputs"], "components": item["components"], "total": item["total_score"]},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    item["calculation_fingerprint"] = fingerprint
    return item


def _assessment_access(assessment_id: int) -> sqlite3.Row | None:
    user = current_user()
    if has_permission(user, "scores.read_team"):
        return get_db().execute("SELECT * FROM assessment_snapshots WHERE id = ? AND workspace_id = ?", (assessment_id, workspace_id())).fetchone()
    return (
        get_db()
        .execute("SELECT * FROM assessment_snapshots WHERE id = ? AND workspace_id = ? AND user_id = ?", (assessment_id, workspace_id(), actor_id()))
        .fetchone()
    )


@scoring_api.get("/api/scores/me")
@require_permission("scores.read_own")
def my_scores():
    rows = (
        get_db()
        .execute(
            """SELECT a.*, tr.difficulty, s.name AS scenario_name
        FROM assessment_snapshots a JOIN training_runs tr ON tr.id = a.run_id
        JOIN scenario_versions sv ON sv.id = tr.scenario_version_id JOIN attack_scenarios s ON s.id = sv.scenario_id
        WHERE a.workspace_id = ? AND a.user_id = ? ORDER BY a.created_at DESC""",
            (workspace_id(), actor_id()),
        )
        .fetchall()
    )
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
    rows = (
        get_db()
        .execute(
            f"""SELECT a.id, a.user_id, a.total_score, a.created_at, tr.difficulty, s.id AS scenario_id, s.name AS scenario_name, u.name
        FROM assessment_snapshots a JOIN training_runs tr ON tr.id = a.run_id
        JOIN scenario_versions sv ON sv.id = tr.scenario_version_id JOIN attack_scenarios s ON s.id = sv.scenario_id
        JOIN users u ON u.id = a.user_id WHERE {" AND ".join(clauses)}
        ORDER BY a.total_score DESC, a.created_at ASC LIMIT 100""",
            parameters,
        )
        .fetchall()
    )
    manager = has_permission(current_user(), "scores.read_team")
    items = []
    for rank, row in enumerate(rows, 1):
        pseudonym = "متدرب-" + hashlib.sha256(f"{workspace_id()}:{row['user_id']}".encode()).hexdigest()[:8]
        items.append(
            {
                "rank": rank,
                "assessment_id": row["id"] if manager or row["user_id"] == actor_id() else None,
                "name": row["name"] if manager or row["user_id"] == actor_id() else pseudonym,
                "score": row["total_score"],
                "difficulty": row["difficulty"],
                "scenario_id": row["scenario_id"],
                "scenario_name": row["scenario_name"],
                "is_current_user": row["user_id"] == actor_id(),
            }
        )
    return jsonify({"items": items, "grouping": ["scenario_id", "difficulty"]})
