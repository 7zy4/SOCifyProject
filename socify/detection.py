import hashlib
import ipaddress
import json
import math
import sqlite3
import time
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from flask import Blueprint, jsonify, request

from .audit import record_audit, record_training_action
from .db import get_db, inserted_id, transaction
from .schema import insert_outbox, public_id
from .security import actor_id, can_access_training_run, error_response, parse_json_object, require_permission, training_scope_sql, workspace_id
from .timeutils import iso_now, parse_timestamp

detection_api = Blueprint("detection", __name__)

FIELDS = {
    "event_type",
    "category",
    "severity",
    "source",
    "source_ip",
    "destination_ip",
    "username",
    "hostname",
    "process",
    "process_name",
    "parent_process",
    "file_hash",
    "http_status",
    "action",
    "outcome",
    "anomaly_score",
    "title",
    "training_run_id",
    "mitre_ids",
}
OPERATORS = {
    "equals",
    "not_equals",
    "contains",
    "not_contains",
    "starts_with",
    "ends_with",
    "in",
    "gt",
    "gte",
    "lt",
    "lte",
    "cidr",
    "exists",
    "boolean",
}
SEVERITIES = {"critical", "high", "medium", "low"}


class RuleValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


@dataclass(frozen=True)
class Evaluation:
    matched: bool
    event_ids: tuple[int, ...]
    trace: dict[str, Any]
    group_key: str


def _event_value(event: dict[str, Any], field: str) -> Any:
    if field == "process":
        field = "process_name"
    if field in event and event[field] is not None:
        return event[field]
    normalized = event.get("normalized_fields")
    if isinstance(normalized, str):
        try:
            normalized = json.loads(normalized)
        except json.JSONDecodeError:
            normalized = {}
    if isinstance(normalized, dict):
        return normalized.get(field)
    return None


def _coerce_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _leaf_matches(condition: dict[str, Any], event: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    field = str(condition["field"])
    operator = str(condition["operator"])
    expected = condition.get("value")
    actual = _event_value(event, field)
    matched = False
    if operator == "exists":
        matched = (actual is not None) is bool(expected if expected is not None else True)
    elif operator == "boolean":
        matched = isinstance(actual, bool) and actual is bool(expected)
    elif operator == "equals":
        matched = actual == expected or str(actual).casefold() == str(expected).casefold()
    elif operator == "not_equals":
        matched = not (actual == expected or str(actual).casefold() == str(expected).casefold())
    elif operator == "contains":
        matched = expected in actual if isinstance(actual, list) else str(expected).casefold() in str(actual or "").casefold()
    elif operator == "not_contains":
        matched = expected not in actual if isinstance(actual, list) else str(expected).casefold() not in str(actual or "").casefold()
    elif operator == "starts_with":
        matched = str(actual or "").casefold().startswith(str(expected).casefold())
    elif operator == "ends_with":
        matched = str(actual or "").casefold().endswith(str(expected).casefold())
    elif operator == "in":
        matched = isinstance(expected, list) and any(actual == item or str(actual).casefold() == str(item).casefold() for item in expected)
    elif operator in {"gt", "gte", "lt", "lte"}:
        left = _coerce_number(actual)
        right = _coerce_number(expected)
        if left is not None and right is not None:
            matched = {"gt": left > right, "gte": left >= right, "lt": left < right, "lte": left <= right}[operator]
    elif operator == "cidr":
        try:
            matched = ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            matched = False
    return matched, {"field": field, "operator": operator, "expected": expected, "actual": actual, "matched": matched}


def _condition_matches(node: dict[str, Any], event: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    if "field" in node:
        return _leaf_matches(node, event)
    logic = str(node.get("logic", "and")).lower()
    children = node.get("conditions")
    if not isinstance(children, list):
        return False, {"logic": logic, "matched": False, "children": []}
    results = [_condition_matches(item, event) for item in children if isinstance(item, dict)]
    values = [item[0] for item in results]
    matched = all(values) if logic == "and" else any(values) if logic == "or" else not any(values)
    return matched, {"logic": logic, "matched": matched, "children": [item[1] for item in results]}


def _validate_condition(node: object, path: str, depth: int, errors: list[str], counter: list[int]) -> None:
    if depth > 5:
        errors.append(f"{path}: maximum nesting depth is 5")
        return
    if not isinstance(node, dict):
        errors.append(f"{path}: condition must be an object")
        return
    counter[0] += 1
    if counter[0] > 30:
        errors.append("rule exceeds the 30-condition budget")
        return
    if "field" in node:
        field = node.get("field")
        operator = node.get("operator")
        if not isinstance(field, str) or field not in FIELDS:
            errors.append(f"{path}.field: unsupported field")
        if not isinstance(operator, str) or operator not in OPERATORS:
            errors.append(f"{path}.operator: unsupported operator")
        if operator != "exists" and "value" not in node:
            errors.append(f"{path}.value: value is required")
        if operator == "in" and (not isinstance(node.get("value"), list) or len(node.get("value", [])) > 100):
            errors.append(f"{path}.value: in requires a list with at most 100 items")
        if operator == "cidr":
            try:
                ipaddress.ip_network(str(node.get("value")), strict=False)
            except ValueError:
                errors.append(f"{path}.value: invalid CIDR")
        return
    logic = node.get("logic")
    children = node.get("conditions")
    if not isinstance(logic, str) or logic not in {"and", "or", "not"}:
        errors.append(f"{path}.logic: expected and, or, or not")
    if not isinstance(children, list) or not children or len(children) > 20:
        errors.append(f"{path}.conditions: expected 1-20 conditions")
        return
    if logic == "not" and len(children) != 1:
        errors.append(f"{path}.conditions: not accepts one condition")
    for index, child in enumerate(children):
        _validate_condition(child, f"{path}.conditions[{index}]", depth + 1, errors, counter)


def validate_dsl(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuleValidationError(["dsl must be an object"])
    errors: list[str] = []
    root = value.get("condition") or {"logic": value.get("logic", "and"), "conditions": value.get("conditions", [])}
    _validate_condition(root, "condition", 0, errors, [0])
    window = value.get("window")
    if window is not None:
        if not isinstance(window, dict):
            errors.append("window must be an object")
        else:
            seconds = window.get("seconds")
            threshold = window.get("threshold")
            group_by = window.get("group_by", [])
            mode = window.get("mode", "count")
            if type(seconds) is not int or not 1 <= seconds <= 604800:
                errors.append("window.seconds must be between 1 and 604800")
            if type(threshold) is not int or not 1 <= threshold <= 10000:
                errors.append("window.threshold must be between 1 and 10000")
            if not isinstance(group_by, list) or len(group_by) > 4 or any(not isinstance(item, str) or item not in FIELDS for item in group_by):
                errors.append("window.group_by contains unsupported fields")
            if not isinstance(mode, str) or mode not in {"count", "distinct_count"}:
                errors.append("window.mode must be count or distinct_count")
            if mode == "distinct_count" and (not isinstance(window.get("distinct_field"), str) or window["distinct_field"] not in FIELDS):
                errors.append("window.distinct_field is required for distinct_count")
            allowed_lateness = window.get("allowed_lateness_seconds", 86400)
            if not isinstance(allowed_lateness, int) or not 0 <= allowed_lateness <= 2592000:
                errors.append("window.allowed_lateness_seconds is outside the permitted range")
    sequence = value.get("sequence")
    if sequence is not None:
        if not isinstance(sequence, list) or not 2 <= len(sequence) <= 10:
            errors.append("sequence must contain 2-10 ordered conditions")
        else:
            for index, item in enumerate(sequence):
                _validate_condition(item, f"sequence[{index}]", 0, errors, [0])
            if not isinstance(window, dict):
                errors.append("sequence rules require a window")
    mitre_ids = value.get("mitre_ids", [])
    if not isinstance(mitre_ids, list) or len(mitre_ids) > 20 or any(not isinstance(item, str) for item in mitre_ids):
        errors.append("mitre_ids must be a list of at most 20 identifiers")
    if errors:
        raise RuleValidationError(errors)
    normalized = dict(value)
    normalized["condition"] = root
    normalized.pop("logic", None)
    normalized.pop("conditions", None)
    return normalized


def legacy_dsl(rule: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    data = dict(rule)
    if data.get("dsl_json"):
        return validate_dsl(json.loads(str(data["dsl_json"])))
    condition = parse_json_object(data.get("condition_value") or {}, "condition_value")
    kind = data.get("condition_type")
    if kind == "failed_login_count":
        timeframe = str(condition.get("timeframe", "10m"))
        unit = timeframe[-1:].lower()
        multiplier = {"s": 1, "m": 60, "h": 3600}.get(unit, 60)
        try:
            seconds = int(timeframe[:-1]) * multiplier
        except ValueError:
            seconds = 600
        return validate_dsl(
            {
                "condition": {
                    "logic": "or",
                    "conditions": [
                        {"field": "event_type", "operator": "equals", "value": "failed_login"},
                        {"field": "category", "operator": "contains", "value": "brute force"},
                    ],
                },
                "window": {"seconds": seconds, "threshold": int(condition.get("threshold", 5)), "group_by": ["source_ip", "username"], "mode": "count"},
                "mitre_ids": ["T1110"],
            }
        )
    if kind == "network_anomaly":
        return validate_dsl({"condition": {"field": "anomaly_score", "operator": "gte", "value": condition.get("threshold", 0.8)}, "mitre_ids": []})
    if kind == "error_level":
        return validate_dsl({"condition": {"field": "severity", "operator": "equals", "value": condition.get("level", "critical")}, "mitre_ids": []})
    raise RuleValidationError([f"unsupported legacy condition type: {kind}"])


def _event_dict(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    for key in ("normalized_fields", "tags", "mitre_ids"):
        value = data.get(key)
        if isinstance(value, str):
            try:
                data[key] = json.loads(value)
            except json.JSONDecodeError:
                data[key] = {} if key == "normalized_fields" else []
    return data


def _group_key(event: dict[str, Any], fields: list[str]) -> str:
    values = [str(_event_value(event, field) or "") for field in fields]
    return "|".join(values) if values else "global"


def _candidate_events(connection: sqlite3.Connection, event: dict[str, Any], seconds: int) -> list[dict[str, Any]]:
    end = parse_timestamp(event["event_time"])
    start = end - timedelta(seconds=seconds)
    rows = connection.execute(
        """SELECT * FROM security_events
        WHERE workspace_id = ? AND training_run_id IS ? AND source != 'rules_engine' AND event_time >= ? AND event_time <= ?
        ORDER BY event_time, id LIMIT 20000""",
        (event["workspace_id"], event.get("training_run_id"), start.isoformat().replace("+00:00", "Z"), end.isoformat().replace("+00:00", "Z")),
    ).fetchall()
    return [_event_dict(row) for row in rows]


def evaluate_dsl(connection: sqlite3.Connection, dsl: dict[str, Any], event: dict[str, Any]) -> Evaluation:
    root = dsl["condition"]
    direct, direct_trace = _condition_matches(root, event)
    window = dsl.get("window")
    if not isinstance(window, dict):
        return Evaluation(
            direct, (int(event["id"]),) if direct else (), {"condition": direct_trace, "event_time": event["event_time"], "policy": "single_event"}, "single"
        )
    if not direct:
        return Evaluation(False, (), {"condition": direct_trace, "event_time": event["event_time"], "policy": "event_time_window", "count": 0}, "unmatched")
    sequence = dsl.get("sequence")
    if isinstance(sequence, list) and sequence:
        final_step, final_trace = _condition_matches(sequence[-1], event)
        if not final_step:
            return Evaluation(
                False, (), {"condition": direct_trace, "final_step": final_trace, "event_time": event["event_time"], "policy": "ordered_sequence"}, "unmatched"
            )
    seconds = int(window["seconds"])
    threshold = int(window["threshold"])
    group_fields = [str(item) for item in window.get("group_by", [])]
    target_group = _group_key(event, group_fields)
    max_time_row = connection.execute(
        "SELECT MAX(event_time) FROM security_events WHERE workspace_id = ? AND training_run_id IS ? AND source != 'rules_engine'",
        (event["workspace_id"], event.get("training_run_id")),
    ).fetchone()
    max_time = parse_timestamp(max_time_row[0]) if max_time_row and max_time_row[0] else parse_timestamp(event["event_time"])
    lateness = int((max_time - parse_timestamp(event["event_time"])).total_seconds())
    allowed_lateness = int(window.get("allowed_lateness_seconds", 86400))
    if lateness > allowed_lateness:
        return Evaluation(
            False,
            (),
            {"condition": direct_trace, "policy": "event_time", "late_by_seconds": lateness, "allowed_lateness_seconds": allowed_lateness, "suppressed": True},
            target_group,
        )
    candidates = _candidate_events(connection, event, seconds)
    matching: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for candidate in candidates:
        matched, trace = _condition_matches(root, candidate)
        if matched and _group_key(candidate, group_fields) == target_group:
            matching.append((candidate, trace))
    if sequence:
        ordered_ids: list[int] = []
        position = 0
        for candidate in candidates:
            if _group_key(candidate, group_fields) != target_group:
                continue
            matched, _ = _condition_matches(sequence[position], candidate)
            if matched:
                ordered_ids.append(int(candidate["id"]))
                position += 1
                if position == len(sequence):
                    break
        matched = position == len(sequence)
        return Evaluation(
            matched,
            tuple(ordered_ids) if matched else (),
            {"policy": "ordered_sequence", "group": target_group, "matched_steps": position, "required_steps": len(sequence), "window_seconds": seconds},
            target_group,
        )
    mode = str(window.get("mode", "count"))
    if mode == "distinct_count":
        distinct_field = str(window["distinct_field"])
        selected: dict[str, int] = {}
        for candidate, _ in matching:
            value = str(_event_value(candidate, distinct_field) or "")
            if value and value not in selected:
                selected[value] = int(candidate["id"])
        matched = len(selected) >= threshold
        event_ids = tuple(list(selected.values())[:threshold]) if matched else tuple(selected.values())
        count = len(selected)
    else:
        matched = len(matching) >= threshold
        event_ids = tuple(int(item[0]["id"]) for item in matching[:threshold] if item[0].get("id") is not None)
        count = len(matching)
    trace = {
        "policy": "event_time_window",
        "window_seconds": seconds,
        "threshold": threshold,
        "count": count,
        "group_by": group_fields,
        "group": target_group,
        "late_by_seconds": max(0, lateness),
        "allowed_lateness_seconds": allowed_lateness,
        "condition": direct_trace,
        "matched_event_ids": list(event_ids),
    }
    return Evaluation(matched, event_ids if matched else (), trace, target_group)


def _alert_reason(rule_name: str, evaluation: Evaluation) -> str:
    policy = evaluation.trace.get("policy")
    if policy == "event_time_window":
        return f"{rule_name}: {evaluation.trace.get('count')} matching events reached threshold {evaluation.trace.get('threshold')} for {evaluation.group_key}"
    if policy == "ordered_sequence":
        return f"{rule_name}: ordered sequence completed for {evaluation.group_key}"
    return f"{rule_name}: event matched the published rule"


def evaluate_rules(connection: sqlite3.Connection, event_id: int) -> list[int]:
    row = connection.execute("SELECT * FROM security_events WHERE id = ?", (event_id,)).fetchone()
    if not row or row["source"] == "rules_engine":
        return []
    event = _event_dict(row)
    rules = connection.execute(
        "SELECT * FROM rules WHERE workspace_id = ? AND is_active = 1 AND archived_at IS NULL ORDER BY id LIMIT 500",
        (event["workspace_id"],),
    ).fetchall()
    alert_ids: list[int] = []
    for rule in rules:
        started = time.perf_counter()
        try:
            dsl = legacy_dsl(rule)
            evaluation = evaluate_dsl(connection, dsl, event)
            elapsed = (time.perf_counter() - started) * 1000
            previous_count = int(rule["match_count"] or 0)
            previous_average = float(rule["average_evaluation_ms"] or 0)
            updated_average = ((previous_average * previous_count) + elapsed) / (previous_count + 1)
            connection.execute("UPDATE rules SET average_evaluation_ms = ? WHERE id = ?", (updated_average, rule["id"]))
            if not evaluation.matched:
                if evaluation.trace.get("suppressed"):
                    connection.execute("UPDATE rules SET suppressions = suppressions + 1 WHERE id = ?", (rule["id"],))
                continue
            material = f"{rule['id']}|{rule['version']}|{evaluation.group_key}|{','.join(str(item) for item in evaluation.event_ids)}|{event.get('training_run_id') or ''}"
            dedup_key = hashlib.sha256(material.encode()).hexdigest()
            existing = connection.execute("SELECT id FROM alerts WHERE dedup_key = ?", (dedup_key,)).fetchone()
            if existing:
                continue
            action = parse_json_object(rule["action_value"] or {}, "action_value")
            severity = str(action.get("severity", event.get("severity") or "medium")).lower()
            if severity not in SEVERITIES:
                severity = "medium"
            confidence = _coerce_number(action.get("confidence", 0.85)) or 0.85
            confidence = min(max(confidence, 0), 1)
            mitre_ids = dsl.get("mitre_ids", [])
            unknown = [item for item in mitre_ids if not connection.execute("SELECT 1 FROM attack_techniques WHERE technique_id = ?", (item,)).fetchone()]
            if unknown:
                raise RuleValidationError([f"unknown MITRE technique: {item}" for item in unknown])
            now = iso_now()
            alert_public_id = public_id("ALT")
            alert_cursor = connection.execute(
                """INSERT INTO alerts
                (alert_id, workspace_id, training_run_id, rule_id, rule_version, reason, evidence, severity,
                confidence, detected_at, status, mitre_technique_ids, dedup_key, trace)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'untriaged', ?, ?, ?)""",
                (
                    alert_public_id,
                    event["workspace_id"],
                    event.get("training_run_id"),
                    rule["id"],
                    rule["version"],
                    _alert_reason(str(rule["name"]), evaluation),
                    json.dumps({"event_ids": list(evaluation.event_ids)}, separators=(",", ":")),
                    severity,
                    confidence,
                    now,
                    json.dumps(mitre_ids, separators=(",", ":")),
                    dedup_key,
                    json.dumps(evaluation.trace, ensure_ascii=False, separators=(",", ":")),
                ),
            )
            alert_id = inserted_id(alert_cursor)
            for matched_event_id in evaluation.event_ids:
                connection.execute("INSERT OR IGNORE INTO alert_events (alert_id, event_id) VALUES (?, ?)", (alert_id, matched_event_id))
            compatibility_event_id = public_id("DET")
            compatibility_cursor = connection.execute(
                """INSERT INTO security_events
                (event_id, external_id, idempotency_key, workspace_id, training_run_id, source, source_type, severity,
                category, event_type, title, description, event_time, ingested_at, timestamp, raw_data, normalized_fields,
                tags, mitre_ids, status, created_by, parser_version, raw_hash, provenance)
                VALUES (?, ?, ?, ?, ?, 'rules_engine', 'internal', ?, 'detection', 'alert', ?, ?, ?, ?, ?, ?, '{}', '[]', ?, 'open', ?, 'socify-detection-2', ?, ?)""",
                (
                    compatibility_event_id,
                    alert_public_id,
                    f"alert:{dedup_key}",
                    event["workspace_id"],
                    event.get("training_run_id"),
                    severity,
                    f"Detection: {str(rule['name'])[:220]}",
                    _alert_reason(str(rule["name"]), evaluation),
                    now,
                    now,
                    now,
                    json.dumps({"alert_id": alert_public_id, "rule_id": rule["id"]}, separators=(",", ":")),
                    json.dumps(mitre_ids, separators=(",", ":")),
                    event.get("created_by"),
                    hashlib.sha256(alert_public_id.encode()).hexdigest(),
                    json.dumps({"kind": "derived_alert", "origin_event_ids": list(evaluation.event_ids)}, separators=(",", ":")),
                ),
            )
            connection.execute(
                """INSERT OR IGNORE INTO detection_matches
                (rule_id, event_id, alert_event_id, alert_id, dedup_key, trace, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (rule["id"], event_id, inserted_id(compatibility_cursor), alert_id, dedup_key, json.dumps(evaluation.trace, separators=(",", ":")), now),
            )
            connection.execute("UPDATE rules SET match_count = match_count + 1, last_triggered_at = ? WHERE id = ?", (now, rule["id"]))
            insert_outbox(connection, int(event["workspace_id"]), "alert.created", {"id": alert_id, "alert_id": alert_public_id, "severity": severity})
            alert_ids.append(alert_id)
        except (RuleValidationError, ValueError, TypeError, json.JSONDecodeError):
            connection.execute("UPDATE rules SET failed_evaluations = failed_evaluations + 1 WHERE id = ?", (rule["id"],))
    return alert_ids


def _rule_payload() -> tuple[dict[str, Any] | None, object | None]:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, error_response("INVALID_JSON", "يلزم إرسال كائن JSON صالح", 400)
    try:
        dsl = validate_dsl(data.get("dsl"))
    except RuleValidationError as exc:
        return None, error_response("INVALID_RULE", "تعريف القاعدة غير صالح", 422, {"errors": exc.errors})
    mitre_ids = dsl.get("mitre_ids", [])
    if mitre_ids:
        placeholders = ",".join("?" for _ in mitre_ids)
        known = {
            row["technique_id"]
            for row in get_db().execute(f"SELECT technique_id FROM attack_techniques WHERE technique_id IN ({placeholders})", mitre_ids).fetchall()
        }
        unknown = sorted(set(mitre_ids) - known)
        if unknown:
            return None, error_response(
                "UNKNOWN_MITRE_TECHNIQUE", "تحتوي القاعدة على تقنيات غير موجودة في نسخة ATT&CK المثبتة", 422, {"technique_ids": unknown}
            )
    name = data.get("name")
    description = data.get("description", "")
    if not isinstance(name, str) or not 3 <= len(name.strip()) <= 150 or not isinstance(description, str) or len(description) > 2000:
        return None, error_response("INVALID_RULE_METADATA", "تحقق من اسم القاعدة ووصفها", 422)
    action = data.get("action", {"severity": "medium", "confidence": 0.85})
    if not isinstance(action, dict) or not isinstance(action.get("severity", "medium"), str) or action.get("severity", "medium") not in SEVERITIES:
        return None, error_response("INVALID_RULE_ACTION", "إجراء القاعدة غير صالح", 422)
    return {
        "name": name.strip(),
        "description": description.strip(),
        "dsl": dsl,
        "action": action,
        "active": bool(data.get("active", False)),
        "change_summary": str(data.get("change_summary") or "Rule created")[:500],
    }, None


def _rule_view(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    try:
        data["dsl"] = legacy_dsl(row)
    except (RuleValidationError, ValueError, json.JSONDecodeError):
        data["dsl"] = None
    data["action"] = parse_json_object(data.pop("action_value") or {}, "action_value")
    data.pop("condition_value", None)
    data.pop("dsl_json", None)
    return data


@detection_api.get("/api/rules")
@require_permission("rules.read")
def list_rules():
    include_archived = request.args.get("archived") == "1"
    query = "SELECT * FROM rules WHERE workspace_id = ?"
    parameters: list[object] = [workspace_id()]
    if not include_archived:
        query += " AND archived_at IS NULL"
    query += " ORDER BY updated_at DESC, id DESC"
    rows = get_db().execute(query, parameters).fetchall()
    return jsonify({"items": [_rule_view(row) for row in rows], "total": len(rows)})


@detection_api.post("/api/rules")
@require_permission("rules.manage")
def create_rule():
    payload, failure = _rule_payload()
    if failure:
        return failure
    if payload is None:
        raise RuntimeError("Rule payload validation returned no result")
    with transaction():
        now = iso_now()
        cursor = get_db().execute(
            """INSERT INTO rules
            (name, description, condition_type, condition_value, dsl_json, action_type, action_value, is_active,
            version, deployment_state, workspace_id, created_by, deployed_by, created_at, updated_at)
            VALUES (?, ?, 'dsl', ?, ?, 'create_alert', ?, ?, 1, ?, ?, ?, ?, ?, ?)""",
            (
                payload["name"],
                payload["description"],
                json.dumps(payload["dsl"], separators=(",", ":")),
                json.dumps(payload["dsl"], separators=(",", ":")),
                json.dumps(payload["action"], separators=(",", ":")),
                1 if payload["active"] else 0,
                "published" if payload["active"] else "draft",
                workspace_id(),
                actor_id(),
                actor_id() if payload["active"] else None,
                now,
                now,
            ),
        )
        rule_id = inserted_id(cursor)
        get_db().execute(
            "INSERT INTO rule_versions (rule_id, version, dsl_json, action_json, change_summary, created_by, created_at) VALUES (?, 1, ?, ?, ?, ?, ?)",
            (
                rule_id,
                json.dumps(payload["dsl"], separators=(",", ":")),
                json.dumps(payload["action"], separators=(",", ":")),
                payload["change_summary"],
                actor_id(),
                now,
            ),
        )
        record_audit(get_db(), "create", "rule", rule_id, details={"active": payload["active"]})
    row = get_db().execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
    return jsonify(_rule_view(row)), 201, {"Location": f"/api/rules/{rule_id}"}


@detection_api.get("/api/rules/<int:rule_id>")
@require_permission("rules.read")
def rule_detail(rule_id: int):
    row = get_db().execute("SELECT * FROM rules WHERE id = ? AND workspace_id = ?", (rule_id, workspace_id())).fetchone()
    if not row:
        return error_response("RULE_NOT_FOUND", "القاعدة غير موجودة", 404)
    return jsonify(_rule_view(row))


@detection_api.put("/api/rules/<int:rule_id>")
@require_permission("rules.manage")
def update_rule(rule_id: int):
    current = get_db().execute("SELECT * FROM rules WHERE id = ? AND workspace_id = ? AND archived_at IS NULL", (rule_id, workspace_id())).fetchone()
    if not current:
        return error_response("RULE_NOT_FOUND", "القاعدة غير موجودة", 404)
    payload, failure = _rule_payload()
    if failure:
        return failure
    if payload is None:
        raise RuntimeError("Rule payload validation returned no result")
    version = int(current["version"]) + 1
    now = iso_now()
    with transaction():
        get_db().execute(
            """UPDATE rules SET name = ?, description = ?, condition_value = ?, dsl_json = ?, action_value = ?, is_active = ?,
            version = ?, deployment_state = ?, deployed_by = ?, updated_at = ? WHERE id = ?""",
            (
                payload["name"],
                payload["description"],
                json.dumps(payload["dsl"], separators=(",", ":")),
                json.dumps(payload["dsl"], separators=(",", ":")),
                json.dumps(payload["action"], separators=(",", ":")),
                1 if payload["active"] else 0,
                version,
                "published" if payload["active"] else "draft",
                actor_id() if payload["active"] else current["deployed_by"],
                now,
                rule_id,
            ),
        )
        get_db().execute(
            "INSERT INTO rule_versions (rule_id, version, dsl_json, action_json, change_summary, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                rule_id,
                version,
                json.dumps(payload["dsl"], separators=(",", ":")),
                json.dumps(payload["action"], separators=(",", ":")),
                payload["change_summary"],
                actor_id(),
                now,
            ),
        )
        record_audit(get_db(), "update", "rule", rule_id, details={"version": version, "active": payload["active"]})
    return jsonify(_rule_view(get_db().execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()))


@detection_api.post("/api/rules/<int:rule_id>/toggle")
@require_permission("rules.manage")
def toggle_rule(rule_id: int):
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("active"), bool):
        return error_response("INVALID_TOGGLE", "يلزم إرسال active بقيمة منطقية", 422)
    row = get_db().execute("SELECT id FROM rules WHERE id = ? AND workspace_id = ? AND archived_at IS NULL", (rule_id, workspace_id())).fetchone()
    if not row:
        return error_response("RULE_NOT_FOUND", "القاعدة غير موجودة", 404)
    get_db().execute(
        "UPDATE rules SET is_active = ?, deployment_state = ?, deployed_by = ?, updated_at = ? WHERE id = ?",
        (1 if data["active"] else 0, "published" if data["active"] else "disabled", actor_id(), iso_now(), rule_id),
    )
    record_audit(get_db(), "activate" if data["active"] else "disable", "rule", rule_id)
    return jsonify({"id": rule_id, "active": data["active"]})


@detection_api.delete("/api/rules/<int:rule_id>")
@require_permission("rules.manage")
def archive_rule(rule_id: int):
    row = get_db().execute("SELECT id FROM rules WHERE id = ? AND workspace_id = ? AND archived_at IS NULL", (rule_id, workspace_id())).fetchone()
    if not row:
        return error_response("RULE_NOT_FOUND", "القاعدة غير موجودة", 404)
    get_db().execute(
        "UPDATE rules SET archived_at = ?, is_active = 0, deployment_state = 'archived', updated_at = ? WHERE id = ?", (iso_now(), iso_now(), rule_id)
    )
    record_audit(get_db(), "archive", "rule", rule_id)
    return "", 204


@detection_api.post("/api/rules/<int:rule_id>/clone")
@require_permission("rules.manage")
def clone_rule(rule_id: int):
    source = get_db().execute("SELECT * FROM rules WHERE id = ? AND workspace_id = ? AND archived_at IS NULL", (rule_id, workspace_id())).fetchone()
    if not source:
        return error_response("RULE_NOT_FOUND", "القاعدة غير موجودة", 404)
    data = request.get_json(silent=True)
    requested_name = data.get("name") if isinstance(data, dict) else None
    name = requested_name.strip() if isinstance(requested_name, str) and 3 <= len(requested_name.strip()) <= 150 else f"{source['name']} copy"
    now = iso_now()
    with transaction():
        cursor = get_db().execute(
            """INSERT INTO rules
            (name, description, condition_type, condition_value, dsl_json, action_type, action_value, is_active,
            version, deployment_state, workspace_id, created_by, created_at, updated_at)
            VALUES (?, ?, 'dsl', ?, ?, 'create_alert', ?, 0, 1, 'draft', ?, ?, ?, ?)""",
            (name, source["description"], source["dsl_json"], source["dsl_json"], source["action_value"], workspace_id(), actor_id(), now, now),
        )
        cloned_id = inserted_id(cursor)
        get_db().execute(
            "INSERT INTO rule_versions (rule_id, version, dsl_json, action_json, change_summary, created_by, created_at) VALUES (?, 1, ?, ?, ?, ?, ?)",
            (cloned_id, source["dsl_json"], source["action_value"], f"Cloned from rule {rule_id}", actor_id(), now),
        )
        record_audit(get_db(), "clone", "rule", cloned_id, details={"source_rule_id": rule_id})
    return jsonify(_rule_view(get_db().execute("SELECT * FROM rules WHERE id = ?", (cloned_id,)).fetchone())), 201


@detection_api.post("/api/rules/<int:rule_id>/backfill")
@require_permission("rules.manage")
def backfill_rule(rule_id: int):
    rule = get_db().execute("SELECT * FROM rules WHERE id = ? AND workspace_id = ? AND archived_at IS NULL", (rule_id, workspace_id())).fetchone()
    if not rule:
        return error_response("RULE_NOT_FOUND", "القاعدة غير موجودة", 404)
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("reason"), str) or len(data["reason"].strip()) < 8:
        return error_response("BACKFILL_REASON_REQUIRED", "يلزم سبب واضح لإعادة المعالجة", 422)
    try:
        limit = min(max(int(data.get("limit", 1000)), 1), 5000)
    except (TypeError, ValueError):
        return error_response("INVALID_BACKFILL_LIMIT", "حد إعادة المعالجة غير صالح", 422)
    scope, parameters = training_scope_sql("training_run_id")
    rows = (
        get_db()
        .execute(
            f"SELECT id FROM security_events WHERE workspace_id = ? AND source != 'rules_engine'{scope} ORDER BY event_time, id LIMIT ?",
            (workspace_id(), *parameters, limit),
        )
        .fetchall()
    )
    created: set[int] = set()
    started = time.perf_counter()
    with transaction():
        active_rule_ids = [
            int(row["id"])
            for row in get_db().execute("SELECT id FROM rules WHERE workspace_id = ? AND is_active = 1 AND archived_at IS NULL", (workspace_id(),)).fetchall()
        ]
        get_db().execute(
            "UPDATE rules SET is_active = CASE WHEN id = ? THEN 1 ELSE 0 END WHERE workspace_id = ? AND archived_at IS NULL", (rule_id, workspace_id())
        )
        for event in rows:
            created.update(evaluate_rules(get_db(), int(event["id"])))
        get_db().execute("UPDATE rules SET is_active = 0 WHERE workspace_id = ? AND archived_at IS NULL", (workspace_id(),))
        get_db().executemany("UPDATE rules SET is_active = 1 WHERE id = ?", [(identifier,) for identifier in active_rule_ids])
        record_audit(
            get_db(), "backfill", "rule", rule_id, details={"events": len(rows), "alerts": len(created), "reason": data["reason"].strip(), "limit": limit}
        )
    return jsonify(
        {
            "rule_id": rule_id,
            "processed_events": len(rows),
            "created_alert_ids": sorted(created),
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            "bounded": True,
        }
    )


@detection_api.post("/api/rules/<int:rule_id>/test")
@require_permission("rules.read")
def test_rule(rule_id: int):
    rule = get_db().execute("SELECT * FROM rules WHERE id = ? AND workspace_id = ?", (rule_id, workspace_id())).fetchone()
    if not rule:
        return error_response("RULE_NOT_FOUND", "القاعدة غير موجودة", 404)
    data = request.get_json(silent=True) or {}
    event_id = data.get("event_id") if isinstance(data, dict) else None
    if not isinstance(event_id, int):
        return error_response("EVENT_ID_REQUIRED", "حدد سجلًا لاختبار القاعدة", 422)
    event = get_db().execute("SELECT * FROM security_events WHERE id = ? AND workspace_id = ?", (event_id, workspace_id())).fetchone()
    if not event or not can_access_training_run(event["training_run_id"]):
        return error_response("EVENT_NOT_FOUND", "السجل غير موجود", 404)
    started = time.perf_counter()
    evaluation = evaluate_dsl(get_db(), legacy_dsl(rule), _event_dict(event))
    return jsonify(
        {
            "matched": evaluation.matched,
            "event_ids": list(evaluation.event_ids),
            "trace": evaluation.trace,
            "evaluation_ms": round((time.perf_counter() - started) * 1000, 3),
            "persisted_alert": False,
        }
    )


@detection_api.get("/api/rules/<int:rule_id>/versions")
@require_permission("rules.read")
def rule_versions(rule_id: int):
    rule = get_db().execute("SELECT id FROM rules WHERE id = ? AND workspace_id = ?", (rule_id, workspace_id())).fetchone()
    if not rule:
        return error_response("RULE_NOT_FOUND", "القاعدة غير موجودة", 404)
    rows = (
        get_db()
        .execute("SELECT id, version, change_summary, created_by, created_at FROM rule_versions WHERE rule_id = ? ORDER BY version DESC", (rule_id,))
        .fetchall()
    )
    return jsonify({"items": [dict(row) for row in rows]})


@detection_api.post("/api/rules/<int:rule_id>/rollback")
@require_permission("rules.manage")
def rollback_rule(rule_id: int):
    data = request.get_json(silent=True)
    target = data.get("version") if isinstance(data, dict) else None
    if not isinstance(target, int):
        return error_response("VERSION_REQUIRED", "حدد رقم الإصدار", 422)
    rule = get_db().execute("SELECT * FROM rules WHERE id = ? AND workspace_id = ?", (rule_id, workspace_id())).fetchone()
    version = get_db().execute("SELECT * FROM rule_versions WHERE rule_id = ? AND version = ?", (rule_id, target)).fetchone()
    if not rule or not version:
        return error_response("RULE_VERSION_NOT_FOUND", "إصدار القاعدة غير موجود", 404)
    next_version = int(rule["version"]) + 1
    now = iso_now()
    with transaction():
        get_db().execute(
            "UPDATE rules SET dsl_json = ?, condition_value = ?, action_value = ?, version = ?, updated_at = ? WHERE id = ?",
            (version["dsl_json"], version["dsl_json"], version["action_json"], next_version, now, rule_id),
        )
        get_db().execute(
            "INSERT INTO rule_versions (rule_id, version, dsl_json, action_json, change_summary, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (rule_id, next_version, version["dsl_json"], version["action_json"], f"Rollback to version {target}", actor_id(), now),
        )
        record_audit(get_db(), "rollback", "rule", rule_id, details={"from": rule["version"], "target": target, "new_version": next_version})
    return jsonify({"id": rule_id, "version": next_version, "rolled_back_to": target})


@detection_api.get("/api/alerts")
@require_permission("alerts.read")
def list_alerts():
    status = request.args.get("status")
    severity = request.args.get("severity")
    try:
        page = max(int(request.args.get("page", 1)), 1)
        page_size = min(max(int(request.args.get("page_size", 50)), 1), 100)
    except ValueError:
        return error_response("INVALID_PAGINATION", "قيم الترقيم غير صالحة", 400)
    clauses = ["a.workspace_id = ?"]
    params: list[object] = [workspace_id()]
    scope, scope_parameters = training_scope_sql("a.training_run_id")
    if scope:
        clauses.append(scope.removeprefix(" AND "))
        params.extend(scope_parameters)
    if status:
        clauses.append("a.status = ?")
        params.append(status)
    if severity:
        clauses.append("a.severity = ?")
        params.append(severity)
    where = " AND ".join(clauses)
    total = get_db().execute(f"SELECT COUNT(*) FROM alerts a WHERE {where}", params).fetchone()[0]
    rows = (
        get_db()
        .execute(
            f"""SELECT a.*, r.name AS rule_name, u.name AS assignee_name
        FROM alerts a JOIN rules r ON r.id = a.rule_id LEFT JOIN users u ON u.id = a.assignee
        WHERE {where} ORDER BY a.detected_at DESC LIMIT ? OFFSET ?""",
            (*params, page_size, (page - 1) * page_size),
        )
        .fetchall()
    )
    items = []
    for row in rows:
        item = dict(row)
        for field in ("evidence", "mitre_technique_ids", "trace"):
            item[field] = json.loads(item[field])
        items.append(item)
    return jsonify({"items": items, "total": total, "page": page, "page_size": page_size})


@detection_api.get("/api/alerts/<int:alert_id>")
@require_permission("alerts.read")
def alert_detail(alert_id: int):
    row = get_db().execute("SELECT * FROM alerts WHERE id = ? AND workspace_id = ?", (alert_id, workspace_id())).fetchone()
    if not row or not can_access_training_run(row["training_run_id"]):
        return error_response("ALERT_NOT_FOUND", "التنبيه غير موجود", 404)
    item = dict(row)
    for field in ("evidence", "mitre_technique_ids", "trace"):
        item[field] = json.loads(item[field])
    events = (
        get_db()
        .execute(
            "SELECT e.id, e.event_id, e.event_time, e.source, e.event_type, e.severity, e.title FROM alert_events ae JOIN security_events e ON e.id = ae.event_id WHERE ae.alert_id = ? ORDER BY e.event_time",
            (alert_id,),
        )
        .fetchall()
    )
    item["events"] = [dict(event) for event in events]
    return jsonify(item)


@detection_api.post("/api/alerts/<int:alert_id>/triage")
@require_permission("alerts.triage")
def triage_alert(alert_id: int):
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or data.get("status") not in {"triaged", "investigating", "closed", "false_positive", "suppressed"}:
        return error_response("INVALID_ALERT_STATUS", "حالة التنبيه غير صالحة", 422)
    row = get_db().execute("SELECT * FROM alerts WHERE id = ? AND workspace_id = ?", (alert_id, workspace_id())).fetchone()
    if not row or not can_access_training_run(row["training_run_id"]):
        return error_response("ALERT_NOT_FOUND", "التنبيه غير موجود", 404)
    reason = data.get("reason")
    if data["status"] in {"false_positive", "suppressed"} and (not isinstance(reason, str) or len(reason.strip()) < 5):
        return error_response("REASON_REQUIRED", "يلزم سبب واضح لهذا القرار", 422)
    assignee = data.get("assignee", row["assignee"])
    if assignee is not None and (
        not isinstance(assignee, int)
        or not get_db().execute("SELECT 1 FROM users WHERE id = ? AND workspace_id = ? AND is_active = 1", (assignee, workspace_id())).fetchone()
    ):
        return error_response("INVALID_ASSIGNEE", "المحلل المحدد غير متاح في مساحة العمل", 422)
    with transaction():
        get_db().execute(
            "UPDATE alerts SET status = ?, assignee = ?, false_positive_reason = ? WHERE id = ?",
            (data["status"], assignee, reason.strip() if isinstance(reason, str) else None, alert_id),
        )
        if data["status"] == "false_positive":
            get_db().execute("UPDATE rules SET false_positive_count = false_positive_count + 1 WHERE id = ?", (row["rule_id"],))
        record_audit(get_db(), "triage", "alert", alert_id, details={"status": data["status"], "reason": reason or ""})
        record_training_action(
            get_db(),
            row["training_run_id"],
            actor_id(),
            "alert_triage",
            "alert",
            alert_id,
            {"status": data["status"]},
            f"alert-triage:{alert_id}:{data['status']}",
        )
    return jsonify({"id": alert_id, "status": data["status"], "assignee": assignee})
