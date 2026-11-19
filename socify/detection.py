import hashlib
import ipaddress
import json
import math
import sqlite3
import time
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from .db import inserted_id
from .schema import public_id
from .security import parse_json_object
from .timeutils import iso_now, parse_timestamp

FIELDS = {
    "source_type",
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
    "description",
    "command_line",
    "mitre_ids",
    "exposed_secret_count",
    "sensitive_data_count",
    "decoded_threat_count",
    "ids_severity",
    "ids_signature",
    "query_name",
    "query_action",
    "runtime_rule",
    "runtime_source",
    "container_id",
    "container_name",
    "kubernetes_namespace",
    "kubernetes_pod",
    "kubernetes_node",
    "destination_port",
    "protocol",
    "auth_target",
    "event_time_known",
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
        WHERE workspace_id = ? AND owner_case_id IS ? AND autopsy_active = 1 AND source != 'rules_engine' AND event_time >= ? AND event_time <= ?
        ORDER BY event_time, id LIMIT 20000""",
        (
            event["workspace_id"],
            event.get("owner_case_id"),
            start.isoformat().replace("+00:00", "Z"),
            end.isoformat().replace("+00:00", "Z"),
        ),
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
        "SELECT MAX(event_time) FROM security_events WHERE workspace_id = ? AND owner_case_id IS ? AND autopsy_active = 1 AND source != 'rules_engine'",
        (event["workspace_id"], event.get("owner_case_id")),
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
        for candidate, _ in matching:
            if candidate["id"] == event["id"]:
                break
            if position == len(sequence) - 1:
                continue
            matched, _ = _condition_matches(sequence[position], candidate)
            if matched:
                ordered_ids.append(int(candidate["id"]))
                position += 1
        matched = position == len(sequence) - 1
        if matched:
            ordered_ids.append(int(event["id"]))
            position += 1
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
        return f"{rule_name}: {evaluation.trace.get('matched_steps')} ordered events within {evaluation.trace.get('window_seconds')} seconds"
    return f"{rule_name}: event matched the published rule"


def evaluate_rules(connection: sqlite3.Connection, event_id: int, only_rule_id: int | None = None) -> list[int]:
    """Evaluate the team's active rules (seeding the built-in ones when absent) against one stored event and return the ids of alerts it raised."""
    row = connection.execute("SELECT * FROM security_events WHERE id = ?", (event_id,)).fetchone()
    if not row or row["source"] == "rules_engine" or not row["autopsy_active"]:
        return []
    event = _event_dict(row)
    rules = connection.execute(
        "SELECT * FROM rules WHERE workspace_id = ? AND is_active = 1 AND archived_at IS NULL ORDER BY id LIMIT 500",
        (event["workspace_id"],),
    ).fetchall()
    if not any(str(r["name"]).startswith("[SOCify]") for r in rules):
        from .builtin_rules import seed_builtin_rules

        if seed_builtin_rules(connection):
            rules = connection.execute(
                "SELECT * FROM rules WHERE workspace_id = ? AND is_active = 1 AND archived_at IS NULL ORDER BY id LIMIT 500",
                (event["workspace_id"],),
            ).fetchall()
    alert_ids: list[int] = []
    for rule in rules:
        if only_rule_id is not None and rule["id"] != only_rule_id:
            continue
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
            # The trailing separator is part of the key format; dropping it would re-raise alerts that already exist.
            material = f"{rule['id']}|{rule['version']}|{evaluation.group_key}|{','.join(str(item) for item in evaluation.event_ids)}|"
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
                (alert_id, workspace_id, rule_id, rule_version, reason, evidence, severity,
                confidence, detected_at, status, mitre_technique_ids, dedup_key, trace)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'untriaged', ?, ?, ?)""",
                (
                    alert_public_id,
                    event["workspace_id"],
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
            if event.get("owner_case_id") is not None:
                connection.execute("UPDATE alerts SET owner_case_id = ? WHERE id = ?", (event["owner_case_id"], alert_id))
            for matched_event_id in evaluation.event_ids:
                connection.execute("INSERT OR IGNORE INTO alert_events (alert_id, event_id) VALUES (?, ?)", (alert_id, matched_event_id))
            compatibility_event_id = public_id("DET")
            compatibility_cursor = connection.execute(
                """INSERT INTO security_events
                (event_id, external_id, idempotency_key, workspace_id, source, source_type, severity,
                category, event_type, title, description, event_time, ingested_at, timestamp, raw_data, normalized_fields,
                tags, mitre_ids, status, created_by, parser_version, raw_hash, provenance)
                VALUES (?, ?, ?, ?, 'rules_engine', 'internal', ?, 'detection', 'alert', ?, ?, ?, ?, ?, ?, '{}', '[]', ?, 'open', ?, 'socify-detection-2', ?, ?)""",
                (
                    compatibility_event_id,
                    alert_public_id,
                    f"alert:{dedup_key}",
                    event["workspace_id"],
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
            if event.get("owner_case_id") is not None:
                connection.execute("UPDATE security_events SET owner_case_id = ? WHERE id = ?", (event["owner_case_id"], inserted_id(compatibility_cursor)))
            connection.execute(
                """INSERT OR IGNORE INTO detection_matches
                (rule_id, event_id, alert_event_id, alert_id, dedup_key, trace, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (rule["id"], event_id, inserted_id(compatibility_cursor), alert_id, dedup_key, json.dumps(evaluation.trace, separators=(",", ":")), now),
            )
            connection.execute("UPDATE rules SET match_count = match_count + 1, last_triggered_at = ? WHERE id = ?", (now, rule["id"]))
            alert_ids.append(alert_id)
        except (RuleValidationError, ValueError, TypeError, json.JSONDecodeError):
            connection.execute("UPDATE rules SET failed_evaluations = failed_evaluations + 1 WHERE id = ?", (rule["id"],))
    return alert_ids
