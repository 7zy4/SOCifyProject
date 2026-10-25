import json
import sqlite3
import time
from collections import OrderedDict
from collections.abc import Iterator
from typing import Any

from flask import Blueprint, Response, g, jsonify, request, stream_with_context

from .db import get_db
from .security import actor_id, can_access_training_run, current_user, error_response, has_permission, require_permission, workspace_id
from .timeutils import iso_timestamp

visualization_api = Blueprint("visualization", __name__)


def _outbox_visible(row: sqlite3.Row) -> bool:
    event_type = str(row["event_type"])
    try:
        payload = json.loads(row["payload"])
    except (TypeError, json.JSONDecodeError):
        return False
    identifier = payload.get("id", payload.get("resource_id")) if isinstance(payload, dict) else None
    if event_type == "training.notification" and isinstance(payload, dict):
        identifier = payload.get("playbook_run_id")
    if event_type.startswith("playbook_run.") or event_type == "training.notification":
        from .playbooks import _run_access

        return type(identifier) is int and _run_access(identifier) is not None
    if not isinstance(identifier, int):
        return has_permission(current_user(), "audit.read")
    table = None
    if event_type.startswith("event."):
        table = "security_events"
    elif event_type.startswith("alert."):
        table = "alerts"
    elif event_type.startswith(("incident.", "case.")):
        table = "incident_cases"
    elif event_type.startswith("training_run."):
        return can_access_training_run(identifier)
    if table:
        record = get_db().execute(f"SELECT training_run_id FROM {table} WHERE id = ? AND workspace_id = ?", (identifier, workspace_id())).fetchone()
        return bool(record and can_access_training_run(record["training_run_id"]))
    return has_permission(current_user(), "audit.read")


def _scope() -> tuple[str, list[object]]:
    user = current_user()
    if has_permission(user, "scores.read_team") or has_permission(user, "training.manage"):
        return "", []
    return " AND (e.training_run_id IS NULL OR e.training_run_id IN (SELECT id FROM training_runs WHERE workspace_id = ? AND user_id = ?))", [
        workspace_id(),
        actor_id(),
    ]


def _filters(alias: str = "e", fixed_case_id: int | None = None) -> tuple[str, list[object]]:
    clauses = [f"{alias}.workspace_id = ?"]
    parameters: list[object] = [workspace_id()]
    from .operational import operational_mode

    if operational_mode():
        from .autopsy_pipeline import active_event_sql, visibility_sql

        scope, arguments = visibility_sql(alias)
        clauses.extend([active_event_sql(alias), scope])
        parameters.extend(arguments)
    if request.args.get("include_derived") != "1":
        clauses.append(f"{alias}.source != 'rules_engine'")
    case_id = fixed_case_id if fixed_case_id is not None else request.args.get("case_id")
    if case_id:
        from .cases import _case_row

        try:
            case_value = int(case_id)
        except ValueError as exc:
            raise ValueError("case_id must be an integer") from exc
        if _case_row(case_value) is None:
            clauses.append("1 = 0")
        else:
            clauses.append(f"{alias}.id IN (SELECT event_id FROM case_events WHERE case_id = ?)")
            parameters.append(case_value)
    severity = request.args.get("severity")
    if severity:
        if severity not in {"low", "medium", "high", "critical"}:
            raise ValueError("invalid severity")
        clauses.append(f"{alias}.severity = ?")
        parameters.append(severity)
    training_run_id = request.args.get("training_run_id")
    if training_run_id:
        try:
            value = int(training_run_id)
        except ValueError as exc:
            raise ValueError("training_run_id must be an integer") from exc
        clauses.append(f"{alias}.training_run_id = ?")
        parameters.append(value)
    start = request.args.get("start")
    end = request.args.get("end")
    if start:
        clauses.append(f"{alias}.event_time >= ?")
        parameters.append(iso_timestamp(start))
    if end:
        clauses.append(f"{alias}.event_time <= ?")
        parameters.append(iso_timestamp(end))
    return " AND ".join(clauses), parameters


def _node(
    node_id: str, node_type: str, label: object, timestamp: object, source: object, reference_id: object, confidence: float = 1.0, provenance: str = "observed"
) -> dict[str, Any]:
    return {
        "id": node_id,
        "type": node_type,
        "label": str(label)[:255],
        "timestamp": timestamp,
        "source": source,
        "reference_id": reference_id,
        "confidence": confidence,
        "provenance": provenance,
    }


def _edge(
    edge_id: str, source: str, target: str, relation: str, timestamp: object, reference_id: object, confidence: float = 1.0, provenance: str = "observed"
) -> dict[str, Any]:
    return {
        "id": edge_id,
        "source": source,
        "target": target,
        "type": relation,
        "timestamp": timestamp,
        "reference_id": reference_id,
        "confidence": confidence,
        "provenance": provenance,
    }


def build_graph(limit: int, case_id: int | None = None) -> dict[str, Any]:
    where, parameters = _filters(fixed_case_id=case_id)
    scope, scope_parameters = _scope()
    rows = (
        get_db()
        .execute(
            f"SELECT e.* FROM security_events e WHERE {where}{scope} ORDER BY e.event_time DESC, e.id DESC LIMIT ?", (*parameters, *scope_parameters, limit)
        )
        .fetchall()
    )
    nodes: OrderedDict[str, dict[str, Any]] = OrderedDict()
    edges: OrderedDict[str, dict[str, Any]] = OrderedDict()
    for event in rows:
        event_node = f"event:{event['id']}"
        nodes[event_node] = _node(event_node, "Event", event["title"], event["event_time"], event["source"], event["id"])
        if case_id is not None:
            known = json.loads(event["normalized_fields"] or "{}").get("event_time_known") is True
            nodes[event_node]["observed_time_known"] = known
            nodes[event_node]["time_basis"] = json.loads(event["provenance"] or "{}").get("event_time_basis", "legacy_timestamp_not_verified")
            if not known:
                nodes[event_node]["timestamp"] = None
        relationships = [
            ("source_ip", "IP", event["source_ip"], "observed_on"),
            ("destination_ip", "IP", event["destination_ip"], "communicated_with"),
            ("username", "User", event["username"], "related_to"),
            ("hostname", "Host", event["hostname"], "observed_on"),
            ("process_name", "Process", event["process_name"], "executed"),
            ("file_hash", "FileHash", event["file_hash"], "related_to"),
        ]
        for field, node_type, value, relation in relationships:
            if not value:
                continue
            entity = f"{node_type.lower()}:{value}"
            nodes.setdefault(entity, _node(entity, node_type, value, event["event_time"], event["source"], value))
            identifier = f"edge:{event['id']}:{field}"
            edges[identifier] = _edge(identifier, event_node, entity, relation, event["event_time"], event["id"])
        for technique_id in json.loads(event["mitre_ids"] or "[]"):
            technique = get_db().execute("SELECT name, attack_version FROM attack_techniques WHERE technique_id = ?", (technique_id,)).fetchone()
            entity = f"technique:{technique_id}"
            nodes.setdefault(
                entity,
                _node(
                    entity,
                    "Technique",
                    f"{technique_id} {technique['name'] if technique else ''}".strip(),
                    event["event_time"],
                    f"MITRE ATT&CK {technique['attack_version'] if technique else 'unknown'}",
                    technique_id,
                    1.0,
                    "mapped",
                ),
            )
            identifier = f"edge:{event['id']}:technique:{technique_id}"
            edges[identifier] = _edge(identifier, event_node, entity, "related_to", event["event_time"], event["id"], 0.9, "mapped")
    if rows:
        event_ids = [int(row["id"]) for row in rows]
        placeholders = ",".join("?" for _ in event_ids)
        alerts = (
            get_db()
            .execute(
                f"SELECT DISTINCT a.* FROM alerts a JOIN alert_events ae ON ae.alert_id = a.id WHERE ae.event_id IN ({placeholders}) AND a.workspace_id = ?",
                (*event_ids, workspace_id()),
            )
            .fetchall()
        )
        for alert in alerts:
            if case_id is not None and not get_db().execute("SELECT 1 FROM case_alerts WHERE case_id = ? AND alert_id = ?", (case_id, alert["id"])).fetchone():
                continue
            if not can_access_training_run(alert["training_run_id"]):
                continue
            alert_node = f"alert:{alert['id']}"
            nodes[alert_node] = _node(alert_node, "Alert", alert["reason"], alert["detected_at"], "rules_engine", alert["id"], alert["confidence"], "derived")
            for event in get_db().execute("SELECT event_id FROM alert_events WHERE alert_id = ?", (alert["id"],)).fetchall():
                if f"event:{event['event_id']}" in nodes:
                    identifier = f"edge:alert:{alert['id']}:event:{event['event_id']}"
                    edges[identifier] = _edge(
                        identifier,
                        f"event:{event['event_id']}",
                        alert_node,
                        "triggered_rule",
                        alert["detected_at"],
                        alert["id"],
                        alert["confidence"],
                        "derived",
                    )
        cases = (
            get_db()
            .execute(
                f"SELECT DISTINCT c.* FROM incident_cases c JOIN case_events ce ON ce.case_id = c.id WHERE ce.event_id IN ({placeholders}) AND c.workspace_id = ?",
                (*event_ids, workspace_id()),
            )
            .fetchall()
        )
        for case in cases:
            if case_id is not None and case["id"] != case_id:
                continue
            if not can_access_training_run(case["training_run_id"]):
                continue
            case_node = f"incident:{case['id']}"
            nodes[case_node] = _node(case_node, "Incident", f"{case['reference']} {case['title']}", case["created_at"], "case_management", case["id"])
            for event in get_db().execute("SELECT event_id FROM case_events WHERE case_id = ?", (case["id"],)).fetchall():
                if f"event:{event['event_id']}" in nodes:
                    identifier = f"edge:case:{case['id']}:event:{event['event_id']}"
                    edges[identifier] = _edge(identifier, f"event:{event['event_id']}", case_node, "attached_to_case", case["created_at"], case["id"])
    return {
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "event_count": len(rows),
        "truncated": len(rows) >= limit,
        "limit": limit,
        "accuracy_policy": "Observed relationships reference source events; mapped and derived relationships declare provenance and confidence.",
    }


@visualization_api.get("/api/visualizations/graph")
@require_permission("graph.read")
def graph():
    try:
        limit = min(max(int(request.args.get("limit", 500)), 1), 1000)
        result = build_graph(limit)
    except ValueError as exc:
        return error_response("INVALID_GRAPH_FILTER", str(exc), 422)
    return jsonify(result)


@visualization_api.get("/api/visualizations/timeline")
@require_permission("graph.read")
def timeline():
    try:
        limit = min(max(int(request.args.get("limit", 500)), 1), 1000)
        where, parameters = _filters()
    except ValueError as exc:
        return error_response("INVALID_TIMELINE_FILTER", str(exc), 422)
    scope, scope_parameters = _scope()
    rows = (
        get_db()
        .execute(
            f"SELECT e.id, e.event_id, e.event_time, e.source, e.severity, e.event_type, e.title, e.mitre_ids FROM security_events e WHERE {where}{scope} ORDER BY e.event_time, e.id LIMIT ?",
            (*parameters, *scope_parameters, limit),
        )
        .fetchall()
    )
    items = [{**dict(row), "mitre_ids": json.loads(row["mitre_ids"] or "[]"), "reference": f"/api/events/{row['id']}"} for row in rows]
    return jsonify({"items": items, "truncated": len(rows) >= limit, "limit": limit})


@visualization_api.get("/api/visualizations/graph/export")
@require_permission("graph.read")
def export_graph():
    try:
        result = build_graph(min(max(int(request.args.get("limit", 500)), 1), 1000))
    except ValueError as exc:
        return error_response("INVALID_GRAPH_FILTER", str(exc), 422)
    return Response(
        json.dumps(result, ensure_ascii=False, separators=(",", ":")),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=socify-attack-graph.json"},
    )


@visualization_api.get("/api/stream/events")
@require_permission("events.read")
def event_stream():
    try:
        cursor = max(int(request.headers.get("Last-Event-ID", request.args.get("cursor", 0))), 0)
    except ValueError:
        return error_response("INVALID_STREAM_CURSOR", "معرف الاستئناف غير صالح", 422)
    once = request.args.get("once") == "1"
    workspace = workspace_id()

    def generate() -> Iterator[str]:
        nonlocal cursor
        last_heartbeat = time.monotonic()
        while True:
            g.pop("current_user", None)
            user = current_user()
            if not has_permission(user, "events.read") or not user or user["workspace_id"] != workspace:
                break
            rows = (
                get_db()
                .execute(
                    "SELECT id, event_type, payload, created_at FROM outbox_events WHERE workspace_id = ? AND id > ? ORDER BY id LIMIT 100", (workspace, cursor)
                )
                .fetchall()
            )
            for row in rows:
                cursor = int(row["id"])
                if not _outbox_visible(row):
                    continue
                yield f"id: {cursor}\nevent: {row['event_type']}\ndata: {row['payload']}\n\n"
            if once:
                yield f'event: heartbeat\ndata: {{"cursor":{cursor}}}\n\n'
                break
            if time.monotonic() - last_heartbeat >= 15:
                yield f'event: heartbeat\ndata: {{"cursor":{cursor}}}\n\n'
                last_heartbeat = time.monotonic()
            time.sleep(1)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )
