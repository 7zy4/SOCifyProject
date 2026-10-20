import ipaddress
import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from flask import Blueprint, jsonify, request

from .audit import record_audit
from .db import get_db, inserted_id, transaction
from .events import _event_view
from .security import actor_id, current_user, error_response, has_permission, require_permission, workspace_id
from .timeutils import iso_now

hunting_api = Blueprint("hunting", __name__)

FIELD_MAP = {
    "event_id": "e.event_id",
    "source": "e.source",
    "severity": "e.severity",
    "event_type": "e.event_type",
    "category": "e.category",
    "source_ip": "e.source_ip",
    "destination_ip": "e.destination_ip",
    "username": "e.username",
    "hostname": "e.hostname",
    "process": "e.process_name",
    "file_hash": "e.file_hash",
    "http_status": "e.http_status",
    "action": "e.action",
    "outcome": "e.outcome",
    "training_run_id": "e.training_run_id",
    "mitre_id": "e.mitre_ids",
    "event_time": "e.event_time",
}
TOKEN_PATTERN = re.compile(r'\s*(>=|<=|!=|=|>|<|~|\(|\)|"(?:[^"\\]|\\.)*"|\bAND\b|\bOR\b|\bNOT\b|[A-Za-z_][A-Za-z0-9_]*|[0-9A-Fa-f:.@/_-]+)\s*', re.IGNORECASE)

OFFLINE_INTELLIGENCE = {
    ("ip", "198.51.100.20"): {"verdict": "suspicious", "confidence": 0.92, "reason": "Synthetic credential attack source in the SOCify reference scenario"},
    ("ip", "203.0.113.50"): {"verdict": "suspicious", "confidence": 0.88, "reason": "Synthetic exfiltration destination in the SOCify reference scenario"},
    ("domain", "phish-training.test"): {"verdict": "malicious-training", "confidence": 1.0, "reason": "Reserved synthetic phishing domain"},
    ("domain", "malware-training.test"): {"verdict": "malicious-training", "confidence": 1.0, "reason": "Reserved synthetic malware domain"},
}


class QueryError(ValueError):
    __slots__ = ()


@dataclass
class CompiledQuery:
    sql: str
    parameters: list[object]
    token_count: int


def _tokens(query: str) -> list[str]:
    if len(query) > 2000:
        raise QueryError("query exceeds 2000 characters")
    tokens: list[str] = []
    position = 0
    while position < len(query):
        match = TOKEN_PATTERN.match(query, position)
        if not match:
            raise QueryError(f"invalid token at position {position}")
        tokens.append(match.group(1))
        position = match.end()
    if len(tokens) > 100:
        raise QueryError("query exceeds the 100-token budget")
    return tokens


class Parser:
    def __init__(self, tokens: list[str]):
        self.tokens = tokens
        self.position = 0
        self.parameters: list[object] = []
        self.depth = 0

    def peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def take(self) -> str:
        token = self.peek()
        if token is None:
            raise QueryError("unexpected end of query")
        self.position += 1
        return token

    def parse(self) -> str:
        if not self.tokens:
            return "1 = 1"
        result = self.expression()
        if self.peek() is not None:
            raise QueryError(f"unexpected token {self.peek()}")
        return result

    def expression(self) -> str:
        value = self.term()
        while (self.peek() or "").upper() == "OR":
            self.take()
            value = f"({value} OR {self.term()})"
        return value

    def term(self) -> str:
        value = self.factor()
        while (self.peek() or "").upper() == "AND":
            self.take()
            value = f"({value} AND {self.factor()})"
        return value

    def factor(self) -> str:
        lexical_item = self.peek()
        if lexical_item is None:
            raise QueryError("condition expected")
        if lexical_item.upper() == "NOT":
            self.take()
            return f"(NOT {self.factor()})"
        if lexical_item == "(":
            self.take()
            self.depth += 1
            if self.depth > 5:
                raise QueryError("query nesting exceeds five levels")
            value = self.expression()
            if self.take() != ")":
                raise QueryError("closing parenthesis expected")
            self.depth -= 1
            return f"({value})"
        return self.comparison()

    def comparison(self) -> str:
        field = self.take()
        if field not in FIELD_MAP:
            raise QueryError(f"unsupported field {field}")
        operator = self.take()
        if operator not in {"=", "!=", ">", ">=", "<", "<=", "~"}:
            raise QueryError(f"unsupported operator {operator}")
        raw = self.take()
        if raw in {"(", ")"} or raw.upper() in {"AND", "OR", "NOT"}:
            raise QueryError("comparison value expected")
        if raw.startswith('"'):
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise QueryError("invalid quoted value") from exc
        else:
            value = raw
        column = FIELD_MAP[field]
        if field == "http_status" or field == "training_run_id":
            try:
                value = int(value)
            except ValueError as exc:
                raise QueryError(f"{field} requires an integer") from exc
        if field == "mitre_id":
            if operator not in {"=", "~"}:
                raise QueryError("mitre_id supports = or ~")
            self.parameters.append(f'%"{str(value).replace("%", "").replace("_", "")}"%')
            return f"{column} LIKE ? ESCAPE '\\'"
        if operator == "~":
            text = str(value).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            self.parameters.append(f"%{text}%")
            return f"{column} LIKE ? ESCAPE '\\'"
        self.parameters.append(value)
        return f"{column} {operator} ?"


def compile_query(query: str) -> CompiledQuery:
    tokens = _tokens(query)
    parser = Parser(tokens)
    return CompiledQuery(parser.parse(), parser.parameters, len(tokens))


def _run_scope() -> tuple[str, list[object]]:
    user = current_user()
    if has_permission(user, "scores.read_team") or has_permission(user, "training.manage"):
        return "", []
    return " AND (e.training_run_id IS NULL OR e.training_run_id IN (SELECT id FROM training_runs WHERE user_id = ? AND workspace_id = ?))", [actor_id(), workspace_id()]


@hunting_api.post("/api/hunt/query")
@require_permission("hunt.execute")
def execute_query():
    data = request.get_json(silent=True)
    payload = data if isinstance(data, dict) else {}
    query = payload.get("query", "")
    if not isinstance(query, str):
        return error_response("INVALID_QUERY", "الاستعلام يجب أن يكون نصًا", 422)
    try:
        compiled = compile_query(query)
    except QueryError as exc:
        return error_response("INVALID_HUNT_QUERY", str(exc), 422)
    try:
        page = max(int(payload.get("page", 1)), 1)
        page_size = min(max(int(payload.get("page_size", 50)), 1), 100)
    except (TypeError, ValueError):
        return error_response("INVALID_PAGINATION", "قيم الترقيم غير صالحة", 422)
    scope, scope_parameters = _run_scope()
    base_parameters: list[object] = [workspace_id(), *compiled.parameters, *scope_parameters]
    where = f"e.workspace_id = ? AND ({compiled.sql}){scope}"
    total = int(get_db().execute(f"SELECT COUNT(*) FROM security_events e WHERE {where}", base_parameters).fetchone()[0])
    rows = get_db().execute(f"SELECT e.* FROM security_events e WHERE {where} ORDER BY e.event_time DESC, e.id DESC LIMIT ? OFFSET ?", (*base_parameters, page_size, (page - 1) * page_size)).fetchall()
    aggregation = get_db().execute(f"SELECT e.source, COUNT(*) AS count FROM security_events e WHERE {where} GROUP BY e.source ORDER BY count DESC LIMIT 20", base_parameters).fetchall()
    record_audit(get_db(), "execute", "hunt_query", None, details={"tokens": compiled.token_count, "results": total})
    return jsonify({"items": [_event_view(row) for row in rows], "total": total, "page": page, "page_size": page_size, "aggregation": [dict(row) for row in aggregation], "query_plan": {"parameterized": True, "tokens": compiled.token_count}})


@hunting_api.get("/api/hunt/saved-queries")
@require_permission("hunt.save")
def list_saved_queries():
    rows = get_db().execute("SELECT * FROM saved_hunt_queries WHERE workspace_id = ? AND (owner_id = ? OR visibility = 'workspace') ORDER BY updated_at DESC", (workspace_id(), actor_id())).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["tags"] = json.loads(item["tags"])
        items.append(item)
    return jsonify({"items": items})


@hunting_api.post("/api/hunt/saved-queries")
@require_permission("hunt.save")
def save_query():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("name"), str) or not 2 <= len(data["name"].strip()) <= 150 or not isinstance(data.get("query"), str):
        return error_response("INVALID_SAVED_QUERY", "اسم الاستعلام ونصه مطلوبان", 422)
    visibility = data.get("visibility", "private")
    if visibility not in {"private", "workspace"} or visibility == "workspace" and not has_permission(current_user(), "hunt.share"):
        return error_response("INVALID_QUERY_VISIBILITY", "لا تملك صلاحية مشاركة الاستعلام", 403)
    try:
        compile_query(data["query"])
    except QueryError as exc:
        return error_response("INVALID_HUNT_QUERY", str(exc), 422)
    tags = data.get("tags", [])
    if not isinstance(tags, list) or len(tags) > 20 or any(not isinstance(item, str) or len(item) > 80 for item in tags):
        return error_response("INVALID_TAGS", "الوسوم غير صالحة", 422)
    now = iso_now()
    cursor = get_db().execute("INSERT INTO saved_hunt_queries (workspace_id, owner_id, name, description, query, visibility, tags, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (workspace_id(), actor_id(), data["name"].strip(), str(data.get("description") or "")[:1000], data["query"], visibility, json.dumps(tags, ensure_ascii=False), now, now))
    query_id = inserted_id(cursor)
    record_audit(get_db(), "create", "saved_hunt_query", query_id, details={"visibility": visibility})
    return jsonify({"id": query_id, "name": data["name"].strip(), "query": data["query"], "visibility": visibility}), 201


@hunting_api.delete("/api/hunt/saved-queries/<int:query_id>")
@require_permission("hunt.save")
def delete_saved_query(query_id: int):
    row = get_db().execute("SELECT id FROM saved_hunt_queries WHERE id = ? AND workspace_id = ? AND owner_id = ?", (query_id, workspace_id(), actor_id())).fetchone()
    if not row:
        return error_response("SAVED_QUERY_NOT_FOUND", "الاستعلام المحفوظ غير موجود", 404)
    get_db().execute("DELETE FROM saved_hunt_queries WHERE id = ?", (query_id,))
    record_audit(get_db(), "delete", "saved_hunt_query", query_id)
    return "", 204


def _ioc_type(value: str) -> tuple[str, str] | None:
    candidate = value.strip().lower().strip("'\"[](),;")
    try:
        return "ip", str(ipaddress.ip_address(candidate))
    except ValueError:
        ip_candidate = None
    if ip_candidate is not None:
        return ip_candidate
    if re.fullmatch(r"[a-f0-9]{64}", candidate):
        return "sha256", candidate
    if re.fullmatch(r"[a-f0-9]{40}", candidate):
        return "sha1", candidate
    if re.fullmatch(r"[a-f0-9]{32}", candidate):
        return "md5", candidate
    parsed = urlparse(candidate)
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        return "url", candidate
    if re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", candidate):
        return "domain", candidate.rstrip(".")
    return None


def _upsert_ioc(value_type: str, value: str, context: dict[str, Any]) -> int:
    now = iso_now()
    existing = get_db().execute("SELECT id FROM ioc_indicators WHERE workspace_id = ? AND type = ? AND value = ?", (workspace_id(), value_type, value)).fetchone()
    if existing:
        identifier = int(existing["id"])
    else:
        cursor = get_db().execute("INSERT INTO ioc_indicators (workspace_id, type, value, first_seen, last_seen, confidence, source, context, tags) VALUES (?, ?, ?, ?, ?, 0.5, 'SOCify extraction', '{}', '[\"training\"]')", (workspace_id(), value_type, value, now, now))
        identifier = inserted_id(cursor)
    get_db().execute("INSERT OR IGNORE INTO ioc_observations (ioc_id, event_id, context, tags, created_at) VALUES (?, ?, ?, '[\"training\"]', ?)", (identifier, context["event_id"], json.dumps(context, ensure_ascii=False), now))
    return identifier


def _ioc_view(row: sqlite3.Row) -> dict[str, Any] | None:
    scope, parameters = _run_scope()
    observations = get_db().execute(f"SELECT o.* FROM ioc_observations o JOIN security_events e ON e.id = o.event_id WHERE o.ioc_id = ? AND e.workspace_id = ?{scope} ORDER BY o.created_at, o.event_id", (row["id"], workspace_id(), *parameters)).fetchall()
    item = dict(row)
    if observations:
        item["first_seen"] = observations[0]["created_at"]
        item["last_seen"] = observations[-1]["created_at"]
        item["context"] = json.loads(observations[-1]["context"])
        item["tags"] = sorted({tag for observation in observations for tag in json.loads(observation["tags"])})
    elif row["source"] == "SOCify synthetic fixtures":
        item["context"] = json.loads(row["context"])
        item["tags"] = json.loads(row["tags"])
    else:
        return None
    return item


@hunting_api.post("/api/iocs/extract")
@require_permission("hunt.execute")
def extract_iocs():
    data = request.get_json(silent=True)
    event_id = data.get("event_id") if isinstance(data, dict) else None
    if not isinstance(event_id, int):
        return error_response("EVENT_ID_REQUIRED", "حدد السجل المطلوب", 422)
    scope, scope_parameters = _run_scope()
    event = get_db().execute(f"SELECT e.* FROM security_events e WHERE e.id = ? AND e.workspace_id = ?{scope}", (event_id, workspace_id(), *scope_parameters)).fetchone()
    if not event:
        return error_response("EVENT_NOT_FOUND", "السجل غير موجود", 404)
    candidates = [event["source_ip"], event["destination_ip"], event["file_hash"]]
    raw = str(event["raw_data"] or "")
    candidates.extend(re.findall(r"(?:https?://[^\s\"'<>]+|\b(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b)", raw))
    found: dict[tuple[str, str], int] = {}
    with transaction():
        for candidate in candidates:
            if not isinstance(candidate, str):
                continue
            parsed = _ioc_type(candidate)
            if parsed and parsed not in found:
                found[parsed] = _upsert_ioc(parsed[0], parsed[1], {"event_id": event_id, "training": True})
        record_audit(get_db(), "extract", "ioc", None, details={"event_id": event_id, "count": len(found)})
    return jsonify({"items": [{"id": identifier, "type": key[0], "value": key[1]} for key, identifier in found.items()]})


@hunting_api.get("/api/iocs")
@require_permission("hunt.execute")
def list_iocs():
    rows = get_db().execute("SELECT * FROM ioc_indicators WHERE workspace_id = ? ORDER BY last_seen DESC LIMIT 500", (workspace_id(),)).fetchall()
    items = []
    for row in rows:
        item = _ioc_view(row)
        if item is not None:
            items.append(item)
    items.sort(key=lambda item: item["last_seen"], reverse=True)
    return jsonify({"items": items})


@hunting_api.post("/api/iocs/<int:ioc_id>/enrich")
@require_permission("hunt.execute")
def enrich_ioc(ioc_id: int):
    row = get_db().execute("SELECT * FROM ioc_indicators WHERE id = ? AND workspace_id = ?", (ioc_id, workspace_id())).fetchone()
    if not row or _ioc_view(row) is None:
        return error_response("IOC_NOT_FOUND", "المؤشر غير موجود", 404)
    provider = request.args.get("provider", "offline")
    now = iso_now()
    if provider != "offline":
        provider_result = {"provider": provider, "status": "not_configured", "message": "لم يتم تفعيل موفر خارجي ولم تُرسل أي بيانات"}
        cursor = get_db().execute("INSERT INTO ioc_enrichment_results (ioc_id, provider, status, result, created_at) VALUES (?, ?, 'not_configured', ?, ?)", (ioc_id, provider, json.dumps(provider_result, ensure_ascii=False), now))
        return jsonify({"id": inserted_id(cursor), **provider_result})
    intelligence = OFFLINE_INTELLIGENCE.get((row["type"], row["value"]), {"verdict": "unknown", "confidence": 0.2, "reason": "No match in the versioned synthetic offline dataset"})
    result: dict[str, Any] = {"provider": "socify-offline-training-v1", "status": "successful", "training_synthetic": True, **intelligence, "attribution": "SOCify synthetic fixtures"}
    cursor = get_db().execute("INSERT INTO ioc_enrichment_results (ioc_id, provider, status, result, confidence, expires_at, created_at) VALUES (?, 'socify-offline-training-v1', 'successful', ?, ?, ?, ?)", (ioc_id, json.dumps(result, ensure_ascii=False), intelligence["confidence"], "9999-12-31T23:59:59Z", now))
    record_audit(get_db(), "enrich", "ioc", ioc_id, details={"provider": "offline", "verdict": intelligence["verdict"]})
    return jsonify({"id": inserted_id(cursor), **result})
