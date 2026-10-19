import json
import sqlite3
from typing import Any

from flask import Blueprint, current_app, jsonify, request

from .db import get_db
from .security import ROLE_PERMISSIONS, actor_id, current_user, error_response, has_permission, login_required, require_permission, workspace_id
from .timeutils import iso_now

platform_api = Blueprint("platform", __name__)


def _training_scope(column: str) -> tuple[str, list[object]]:
    user = current_user()
    if has_permission(user, "scores.read_team") or has_permission(user, "training.manage"):
        return "", []
    return f" AND ({column} IS NULL OR {column} IN (SELECT id FROM training_runs WHERE workspace_id = ? AND user_id = ?))", [workspace_id(), actor_id()]


@platform_api.get("/health/live")
def health_live():
    return jsonify({"status": "live", "service": "socify", "time": iso_now()})


@platform_api.get("/health/ready")
def health_ready():
    try:
        get_db().execute("SELECT 1").fetchone()
        version = get_db().execute("SELECT value FROM schema_meta WHERE key = 'schema_version'").fetchone()
    except sqlite3.Error:
        return jsonify({"status": "not_ready", "database": "unavailable"}), 503
    return jsonify({"status": "ready", "database": "available", "schema_version": version["value"] if version else "unknown"})


@platform_api.get("/api/health")
@login_required
def health_api():
    queue = int(get_db().execute("SELECT COUNT(*) FROM ingestion_jobs WHERE workspace_id = ? AND status = 'processing'", (workspace_id(),)).fetchone()[0])
    failed_rules = int(get_db().execute("SELECT COALESCE(SUM(failed_evaluations), 0) FROM rules WHERE workspace_id = ?", (workspace_id(),)).fetchone()[0])
    return jsonify({"status": "healthy", "database": "available", "import_jobs_processing": queue, "rule_evaluation_failures": failed_rules, "attack_version": "20.0", "time": iso_now()})


def _dashboard_payload() -> dict[str, Any]:
    event_scope, event_parameters = _training_scope("training_run_id")
    alert_scope, alert_parameters = _training_scope("training_run_id")
    case_scope, case_parameters = _training_scope("training_run_id")
    workspace = workspace_id()
    events = int(get_db().execute(f"SELECT COUNT(*) FROM security_events WHERE workspace_id = ? AND source != 'rules_engine'{event_scope}", (workspace, *event_parameters)).fetchone()[0])
    alerts = int(get_db().execute(f"SELECT COUNT(*) FROM alerts WHERE workspace_id = ? AND status NOT IN ('closed', 'false_positive', 'suppressed'){alert_scope}", (workspace, *alert_parameters)).fetchone()[0])
    cases = int(get_db().execute(f"SELECT COUNT(*) FROM incident_cases WHERE workspace_id = ? AND status NOT IN ('closed', 'cancelled', 'false_positive') AND archived_at IS NULL{case_scope}", (workspace, *case_parameters)).fetchone()[0])
    critical = int(get_db().execute(f"SELECT COUNT(*) FROM security_events WHERE workspace_id = ? AND severity = 'critical' AND source != 'rules_engine'{event_scope}", (workspace, *event_parameters)).fetchone()[0])
    overdue = int(get_db().execute(f"SELECT COUNT(*) FROM incident_cases WHERE workspace_id = ? AND sla_due_at < ? AND status NOT IN ('closed', 'cancelled') AND archived_at IS NULL{case_scope}", (workspace, iso_now(), *case_parameters)).fetchone()[0])
    sources = [dict(row) for row in get_db().execute("SELECT source, COUNT(*) AS count FROM security_events WHERE workspace_id = ? AND source != 'rules_engine' GROUP BY source ORDER BY count DESC LIMIT 10", (workspace,)).fetchall()]
    recent_alerts = [dict(row) for row in get_db().execute(f"SELECT id, alert_id, severity, status, reason, detected_at FROM alerts WHERE workspace_id = ?{alert_scope} ORDER BY detected_at DESC LIMIT 10", (workspace, *alert_parameters)).fetchall()]
    recent_cases = [dict(row) for row in get_db().execute(f"SELECT id, reference, title, severity, priority, status, updated_at, sla_due_at FROM incident_cases WHERE workspace_id = ? AND archived_at IS NULL{case_scope} ORDER BY updated_at DESC LIMIT 10", (workspace, *case_parameters)).fetchall()]
    rule_health = [dict(row) for row in get_db().execute("SELECT id, name, is_active, match_count, false_positive_count, last_triggered_at, average_evaluation_ms, failed_evaluations, suppressions FROM rules WHERE workspace_id = ? AND archived_at IS NULL ORDER BY failed_evaluations DESC, match_count DESC LIMIT 10", (workspace,)).fetchall()]
    return {"counts": {"events": events, "open_alerts": alerts, "active_cases": cases, "critical_events": critical, "overdue_cases": overdue}, "top_sources": sources, "recent_alerts": recent_alerts, "recent_cases": recent_cases, "rule_health": rule_health, "scope": "workspace" if has_permission(current_user(), "scores.read_team") else "own_training_runs_and_shared_events", "generated_at": iso_now()}


@platform_api.get("/api/dashboard")
@login_required
def dashboard_data():
    return jsonify(_dashboard_payload())


@platform_api.get("/api/stats")
@login_required
def stats_compatibility():
    payload = _dashboard_payload()
    return jsonify({**payload["counts"], "top_sources": payload["top_sources"], "generated_at": payload["generated_at"]})


@platform_api.get("/api/audit")
@require_permission("audit.read")
def audit_logs():
    try:
        page = max(int(request.args.get("page", 1)), 1)
        page_size = min(max(int(request.args.get("page_size", request.args.get("limit", 100))), 1), 200)
    except ValueError:
        return error_response("INVALID_PAGINATION", "قيم الترقيم غير صالحة", 400)
    action = request.args.get("action")
    resource = request.args.get("resource")
    clauses = ["a.workspace_id = ?"]
    parameters: list[object] = [workspace_id()]
    if action:
        clauses.append("a.action = ?")
        parameters.append(action)
    if resource:
        clauses.append("a.resource_type = ?")
        parameters.append(resource)
    where = " AND ".join(clauses)
    total = int(get_db().execute(f"SELECT COUNT(*) FROM security_audit_logs a WHERE {where}", parameters).fetchone()[0])
    rows = get_db().execute(f"SELECT a.id, a.actor_id, u.name AS actor_name, a.action, a.resource_type, a.resource_id, a.result, a.details, a.correlation_id, a.ip_address, a.created_at FROM security_audit_logs a LEFT JOIN users u ON u.id = a.actor_id WHERE {where} ORDER BY a.id DESC LIMIT ? OFFSET ?", (*parameters, page_size, (page - 1) * page_size)).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["details"] = json.loads(item["details"] or "{}")
        items.append(item)
    return jsonify({"items": items, "total": total, "page": page, "page_size": page_size})


@platform_api.get("/api/profile")
@login_required
def profile():
    user = current_user()
    sessions = int(get_db().execute("SELECT COUNT(*) FROM auth_sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?", (actor_id(), iso_now())).fetchone()[0])
    mfa = get_db().execute("SELECT enabled, verified_at FROM mfa_enrollments WHERE user_id = ?", (actor_id(),)).fetchone()
    return jsonify({"user": user, "active_sessions": sessions, "mfa": {"enabled": bool(mfa and mfa["enabled"]), "verified_at": mfa["verified_at"] if mfa else None}})


@platform_api.get("/api/settings")
@login_required
def settings():
    return jsonify({"environment": current_app.config["ENV_NAME"], "max_upload_bytes": current_app.config["MAX_CONTENT_LENGTH"], "max_import_rows": current_app.config["MAX_IMPORT_ROWS"], "registration_enabled": bool(current_app.config["ALLOW_REGISTRATION"]), "features": {"external_threat_intelligence": "not_configured", "http_source_connector": "default_deny", "attack_snapshot": "20.0", "sse": "enabled", "mfa": "enabled"}})


@platform_api.get("/api/admin/role-matrix")
@require_permission("users.read")
def role_matrix():
    resources: set[str] = set()
    for permissions in ROLE_PERMISSIONS.values():
        resources.update(permission for permission in permissions if permission != "*")
    rows = []
    for role, permissions in ROLE_PERMISSIONS.items():
        rows.append({"role": role, "permissions": sorted(resources if "*" in permissions else permissions)})
    return jsonify({"items": rows, "default_deny": True})
