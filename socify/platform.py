import hmac
import json
import sqlite3

from flask import Blueprint, abort, current_app, jsonify, request

from .db import get_db
from .security import ROLE_PERMISSIONS, current_user, error_response, login_required, require_permission, workspace_id
from .timeutils import iso_now
from .version import VERSION

platform_api = Blueprint("platform", __name__)


@platform_api.get("/health/live")
def health_live():
    return jsonify({"status": "live", "service": "socify", "version": VERSION, "time": iso_now()})


@platform_api.get("/health/ready")
def health_ready():
    try:
        get_db().execute("SELECT 1").fetchone()
        version = get_db().execute("SELECT value FROM schema_meta WHERE key = 'schema_version'").fetchone()
    except sqlite3.Error:
        return jsonify({"status": "not_ready", "database": "unavailable"}), 503
    return jsonify({"status": "ready", "database": "available", "schema_version": version["value"] if version else "unknown"})


IMPORT_STATES = ("queued", "processing", "interrupted", "completed", "completed_with_errors", "failed", "cancelled")
ANALYSIS_STATES = ("queued", "processing", "completed", "failed", "cancelled")


def _state_counts(sql: str, states: tuple[str, ...]) -> dict[str, int]:
    """Counts per known state; anything else is reported as "other", so label values never come from stored text."""
    counts = dict.fromkeys((*states, "other"), 0)
    for state, count in get_db().execute(sql).fetchall():
        counts[state if state in states else "other"] += int(count)
    return counts


def _age_seconds(sql: str) -> float:
    oldest = get_db().execute(sql).fetchone()[0]
    if not oldest:
        return 0.0
    from .timeutils import parse_timestamp, utc_now

    return max((utc_now() - parse_timestamp(str(oldest))).total_seconds(), 0.0)


def _metrics_refusal():
    """None when the request carries the configured metrics token, otherwise the response to send instead.

    Without SOCIFY_METRICS_TOKEN the path does not exist. deploy/nginx.conf also refuses it, so the token is what still
    protects it when port 5000 is published or the ingress is replaced.
    """
    expected = current_app.config.get("METRICS_TOKEN")
    if not expected:
        abort(404)
    scheme, _, supplied = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(supplied.strip().encode(), str(expected).encode()):
        response = error_response("METRICS_TOKEN_REQUIRED", "يلزم رمز المقاييس", 401)
        response[0].headers["WWW-Authenticate"] = 'Bearer realm="socify-metrics"'
        return response
    return None


@platform_api.get("/health/metrics")
def health_metrics():
    """Prometheus text format, read from SQLite on each request.

    Counts and ages only: no case, user, workspace or file values and no label taken from stored text.
    """
    refusal = _metrics_refusal()
    if refusal is not None:
        return refusal
    now = iso_now()
    families: list[tuple[str, str, list[tuple[str, float]]]] = [
        ("socify_schema_version", "Last applied schema migration.", [("", float(get_db().execute("PRAGMA user_version").fetchone()[0]))]),
        (
            "socify_database_bytes",
            "Size of the main database file.",
            [("", float(get_db().execute("SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()").fetchone()[0]))],
        ),
        (
            "socify_import_jobs",
            "Import jobs by state.",
            [
                (f'{{state="{state}"}}', float(count))
                for state, count in _state_counts("SELECT status, COUNT(*) FROM ingestion_jobs GROUP BY status", IMPORT_STATES).items()
            ],
        ),
        (
            "socify_analysis_jobs",
            "Isolated analysis, detection and report jobs by state.",
            [
                (f'{{state="{state}"}}', float(count))
                for state, count in _state_counts("SELECT state, COUNT(*) FROM autopsy_jobs GROUP BY state", ANALYSIS_STATES).items()
            ],
        ),
        (
            "socify_import_oldest_waiting_seconds",
            "Age of the oldest queued or interrupted import job.",
            [("", _age_seconds("SELECT MIN(COALESCE(available_at, created_at)) FROM ingestion_jobs WHERE status IN ('queued', 'interrupted')"))],
        ),
        (
            "socify_analysis_oldest_waiting_seconds",
            "Age of the oldest queued analysis job.",
            [("", _age_seconds("SELECT MIN(COALESCE(available_at, created_at)) FROM autopsy_jobs WHERE state = 'queued'"))],
        ),
        (
            "socify_expired_leases",
            "Jobs still marked processing after their worker lease expired.",
            [
                (
                    '{queue="import"}',
                    float(get_db().execute("SELECT COUNT(*) FROM ingestion_jobs WHERE status = 'processing' AND lease_expires_at <= ?", (now,)).fetchone()[0]),
                ),
                (
                    '{queue="analysis"}',
                    float(get_db().execute("SELECT COUNT(*) FROM autopsy_jobs WHERE state = 'processing' AND lease_expires_at <= ?", (now,)).fetchone()[0]),
                ),
            ],
        ),
        (
            "socify_active_sessions",
            "Signed-in sessions that are neither revoked nor expired.",
            [("", float(get_db().execute("SELECT COUNT(*) FROM auth_sessions WHERE revoked_at IS NULL AND expires_at > ?", (now,)).fetchone()[0]))],
        ),
    ]
    lines = []
    for name, description, samples in families:
        lines += [f"# HELP {name} {description}", f"# TYPE {name} gauge"]
        lines += [f"{name}{labels} {value:g}" for labels, value in samples]
    return current_app.response_class("\n".join(lines) + "\n", mimetype="text/plain", content_type="text/plain; version=0.0.4; charset=utf-8")


@platform_api.get("/api/health")
@login_required
def health_api():
    import_states = {
        row["status"]: int(row["count"])
        for row in get_db().execute("SELECT status, COUNT(*) AS count FROM ingestion_jobs WHERE workspace_id = ? GROUP BY status", (workspace_id(),)).fetchall()
    }
    queue = import_states.get("processing", 0)
    expired_import_leases = int(
        get_db()
        .execute(
            "SELECT COUNT(*) FROM ingestion_jobs WHERE workspace_id = ? AND status = 'processing' AND lease_expires_at <= ?",
            (workspace_id(), iso_now()),
        )
        .fetchone()[0]
    )
    failed_rules = int(get_db().execute("SELECT COALESCE(SUM(failed_evaluations), 0) FROM rules WHERE workspace_id = ?", (workspace_id(),)).fetchone()[0])
    attack_version = get_db().execute("SELECT value FROM schema_meta WHERE key = 'attack_version'").fetchone()
    return jsonify(
        {
            "status": "healthy",
            "database": "available",
            "import_jobs_processing": queue,
            "import_jobs": {
                "queued": sum(import_states.get(state, 0) for state in ("queued", "interrupted")),
                "processing": queue,
                "failed": import_states.get("failed", 0),
                "expired_leases": expired_import_leases,
            },
            "rule_evaluation_failures": failed_rules,
            "attack_version": attack_version["value"] if attack_version else "unknown",
            "time": iso_now(),
        }
    )


@platform_api.get("/api/audit")
@require_permission("audit.read")
def audit_logs():
    from .operational import case_scope

    try:
        page = max(int(request.args.get("page", 1)), 1)
        page_size = min(max(int(request.args.get("page_size", request.args.get("limit", 100))), 1), 200)
    except ValueError:
        return error_response("INVALID_PAGINATION", "قيم الترقيم غير صالحة", 400)
    if page > 1000000:
        return error_response("INVALID_PAGINATION", "قيم الترقيم غير صالحة", 400)
    action = request.args.get("action")
    resource = request.args.get("resource")
    result = request.args.get("result")
    query = request.args.get("q", "").strip()
    if len(query) > 200 or any(len(value or "") > 100 for value in (action, resource, result)):
        return error_response("INVALID_FILTER", "قيمة البحث أو الترشيح أطول من المسموح", 422)
    clauses = ["a.workspace_id = ?"]
    parameters: list[object] = [workspace_id()]
    if action:
        clauses.append("a.action = ?")
        parameters.append(action)
    if resource:
        clauses.append("a.resource_type = ?")
        parameters.append(resource)
    if result:
        clauses.append("a.result = ?")
        parameters.append(result)
    if query:
        pattern = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        fields = [
            "a.action",
            "a.resource_type",
            "a.resource_id",
            "a.correlation_id",
            "a.details",
            "socify_user_name(u.name,u.name_ar,u.name_en)",
            "c.reference",
            "c.title",
        ]
        clauses.append("(" + " OR ".join(f"{field} LIKE ? ESCAPE '\\'" for field in fields) + ")")
        parameters.extend([pattern] * len(fields))
    scope, scope_args = case_scope(current_user() or {})
    joins = f"""LEFT JOIN users u ON u.id = a.actor_id
        LEFT JOIN incident_cases c ON a.resource_type = 'case' AND c.id = a.resource_id
        AND c.workspace_id = a.workspace_id AND c.archived_at IS NULL{scope}"""
    where = " AND ".join(clauses)
    values = [*scope_args, *parameters]
    total = int(get_db().execute(f"SELECT COUNT(*) FROM security_audit_logs a {joins} WHERE {where}", values).fetchone()[0])
    rows = (
        get_db()
        .execute(
            f"SELECT a.id, a.actor_id, socify_user_name(u.name,u.name_ar,u.name_en) AS actor_name, a.action, a.resource_type, a.resource_id, a.result, a.details, a.correlation_id, a.ip_address, a.created_at, c.reference AS resource_reference, c.title AS resource_title FROM security_audit_logs a {joins} WHERE {where} ORDER BY a.id DESC LIMIT ? OFFSET ?",
            (*values, page_size, (page - 1) * page_size),
        )
        .fetchall()
    )
    items = []
    for row in rows:
        item = dict(row)
        item["details"] = json.loads(item["details"] or "{}")
        items.append(item)
    facets = {}
    for key, column in (("actions", "action"), ("resources", "resource_type"), ("results", "result")):
        facets[key] = [
            row[0] for row in get_db().execute(f"SELECT DISTINCT {column} FROM security_audit_logs WHERE workspace_id=? ORDER BY {column}", (workspace_id(),))
        ]
    return jsonify({"items": items, "total": total, "page": page, "page_size": page_size, "filters": facets})


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
