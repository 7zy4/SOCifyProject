import hashlib
import json
import re
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from .maintenance import prune_if_due
from .recovery_codes import protect_existing_recovery_codes
from .timeutils import iso_now

BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS workspaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst',
    name_ar TEXT NOT NULL DEFAULT '',
    name_en TEXT NOT NULL DEFAULT '',
    team TEXT,
    workspace_id INTEGER NOT NULL DEFAULT 1,
    created_at TEXT,
    last_login TEXT,
    password_changed_at TEXT,
    leaderboard_opt_in INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS workspace_memberships (
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    role TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (workspace_id, user_id)
);
CREATE TABLE IF NOT EXISTS team_invitations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_by INTEGER NOT NULL REFERENCES users(id),
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);
CREATE TABLE IF NOT EXISTS team_role_permissions (
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    role TEXT NOT NULL,
    permissions TEXT NOT NULL,
    PRIMARY KEY(workspace_id, role)
);
CREATE TABLE IF NOT EXISTS team_log_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    job_id INTEGER NOT NULL REFERENCES ingestion_jobs(id),
    case_id INTEGER NOT NULL REFERENCES incident_cases(id),
    task_id INTEGER NOT NULL REFERENCES case_tasks(id),
    assignee INTEGER NOT NULL REFERENCES users(id),
    assigned_by INTEGER NOT NULL REFERENCES users(id),
    instructions TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'assigned',
    created_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE(workspace_id, job_id, case_id, assignee)
);
CREATE TABLE IF NOT EXISTS auth_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_hash TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id),
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    ip_address TEXT,
    user_agent TEXT
);
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier_hash TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    succeeded INTEGER NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS mfa_enrollments (
    user_id INTEGER PRIMARY KEY REFERENCES users(id),
    secret_ciphertext TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    verified_at TEXT,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS mfa_backup_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    code_hash TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    external_id TEXT,
    idempotency_key TEXT,
    workspace_id INTEGER NOT NULL DEFAULT 1 REFERENCES workspaces(id),
    source TEXT NOT NULL,
    source_type TEXT,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    event_type TEXT,
    title TEXT NOT NULL,
    description TEXT,
    event_time TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    timestamp TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    username TEXT,
    hostname TEXT,
    process_name TEXT,
    parent_process TEXT,
    file_hash TEXT,
    http_status INTEGER,
    action TEXT,
    outcome TEXT,
    raw_data TEXT,
    normalized_fields TEXT NOT NULL DEFAULT '{}',
    tags TEXT NOT NULL DEFAULT '[]',
    mitre_ids TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'open',
    assigned_to INTEGER REFERENCES users(id),
    created_by INTEGER REFERENCES users(id),
    parser_version TEXT NOT NULL DEFAULT 'socify-1',
    raw_hash TEXT,
    provenance TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    condition_type TEXT NOT NULL DEFAULT 'dsl',
    condition_value TEXT NOT NULL DEFAULT '{}',
    dsl_json TEXT,
    action_type TEXT NOT NULL DEFAULT 'create_alert',
    action_value TEXT NOT NULL DEFAULT '{}',
    is_active INTEGER NOT NULL DEFAULT 0,
    archived_at TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    deployment_state TEXT NOT NULL DEFAULT 'draft',
    workspace_id INTEGER NOT NULL DEFAULT 1 REFERENCES workspaces(id),
    created_by INTEGER NOT NULL REFERENCES users(id),
    deployed_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT,
    match_count INTEGER NOT NULL DEFAULT 0,
    false_positive_count INTEGER NOT NULL DEFAULT 0,
    last_triggered_at TEXT,
    average_evaluation_ms REAL NOT NULL DEFAULT 0,
    failed_evaluations INTEGER NOT NULL DEFAULT 0,
    suppressions INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS rule_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL REFERENCES rules(id),
    version INTEGER NOT NULL,
    dsl_json TEXT NOT NULL,
    action_json TEXT NOT NULL,
    change_summary TEXT NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    UNIQUE (rule_id, version)
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL UNIQUE,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    rule_id INTEGER NOT NULL REFERENCES rules(id),
    rule_version INTEGER NOT NULL,
    reason TEXT NOT NULL,
    evidence TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    detected_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'untriaged',
    assignee INTEGER REFERENCES users(id),
    false_positive_reason TEXT,
    mitre_technique_ids TEXT NOT NULL DEFAULT '[]',
    dedup_key TEXT NOT NULL UNIQUE,
    trace TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alert_events (
    alert_id INTEGER NOT NULL REFERENCES alerts(id),
    event_id INTEGER NOT NULL REFERENCES security_events(id),
    PRIMARY KEY (alert_id, event_id)
);
CREATE TABLE IF NOT EXISTS detection_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL REFERENCES rules(id),
    event_id INTEGER NOT NULL REFERENCES security_events(id),
    alert_event_id INTEGER REFERENCES security_events(id),
    alert_id INTEGER REFERENCES alerts(id),
    dedup_key TEXT,
    trace TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (rule_id, event_id)
);
CREATE TABLE IF NOT EXISTS incident_cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reference TEXT NOT NULL UNIQUE,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    title TEXT NOT NULL,
    title_en TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    case_type TEXT NOT NULL DEFAULT 'investigation',
    severity TEXT NOT NULL DEFAULT 'medium',
    priority TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'new',
    assignee INTEGER REFERENCES users(id),
    team TEXT,
    sla_due_at TEXT,
    sla_paused_at TEXT,
    creator INTEGER NOT NULL REFERENCES users(id),
    reporter INTEGER REFERENCES users(id),
    tags TEXT NOT NULL DEFAULT '[]',
    mitre_ids TEXT NOT NULL DEFAULT '[]',
    disposition TEXT,
    root_cause TEXT,
    impact TEXT,
    response_summary TEXT,
    evidence_summary TEXT,
    lessons_learned TEXT,
    validation TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT,
    closed_at TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    archived_at TEXT
);
CREATE TABLE IF NOT EXISTS case_alerts (
    case_id INTEGER NOT NULL REFERENCES incident_cases(id),
    alert_id INTEGER NOT NULL REFERENCES alerts(id),
    attached_by INTEGER NOT NULL REFERENCES users(id),
    attached_at TEXT NOT NULL,
    PRIMARY KEY (case_id, alert_id)
);
CREATE TABLE IF NOT EXISTS case_events (
    case_id INTEGER NOT NULL REFERENCES incident_cases(id),
    event_id INTEGER NOT NULL REFERENCES security_events(id),
    attached_by INTEGER NOT NULL REFERENCES users(id),
    attached_at TEXT NOT NULL,
    PRIMARY KEY (case_id, event_id)
);
CREATE TABLE IF NOT EXISTS case_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES incident_cases(id),
    author_id INTEGER NOT NULL REFERENCES users(id),
    body TEXT NOT NULL,
    visibility TEXT NOT NULL DEFAULT 'team',
    version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS case_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES incident_cases(id),
    evidence_type TEXT NOT NULL,
    reference_id TEXT NOT NULL,
    title TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    provenance TEXT NOT NULL,
    added_by INTEGER NOT NULL REFERENCES users(id),
    added_at TEXT NOT NULL,
    accessed_at TEXT,
    immutable INTEGER NOT NULL DEFAULT 1,
    UNIQUE (case_id, evidence_type, reference_id)
);
CREATE TRIGGER IF NOT EXISTS case_evidence_immutable_update
BEFORE UPDATE OF case_id, evidence_type, reference_id, title, sha256, provenance, added_by, added_at, immutable ON case_evidence
WHEN OLD.immutable = 1
BEGIN
    SELECT RAISE(ABORT, 'immutable case evidence');
END;
CREATE TRIGGER IF NOT EXISTS case_evidence_immutable_delete
BEFORE DELETE ON case_evidence
WHEN OLD.immutable = 1
BEGIN
    SELECT RAISE(ABORT, 'immutable case evidence');
END;
CREATE TABLE IF NOT EXISTS case_evidence_content (
    evidence_id INTEGER PRIMARY KEY REFERENCES case_evidence(id),
    ciphertext TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS case_evidence_content_immutable_update
BEFORE UPDATE ON case_evidence_content
BEGIN
    SELECT RAISE(ABORT, 'immutable evidence content');
END;
CREATE TRIGGER IF NOT EXISTS case_evidence_content_immutable_delete
BEFORE DELETE ON case_evidence_content
BEGIN
    SELECT RAISE(ABORT, 'immutable evidence content');
END;
CREATE TABLE IF NOT EXISTS case_creation_receipts (
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    actor_id INTEGER NOT NULL REFERENCES users(id),
    request_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    case_id INTEGER NOT NULL REFERENCES incident_cases(id),
    created_at TEXT NOT NULL,
    PRIMARY KEY(workspace_id, actor_id, request_key)
);
CREATE TABLE IF NOT EXISTS case_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES incident_cases(id),
    title TEXT NOT NULL,
    system_key TEXT,
    required INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    assignee INTEGER REFERENCES users(id),
    completed_by INTEGER REFERENCES users(id),
    completed_at TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS case_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES incident_cases(id),
    actor_id INTEGER NOT NULL REFERENCES users(id),
    action TEXT NOT NULL,
    previous_value TEXT,
    new_value TEXT,
    reason TEXT,
    correlation_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS case_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES incident_cases(id),
    revision INTEGER NOT NULL,
    format TEXT NOT NULL,
    content TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    UNIQUE (case_id, revision, format)
);
CREATE TABLE IF NOT EXISTS case_technique_annotations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES incident_cases(id),
    technique_id TEXT NOT NULL,
    attack_version TEXT NOT NULL,
    event_id INTEGER REFERENCES security_events(id),
    assessment TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_case_technique_annotations ON case_technique_annotations(case_id, id);
CREATE TABLE IF NOT EXISTS event_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL DEFAULT 1 REFERENCES workspaces(id),
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    endpoint TEXT,
    api_key TEXT,
    credential_ciphertext TEXT,
    credential_configured INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'not_tested',
    is_active INTEGER NOT NULL DEFAULT 1,
    last_sync TEXT,
    last_validation TEXT,
    rows_ingested INTEGER NOT NULL DEFAULT 0,
    error_rate REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS ingestion_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL UNIQUE,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    source_id INTEGER REFERENCES event_sources(id),
    filename TEXT NOT NULL,
    format TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    evidence_ciphertext TEXT,
    raw_size INTEGER NOT NULL DEFAULT 0,
    estimated_total INTEGER NOT NULL DEFAULT 0,
    checkpoint INTEGER NOT NULL DEFAULT 0,
    retry_count INTEGER NOT NULL DEFAULT 0,
    source_name TEXT NOT NULL DEFAULT 'file-import',
    status TEXT NOT NULL,
    accepted INTEGER NOT NULL DEFAULT 0,
    rejected INTEGER NOT NULL DEFAULT 0,
    skipped INTEGER NOT NULL DEFAULT 0,
    total INTEGER NOT NULL DEFAULT 0,
    progress REAL NOT NULL DEFAULT 0,
    parser_version TEXT NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT,
    completed_at TEXT,
    available_at TEXT,
    worker_id TEXT,
    lease_expires_at TEXT,
    last_error TEXT,
    started_at TEXT
);
CREATE TABLE IF NOT EXISTS ingestion_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL REFERENCES ingestion_jobs(id),
    row_number INTEGER,
    error_code TEXT NOT NULL,
    message TEXT NOT NULL,
    sample TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attack_techniques (
    technique_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    tactic TEXT NOT NULL,
    description TEXT NOT NULL,
    source_url TEXT NOT NULL,
    attack_version TEXT NOT NULL,
    is_subtechnique INTEGER NOT NULL DEFAULT 0,
    deprecated INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS attack_catalog_versions (
    version TEXT PRIMARY KEY,
    source_url TEXT NOT NULL,
    source_sha256 TEXT NOT NULL,
    technique_count INTEGER NOT NULL,
    imported_at TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS attack_technique_versions (
    version TEXT NOT NULL REFERENCES attack_catalog_versions(version),
    technique_id TEXT NOT NULL,
    name TEXT NOT NULL,
    tactic TEXT NOT NULL,
    description TEXT NOT NULL,
    source_url TEXT NOT NULL,
    is_subtechnique INTEGER NOT NULL DEFAULT 0,
    deprecated INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (version, technique_id)
);
CREATE TABLE IF NOT EXISTS attack_catalog_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_version TEXT,
    to_version TEXT NOT NULL REFERENCES attack_catalog_versions(version),
    added_count INTEGER NOT NULL,
    removed_count INTEGER NOT NULL,
    changed_count INTEGER NOT NULL,
    deprecated_count INTEGER NOT NULL,
    revoked_count INTEGER NOT NULL,
    activated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ioc_indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    confidence REAL NOT NULL,
    source TEXT NOT NULL,
    context TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '[]',
    UNIQUE (workspace_id, type, value)
);
CREATE TABLE IF NOT EXISTS playbooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_id TEXT NOT NULL UNIQUE,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    active_version INTEGER NOT NULL DEFAULT 1,
    state TEXT NOT NULL DEFAULT 'draft',
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS security_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER,
    actor_id INTEGER,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    result TEXT NOT NULL,
    details TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL
);
"""


COLUMN_MIGRATIONS: dict[str, dict[str, str]] = {
    "mfa_enrollments": {"last_totp_counter": "INTEGER"},
    "auth_sessions": {"revoked_reason": "TEXT"},
    "case_tasks": {"system_key": "TEXT"},
    "users": {
        "name_ar": "TEXT NOT NULL DEFAULT ''",
        "name_en": "TEXT NOT NULL DEFAULT ''",
        "team": "TEXT",
        "workspace_id": "INTEGER NOT NULL DEFAULT 1",
        "created_at": "TEXT",
        "last_login": "TEXT",
        "password_changed_at": "TEXT",
        "leaderboard_opt_in": "INTEGER NOT NULL DEFAULT 0",
        "is_active": "INTEGER NOT NULL DEFAULT 1",
    },
    "security_events": {
        "external_id": "TEXT",
        "idempotency_key": "TEXT",
        "workspace_id": "INTEGER NOT NULL DEFAULT 1",
        "source_type": "TEXT",
        "event_type": "TEXT",
        "event_time": "TEXT",
        "ingested_at": "TEXT",
        "source_ip": "TEXT",
        "destination_ip": "TEXT",
        "username": "TEXT",
        "hostname": "TEXT",
        "process_name": "TEXT",
        "parent_process": "TEXT",
        "file_hash": "TEXT",
        "http_status": "INTEGER",
        "action": "TEXT",
        "outcome": "TEXT",
        "normalized_fields": "TEXT NOT NULL DEFAULT '{}'",
        "tags": "TEXT NOT NULL DEFAULT '[]'",
        "mitre_ids": "TEXT NOT NULL DEFAULT '[]'",
        "parser_version": "TEXT NOT NULL DEFAULT 'socify-1'",
        "raw_hash": "TEXT",
        "provenance": "TEXT NOT NULL DEFAULT '{}'",
    },
    "rules": {
        "dsl_json": "TEXT",
        "archived_at": "TEXT",
        "version": "INTEGER NOT NULL DEFAULT 1",
        "deployment_state": "TEXT NOT NULL DEFAULT 'draft'",
        "workspace_id": "INTEGER NOT NULL DEFAULT 1",
        "deployed_by": "INTEGER",
        "updated_at": "TEXT",
        "match_count": "INTEGER NOT NULL DEFAULT 0",
        "false_positive_count": "INTEGER NOT NULL DEFAULT 0",
        "last_triggered_at": "TEXT",
        "average_evaluation_ms": "REAL NOT NULL DEFAULT 0",
        "failed_evaluations": "INTEGER NOT NULL DEFAULT 0",
        "suppressions": "INTEGER NOT NULL DEFAULT 0",
    },
    "incident_cases": {
        "title_en": "TEXT NOT NULL DEFAULT ''",
        "evidence_summary": "TEXT",
        "validation": "TEXT",
    },
    "detection_matches": {
        "alert_id": "INTEGER",
        "dedup_key": "TEXT",
        "trace": "TEXT",
    },
    "event_sources": {
        "workspace_id": "INTEGER NOT NULL DEFAULT 1",
        "credential_ciphertext": "TEXT",
        "credential_configured": "INTEGER NOT NULL DEFAULT 0",
        "status": "TEXT NOT NULL DEFAULT 'not_tested'",
        "last_validation": "TEXT",
        "rows_ingested": "INTEGER NOT NULL DEFAULT 0",
        "error_rate": "REAL NOT NULL DEFAULT 0",
        "updated_at": "TEXT",
        "default_case_id": "INTEGER",
        "ingest_token_hash": "TEXT",
    },
    "ingestion_jobs": {
        "evidence_ciphertext": "TEXT",
        "raw_size": "INTEGER NOT NULL DEFAULT 0",
        "estimated_total": "INTEGER NOT NULL DEFAULT 0",
        "checkpoint": "INTEGER NOT NULL DEFAULT 0",
        "retry_count": "INTEGER NOT NULL DEFAULT 0",
        "source_name": "TEXT NOT NULL DEFAULT 'file-import'",
        "updated_at": "TEXT",
        "available_at": "TEXT",
        "worker_id": "TEXT",
        "lease_expires_at": "TEXT",
        "last_error": "TEXT",
        "started_at": "TEXT",
    },
}


INDEX_SCHEMA = """
CREATE INDEX IF NOT EXISTS idx_users_workspace ON users(workspace_id, is_active);
CREATE INDEX IF NOT EXISTS idx_users_email_lower ON users(lower(email));
CREATE INDEX IF NOT EXISTS idx_events_workspace_time ON security_events(workspace_id, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_events_source_time ON security_events(workspace_id, source, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_events_identity ON security_events(workspace_id, source_ip, username, event_time DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_workspace_idempotency ON security_events(workspace_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_rules_workspace_active ON rules(workspace_id, is_active, archived_at);
CREATE INDEX IF NOT EXISTS idx_alerts_workspace_status ON alerts(workspace_id, status, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_cases_workspace_status ON incident_cases(workspace_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_case_history_case ON case_history(case_id, created_at);
CREATE INDEX IF NOT EXISTS idx_ingestion_workspace ON ingestion_jobs(workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ingestion_worker_queue ON ingestion_jobs(status, available_at, lease_expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_workspace ON security_audit_logs(workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(identifier_hash, ip_address, occurred_at);
"""


ATTACK_CATALOG_PATH = Path(__file__).resolve().parent.parent / "data" / "enterprise-attack-v20.0.json"


def _attack_catalog() -> dict[str, Any]:
    payload = json.loads(ATTACK_CATALOG_PATH.read_text(encoding="utf-8"))
    techniques = payload.get("techniques")
    if payload.get("attack_version") != "20.0" or payload.get("total_active") != 706 or not isinstance(techniques, list) or len(techniques) != 706:
        raise RuntimeError("bundled ATT&CK Enterprise v20.0 catalog failed integrity validation")
    return payload


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}


def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    return connection.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone() is not None


PRE_RELEASE_TABLES = (
    "playbook_step_runs",
    "playbook_steps",
    "playbook_runs",
    "playbook_versions",
    "assessment_snapshots",
    "response_simulation_state",
    "trainee_actions",
    "training_run_events",
    "training_runs",
    "scenario_steps",
    "scenario_ground_truth",
    "scenario_versions",
    "attack_scenarios",
    "saved_hunt_queries",
    "ioc_observations",
    "ioc_enrichment_results",
    "event_comments",
    "outbox_events",
)
PRE_RELEASE_INDEXES = ("idx_events_idempotency", "idx_events_scope_idempotency", "idx_events_run_time")
PRE_RELEASE_SOURCE_CONDITION = '{"field":"source_type","operator":"not_equals","value":"training"}'


def has_pre_release_schema(connection: sqlite3.Connection) -> bool:
    return _table_exists(connection, "training_workspaces")


def _rebuild_without_column(connection: sqlite3.Connection, table: str, column: str) -> None:
    """Recreate ``table`` without ``column`` when a constraint on the column rules out ALTER TABLE DROP COLUMN."""
    definition = connection.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone()[0]
    rebuilt = re.sub(rf",\s*UNIQUE\s*\([^)]*\b{column}\b[^)]*\)", "", definition)
    rebuilt = re.sub(rf",\s*{column}\s+INTEGER(?:\s+REFERENCES\s+\w+\(id\))?", "", rebuilt)
    if re.search(rf"\b{column}\b", rebuilt):
        raise RuntimeError(f"cannot remove {table}.{column}: unexpected table definition")
    attached = [
        row[0] for row in connection.execute("SELECT sql FROM sqlite_master WHERE tbl_name = ? AND type IN ('index', 'trigger') AND sql IS NOT NULL", (table,))
    ]
    kept = ", ".join(name for name in (str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")) if name != column)
    staging = f"{table}_rebuild"
    connection.execute(re.sub(rf"^CREATE TABLE\s+(?:IF NOT EXISTS\s+)?\"?{table}\"?", f"CREATE TABLE {staging}", rebuilt, count=1))
    connection.execute(f"INSERT INTO {staging} ({kept}) SELECT {kept} FROM {table}")
    connection.execute(f"DROP TABLE {table}")
    connection.execute(f"ALTER TABLE {staging} RENAME TO {table}")
    for statement in attached:
        connection.execute(statement)


def _retire_pre_release_schema(connection: sqlite3.Connection) -> None:
    """Bring a database created by a pre-release build to the 1.0.0 schema.

    Runs before the baseline, which names the workspace table ``workspaces``, with foreign keys off as table
    rebuilds require (``ensure_schema`` handles both). It refuses to drop records that belong to a training run
    rather than make them visible to the team.
    """
    if not has_pre_release_schema(connection):
        return
    for table in ("security_events", "alerts", "incident_cases", "ingestion_jobs"):
        if (
            _table_exists(connection, table)
            and "training_run_id" in _columns(connection, table)
            and connection.execute(f"SELECT 1 FROM {table} WHERE training_run_id IS NOT NULL LIMIT 1").fetchone()
        ):
            raise RuntimeError(f"{table} holds records from a pre-release training run; export what you need and start from a new database")
    connection.execute("ALTER TABLE training_workspaces RENAME TO workspaces")
    for index in PRE_RELEASE_INDEXES:
        connection.execute(f"DROP INDEX IF EXISTS {index}")
    for table in PRE_RELEASE_TABLES:
        connection.execute(f"DROP TABLE IF EXISTS {table}")
    for table in ("security_events", "alerts", "incident_cases"):
        if _table_exists(connection, table) and "training_run_id" in _columns(connection, table):
            connection.execute(f"ALTER TABLE {table} DROP COLUMN training_run_id")
    if _table_exists(connection, "ingestion_jobs") and "training_run_id" in _columns(connection, "ingestion_jobs"):
        _rebuild_without_column(connection, "ingestion_jobs", "training_run_id")
    for table in ("security_events", "event_sources"):
        if _table_exists(connection, table):
            column = "source_type" if table == "security_events" else "type"
            if column in _columns(connection, table):
                connection.execute(f"UPDATE {table} SET {column} = 'synthetic' WHERE {column} = 'training'")
    if _table_exists(connection, "rules"):
        connection.execute(
            "UPDATE rules SET dsl_json = replace(dsl_json, ?, ?) WHERE instr(dsl_json, ?) > 0",
            (PRE_RELEASE_SOURCE_CONDITION, PRE_RELEASE_SOURCE_CONDITION.replace('"training"', '"synthetic"'), PRE_RELEASE_SOURCE_CONDITION),
        )


def _ensure_columns(connection: sqlite3.Connection) -> None:
    for table, definitions in COLUMN_MIGRATIONS.items():
        if not _table_exists(connection, table):
            continue
        existing = _columns(connection, table)
        for name, definition in definitions.items():
            if name not in existing:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def _normalize_existing_rows(connection: sqlite3.Connection) -> None:
    now = iso_now()
    connection.execute("UPDATE users SET workspace_id = 1 WHERE workspace_id IS NULL")
    connection.execute("UPDATE users SET created_at = ? WHERE created_at IS NULL", (now,))
    if _table_exists(connection, "security_events"):
        for column in ("event_time", "ingested_at", "workspace_id", "raw_hash"):
            connection.execute(f"CREATE INDEX IF NOT EXISTS idx_events_missing_{column} ON security_events(id) WHERE {column} IS NULL")
        connection.execute("UPDATE security_events SET event_time = COALESCE(timestamp, ?) WHERE event_time IS NULL", (now,))
        connection.execute("UPDATE security_events SET ingested_at = COALESCE(timestamp, ?) WHERE ingested_at IS NULL", (now,))
        connection.execute("UPDATE security_events SET workspace_id = 1 WHERE workspace_id IS NULL")
        rows = connection.execute("SELECT id, raw_data FROM security_events WHERE raw_hash IS NULL").fetchall()
        for row in rows:
            raw = row["raw_data"] or ""
            connection.execute("UPDATE security_events SET raw_hash = ? WHERE id = ?", (hashlib.sha256(raw.encode()).hexdigest(), row["id"]))
    if _table_exists(connection, "rules"):
        connection.execute("UPDATE rules SET workspace_id = 1 WHERE workspace_id IS NULL")
        connection.execute("UPDATE rules SET updated_at = COALESCE(created_at, ?) WHERE updated_at IS NULL", (now,))
    if _table_exists(connection, "event_sources"):
        connection.execute("UPDATE event_sources SET workspace_id = 1 WHERE workspace_id IS NULL")
        connection.execute("UPDATE event_sources SET updated_at = COALESCE(created_at, ?) WHERE updated_at IS NULL", (now,))
    if _table_exists(connection, "ingestion_jobs"):
        connection.execute(
            """UPDATE ingestion_jobs SET status = 'interrupted', worker_id = NULL, lease_expires_at = NULL,
            available_at = COALESCE(available_at, ?), last_error = 'worker lease expired before completion', updated_at = ?
            WHERE status = 'processing' AND (lease_expires_at IS NULL OR lease_expires_at <= ?)""",
            (now, now, now),
        )
        connection.execute("UPDATE ingestion_jobs SET updated_at = COALESCE(created_at, ?) WHERE updated_at IS NULL", (now,))
        connection.execute("UPDATE ingestion_jobs SET available_at = COALESCE(created_at, ?) WHERE available_at IS NULL", (now,))


def seed_reference_data(connection: sqlite3.Connection) -> None:
    now = iso_now()
    connection.execute("INSERT OR IGNORE INTO workspaces (id, public_id, name, created_at) VALUES (1, 'workspace-default', 'SOCify Workspace', ?)", (now,))
    existing_catalog = connection.execute("SELECT value FROM schema_meta WHERE key = 'attack_version'").fetchone()
    if existing_catalog:
        _record_existing_attack_catalog(connection, str(existing_catalog["value"]), now)
        return
    existing_rows = int(connection.execute("SELECT COUNT(*) FROM attack_techniques").fetchone()[0])
    if existing_rows:
        raise RuntimeError("ATT&CK catalog already contains records without version metadata; migration requires manual review")
    catalog = _attack_catalog()
    for technique in catalog["techniques"]:
        connection.execute(
            """INSERT INTO attack_techniques
            (technique_id, name, tactic, description, source_url, attack_version, is_subtechnique)
            VALUES (?, ?, ?, ?, ?, '20.0', ?)""",
            (
                technique["technique_id"],
                technique["name"],
                ",".join(technique["tactics"]),
                technique["description"],
                technique["source_url"],
                1 if technique["is_subtechnique"] else 0,
            ),
        )
    connection.execute("INSERT OR IGNORE INTO schema_meta (key, value, updated_at) VALUES ('schema_version', '2', ?)", (now,))
    connection.execute("INSERT INTO schema_meta (key, value, updated_at) VALUES ('attack_version', '20.0', ?)", (now,))
    connection.execute("INSERT INTO schema_meta (key, value, updated_at) VALUES ('attack_snapshot_count', ?, ?)", (str(catalog["total_active"]), now))
    connection.execute("INSERT INTO schema_meta (key, value, updated_at) VALUES ('attack_snapshot_source', ?, ?)", (catalog["source_url"], now))
    connection.execute(
        "INSERT INTO schema_meta (key, value, updated_at) VALUES ('attack_snapshot_sha256', ?, ?)",
        (hashlib.sha256(ATTACK_CATALOG_PATH.read_bytes()).hexdigest(), now),
    )
    _record_existing_attack_catalog(connection, "20.0", now)


def _record_existing_attack_catalog(connection: sqlite3.Connection, version: str, imported_at: str) -> None:
    if connection.execute("SELECT 1 FROM attack_catalog_versions WHERE version = ?", (version,)).fetchone():
        connection.execute("UPDATE attack_catalog_versions SET active = CASE WHEN version = ? THEN 1 ELSE 0 END", (version,))
        return
    rows = connection.execute(
        "SELECT technique_id, name, tactic, description, source_url, is_subtechnique, deprecated, revoked FROM attack_techniques ORDER BY technique_id"
    ).fetchall()
    if not rows:
        raise RuntimeError("ATT&CK catalog metadata exists without technique records")
    canonical = json.dumps([dict(row) for row in rows], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    source_row = connection.execute("SELECT value FROM schema_meta WHERE key = 'attack_snapshot_source'").fetchone()
    digest_row = connection.execute("SELECT value FROM schema_meta WHERE key = 'attack_snapshot_sha256'").fetchone()
    source = str(source_row["value"]) if source_row else "unknown"
    digest = str(digest_row["value"]) if digest_row else hashlib.sha256(canonical).hexdigest()
    connection.execute("UPDATE attack_catalog_versions SET active = 0")
    connection.execute(
        "INSERT INTO attack_catalog_versions (version, source_url, source_sha256, technique_count, imported_at, active) VALUES (?, ?, ?, ?, ?, 1)",
        (version, source, digest, len(rows), imported_at),
    )
    connection.executemany(
        """INSERT INTO attack_technique_versions
        (version, technique_id, name, tactic, description, source_url, is_subtechnique, deprecated, revoked)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            (
                version,
                row["technique_id"],
                row["name"],
                row["tactic"],
                row["description"],
                row["source_url"],
                row["is_subtechnique"],
                row["deprecated"],
                row["revoked"],
            )
            for row in rows
        ],
    )


# Operational bookkeeping kept apart from case data: worker heartbeats (health checks, metrics) and backup runs.
OPERATIONS_SCHEMA = """
CREATE TABLE IF NOT EXISTS worker_heartbeats (
    name TEXT PRIMARY KEY,
    instance TEXT,
    pid INTEGER,
    version TEXT,
    started_at TEXT,
    last_beat_at TEXT,
    state TEXT
);
CREATE TABLE IF NOT EXISTS backup_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('succeeded', 'failed')),
    file_name TEXT,
    size_bytes INTEGER,
    sha256 TEXT,
    encrypted INTEGER NOT NULL DEFAULT 0,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_backup_runs_status ON backup_runs(status, finished_at);
"""


def _execute_schema(connection: sqlite3.Connection, schema: str) -> None:
    statement = ""
    for line in schema.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            connection.execute(statement)
            statement = ""
    if statement.strip():
        raise ValueError("incomplete schema statement")


def baseline_schema(connection: sqlite3.Connection) -> None:
    """Migration 1 (socify.migrations): the idempotent start-up set-up and reconciliation."""
    from .autopsy_schema import migrate

    _execute_schema(connection, BASE_SCHEMA)
    _ensure_columns(connection)
    seed_reference_data(connection)
    _normalize_existing_rows(connection)
    _execute_schema(connection, INDEX_SCHEMA)
    _execute_schema(connection, OPERATIONS_SCHEMA)
    migrate(connection)
    from .api_tokens import migrate as migrate_api_tokens
    from .autopsy_workspace import migrate as migrate_workspace
    from .builtin_rules import seed_builtin_rules
    from .intake import migrate as migrate_intake
    from .onboarding import migrate as migrate_onboarding
    from .quick_reports import migrate as migrate_quick_reports
    from .watchlist import migrate as migrate_watchlist

    migrate_workspace(connection)
    migrate_watchlist(connection)
    migrate_quick_reports(connection)
    migrate_onboarding(connection)
    migrate_api_tokens(connection)
    migrate_intake(connection)
    seed_builtin_rules(connection)
    protect_existing_recovery_codes(connection)


def ensure_schema(connection: sqlite3.Connection) -> None:
    from .migrations import apply_migrations

    # Table rebuilds need foreign keys off, and SQLite only changes that setting outside a transaction.
    retiring = has_pre_release_schema(connection)
    if retiring:
        connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute("BEGIN IMMEDIATE")
    try:
        if retiring:
            _retire_pre_release_schema(connection)
        apply_migrations(connection)
        if retiring and connection.execute("PRAGMA foreign_key_check").fetchone():
            raise RuntimeError("foreign key check failed after upgrading a pre-release database")
        prune_if_due(connection)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        if retiring:
            connection.execute("PRAGMA foreign_keys = ON")


def public_id(prefix: str) -> str:
    """A random identifier shown to users, such as EVT-1A2B3C4D5E6F7A8B."""
    return f"{prefix}-{uuid.uuid4().hex[:16].upper()}"
