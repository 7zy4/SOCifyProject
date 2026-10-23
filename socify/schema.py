import hashlib
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from .db import inserted_id
from .timeutils import iso_now

BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS training_workspaces (
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
    team TEXT,
    workspace_id INTEGER NOT NULL DEFAULT 1,
    created_at TEXT,
    last_login TEXT,
    password_changed_at TEXT,
    leaderboard_opt_in INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS workspace_memberships (
    workspace_id INTEGER NOT NULL REFERENCES training_workspaces(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    role TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (workspace_id, user_id)
);
CREATE TABLE IF NOT EXISTS auth_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_hash TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id),
    workspace_id INTEGER NOT NULL REFERENCES training_workspaces(id),
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
    workspace_id INTEGER NOT NULL DEFAULT 1 REFERENCES training_workspaces(id),
    training_run_id INTEGER,
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
CREATE TABLE IF NOT EXISTS event_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES security_events(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    comment TEXT NOT NULL,
    timestamp TEXT NOT NULL
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
    workspace_id INTEGER NOT NULL DEFAULT 1 REFERENCES training_workspaces(id),
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
    workspace_id INTEGER NOT NULL REFERENCES training_workspaces(id),
    training_run_id INTEGER,
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
    workspace_id INTEGER NOT NULL REFERENCES training_workspaces(id),
    training_run_id INTEGER,
    title TEXT NOT NULL,
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
    lessons_learned TEXT,
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
CREATE TABLE IF NOT EXISTS case_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES incident_cases(id),
    title TEXT NOT NULL,
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
CREATE TABLE IF NOT EXISTS event_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL DEFAULT 1 REFERENCES training_workspaces(id),
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
    workspace_id INTEGER NOT NULL REFERENCES training_workspaces(id),
    source_id INTEGER REFERENCES event_sources(id),
    training_run_id INTEGER,
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
    started_at TEXT,
    UNIQUE (workspace_id, content_hash, training_run_id)
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
CREATE TABLE IF NOT EXISTS attack_scenarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_id TEXT NOT NULL UNIQUE,
    workspace_id INTEGER NOT NULL REFERENCES training_workspaces(id),
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    active_version INTEGER NOT NULL DEFAULT 1,
    state TEXT NOT NULL DEFAULT 'draft',
    visibility TEXT NOT NULL DEFAULT 'workspace',
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scenario_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_id INTEGER NOT NULL REFERENCES attack_scenarios(id),
    version INTEGER NOT NULL,
    objectives TEXT NOT NULL,
    roles TEXT NOT NULL,
    difficulty TEXT NOT NULL,
    duration_minutes INTEGER NOT NULL,
    environment TEXT NOT NULL,
    scoring_policy TEXT NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    UNIQUE (scenario_id, version)
);
CREATE TABLE IF NOT EXISTS scenario_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_version_id INTEGER NOT NULL REFERENCES scenario_versions(id),
    step_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    name TEXT NOT NULL,
    event_template TEXT NOT NULL,
    artifact TEXT NOT NULL,
    mitre_ids TEXT NOT NULL,
    visible_hint TEXT,
    UNIQUE (scenario_version_id, step_id)
);
CREATE TABLE IF NOT EXISTS scenario_ground_truth (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_version_id INTEGER NOT NULL REFERENCES scenario_versions(id),
    step_id TEXT NOT NULL,
    expected_detections TEXT NOT NULL,
    relevant_evidence TEXT NOT NULL,
    allowed_responses TEXT NOT NULL,
    score_weight REAL NOT NULL,
    UNIQUE (scenario_version_id, step_id)
);
CREATE TABLE IF NOT EXISTS training_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL UNIQUE,
    workspace_id INTEGER NOT NULL REFERENCES training_workspaces(id),
    scenario_version_id INTEGER NOT NULL REFERENCES scenario_versions(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    difficulty TEXT NOT NULL,
    seed INTEGER NOT NULL,
    state TEXT NOT NULL,
    current_step INTEGER NOT NULL DEFAULT 0,
    playback_rate REAL NOT NULL DEFAULT 1,
    started_at TEXT NOT NULL,
    paused_at TEXT,
    completed_at TEXT,
    submitted_at TEXT,
    hints_used INTEGER NOT NULL DEFAULT 0,
    snapshot TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS training_run_events (
    run_id INTEGER NOT NULL REFERENCES training_runs(id),
    step_id TEXT NOT NULL,
    event_id INTEGER NOT NULL REFERENCES security_events(id),
    sequence_number INTEGER NOT NULL,
    PRIMARY KEY (run_id, step_id, event_id)
);
CREATE TABLE IF NOT EXISTS trainee_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES training_runs(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    action_type TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    payload TEXT NOT NULL DEFAULT '{}',
    occurred_at TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    UNIQUE (run_id, idempotency_key)
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
CREATE TABLE IF NOT EXISTS saved_hunt_queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL REFERENCES training_workspaces(id),
    owner_id INTEGER NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    query TEXT NOT NULL,
    visibility TEXT NOT NULL DEFAULT 'private',
    tags TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ioc_indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL REFERENCES training_workspaces(id),
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
CREATE TABLE IF NOT EXISTS ioc_observations (
    ioc_id INTEGER NOT NULL REFERENCES ioc_indicators(id),
    event_id INTEGER NOT NULL REFERENCES security_events(id),
    context TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    PRIMARY KEY (ioc_id, event_id)
);
CREATE TABLE IF NOT EXISTS ioc_enrichment_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id INTEGER NOT NULL REFERENCES ioc_indicators(id),
    provider TEXT NOT NULL,
    status TEXT NOT NULL,
    result TEXT NOT NULL,
    confidence REAL,
    expires_at TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS playbooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_id TEXT NOT NULL UNIQUE,
    workspace_id INTEGER NOT NULL REFERENCES training_workspaces(id),
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    active_version INTEGER NOT NULL DEFAULT 1,
    state TEXT NOT NULL DEFAULT 'draft',
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS playbook_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_id INTEGER NOT NULL REFERENCES playbooks(id),
    version INTEGER NOT NULL,
    trigger_type TEXT NOT NULL,
    preconditions TEXT NOT NULL,
    expected_outcome TEXT NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    UNIQUE (playbook_id, version)
);
CREATE TABLE IF NOT EXISTS playbook_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_version_id INTEGER NOT NULL REFERENCES playbook_versions(id),
    position INTEGER NOT NULL,
    action_type TEXT NOT NULL,
    parameters TEXT NOT NULL,
    approval_role TEXT,
    timeout_seconds INTEGER NOT NULL DEFAULT 30,
    retry_limit INTEGER NOT NULL DEFAULT 2,
    compensation_action TEXT,
    UNIQUE (playbook_version_id, position)
);
CREATE TABLE IF NOT EXISTS playbook_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL UNIQUE,
    workspace_id INTEGER NOT NULL REFERENCES training_workspaces(id),
    playbook_version_id INTEGER NOT NULL REFERENCES playbook_versions(id),
    case_id INTEGER REFERENCES incident_cases(id),
    training_run_id INTEGER REFERENCES training_runs(id),
    state TEXT NOT NULL,
    requested_by INTEGER NOT NULL REFERENCES users(id),
    approved_by INTEGER REFERENCES users(id),
    idempotency_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    available_at TEXT,
    worker_id TEXT,
    lease_expires_at TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    started_at TEXT,
    completed_at TEXT,
    UNIQUE (workspace_id, idempotency_key)
);
CREATE TABLE IF NOT EXISTS playbook_step_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES playbook_runs(id),
    step_id INTEGER NOT NULL REFERENCES playbook_steps(id),
    status TEXT NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 0,
    input TEXT NOT NULL,
    output TEXT,
    impact TEXT,
    started_at TEXT,
    completed_at TEXT,
    error TEXT,
    next_attempt_at TEXT,
    duration_ms INTEGER,
    effect_key TEXT,
    UNIQUE (run_id, step_id)
);
CREATE TABLE IF NOT EXISTS response_simulation_state (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL REFERENCES training_workspaces(id),
    training_run_id INTEGER REFERENCES training_runs(id),
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    state TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workspace_id, training_run_id, entity_type, entity_id)
);
CREATE TABLE IF NOT EXISTS assessment_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id TEXT NOT NULL UNIQUE,
    workspace_id INTEGER NOT NULL REFERENCES training_workspaces(id),
    run_id INTEGER NOT NULL REFERENCES training_runs(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    policy_version TEXT NOT NULL,
    weights TEXT NOT NULL,
    inputs TEXT NOT NULL,
    components TEXT NOT NULL,
    total_score REAL NOT NULL,
    created_at TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1,
    UNIQUE (run_id, policy_version, revision)
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
CREATE TABLE IF NOT EXISTS outbox_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


COLUMN_MIGRATIONS: dict[str, dict[str, str]] = {
    "users": {
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
        "training_run_id": "INTEGER",
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
    "training_runs": {"submitted_at": "TEXT"},
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
    "playbook_runs": {
        "available_at": "TEXT",
        "worker_id": "TEXT",
        "lease_expires_at": "TEXT",
        "cancel_requested": "INTEGER NOT NULL DEFAULT 0",
        "last_error": "TEXT",
        "started_at": "TEXT",
        "completed_at": "TEXT",
    },
    "playbook_step_runs": {
        "next_attempt_at": "TEXT",
        "duration_ms": "INTEGER",
        "effect_key": "TEXT",
    },
}


INDEX_SCHEMA = """
CREATE INDEX IF NOT EXISTS idx_users_workspace ON users(workspace_id, is_active);
CREATE INDEX IF NOT EXISTS idx_events_workspace_time ON security_events(workspace_id, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_events_source_time ON security_events(workspace_id, source, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_events_identity ON security_events(workspace_id, source_ip, username, event_time DESC);
DROP INDEX IF EXISTS idx_events_idempotency;
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_scope_idempotency ON security_events(workspace_id, COALESCE(training_run_id, 0), idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_run_time ON security_events(workspace_id, training_run_id, event_time);
CREATE INDEX IF NOT EXISTS idx_rules_workspace_active ON rules(workspace_id, is_active, archived_at);
CREATE INDEX IF NOT EXISTS idx_alerts_workspace_status ON alerts(workspace_id, status, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_cases_workspace_status ON incident_cases(workspace_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_case_history_case ON case_history(case_id, created_at);
CREATE INDEX IF NOT EXISTS idx_ingestion_workspace ON ingestion_jobs(workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ingestion_worker_queue ON ingestion_jobs(status, available_at, lease_expires_at);
CREATE INDEX IF NOT EXISTS idx_runs_workspace ON training_runs(workspace_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_workspace ON security_audit_logs(workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_outbox_workspace ON outbox_events(workspace_id, id);
CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(identifier_hash, ip_address, occurred_at);
CREATE INDEX IF NOT EXISTS idx_playbook_worker_queue ON playbook_runs(state, available_at, lease_expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_playbook_step_effect ON playbook_step_runs(effect_key) WHERE effect_key IS NOT NULL;
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
    for indicator in connection.execute("SELECT id, workspace_id, context, last_seen FROM ioc_indicators WHERE source = 'SOCify extraction'").fetchall():
        context = json.loads(indicator["context"])
        event_id = context.get("event_id") if isinstance(context, dict) else None
        event = (
            connection.execute("SELECT id FROM security_events WHERE id = ? AND workspace_id = ?", (event_id, indicator["workspace_id"])).fetchone()
            if type(event_id) is int
            else None
        )
        if event:
            connection.execute(
                "INSERT OR IGNORE INTO ioc_observations (ioc_id, event_id, context, tags, created_at) VALUES (?, ?, ?, '[\"training\"]', ?)",
                (indicator["id"], event_id, indicator["context"], indicator["last_seen"]),
            )
    connection.execute("UPDATE users SET workspace_id = 1 WHERE workspace_id IS NULL")
    connection.execute("UPDATE users SET created_at = COALESCE(created_at, ?)", (now,))
    if _table_exists(connection, "security_events"):
        connection.execute("UPDATE security_events SET event_time = COALESCE(event_time, timestamp, ?)", (now,))
        connection.execute("UPDATE security_events SET ingested_at = COALESCE(ingested_at, timestamp, ?)", (now,))
        connection.execute("UPDATE security_events SET workspace_id = 1 WHERE workspace_id IS NULL")
        rows = connection.execute("SELECT id, raw_data FROM security_events WHERE raw_hash IS NULL").fetchall()
        for row in rows:
            raw = row["raw_data"] or ""
            connection.execute("UPDATE security_events SET raw_hash = ? WHERE id = ?", (hashlib.sha256(raw.encode()).hexdigest(), row["id"]))
    if _table_exists(connection, "rules"):
        connection.execute("UPDATE rules SET workspace_id = 1 WHERE workspace_id IS NULL")
        connection.execute("UPDATE rules SET updated_at = COALESCE(updated_at, created_at, ?)", (now,))
    if _table_exists(connection, "event_sources"):
        connection.execute("UPDATE event_sources SET workspace_id = 1 WHERE workspace_id IS NULL")
        connection.execute("UPDATE event_sources SET updated_at = COALESCE(updated_at, created_at, ?)", (now,))
    if _table_exists(connection, "ingestion_jobs"):
        connection.execute(
            """UPDATE ingestion_jobs SET status = 'interrupted', worker_id = NULL, lease_expires_at = NULL,
            available_at = COALESCE(available_at, ?), last_error = 'worker lease expired before completion', updated_at = ?
            WHERE status = 'processing' AND (lease_expires_at IS NULL OR lease_expires_at <= ?)""",
            (now, now, now),
        )
        connection.execute("UPDATE ingestion_jobs SET updated_at = COALESCE(updated_at, created_at, ?)", (now,))
        connection.execute("UPDATE ingestion_jobs SET available_at = COALESCE(available_at, created_at, ?)", (now,))
    if _table_exists(connection, "playbook_runs"):
        connection.execute("UPDATE playbook_runs SET available_at = COALESCE(available_at, created_at, ?)", (now,))
        connection.execute("UPDATE playbook_step_runs SET effect_key = 'playbook-step:' || run_id || ':' || step_id WHERE effect_key IS NULL")


def _migrate_legacy_incidents(connection: sqlite3.Connection) -> None:
    if not _table_exists(connection, "incidents"):
        return
    marker = connection.execute("SELECT value FROM schema_meta WHERE key = 'legacy_incidents_migrated'").fetchone()
    if marker:
        return
    rows = connection.execute("SELECT * FROM incidents ORDER BY id").fetchall()
    now = iso_now()
    for row in rows:
        data = dict(row)
        status_map = {"open": "open", "investigating": "investigating", "resolved": "recovered", "false_positive": "false_positive"}
        connection.execute(
            """INSERT OR IGNORE INTO incident_cases
            (id, reference, workspace_id, title, description, severity, priority, status, assignee, creator, reporter, created_at, updated_at, version)
            VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
            (
                data["id"],
                f"LEGACY-{data['id']:06d}",
                data["title"],
                data.get("description") or "",
                data.get("severity") or "medium",
                data.get("severity") or "medium",
                status_map.get(str(data.get("status") or ""), "open"),
                data.get("assigned_to"),
                data.get("created_by") or 1,
                data.get("created_by") or 1,
                data.get("created_at") or now,
                data.get("updated_at") or now,
            ),
        )
    if _table_exists(connection, "incident_events"):
        for row in connection.execute("SELECT incident_id, event_id FROM incident_events").fetchall():
            case = connection.execute("SELECT creator, created_at FROM incident_cases WHERE id = ?", (row["incident_id"],)).fetchone()
            if case:
                connection.execute(
                    "INSERT OR IGNORE INTO case_events (case_id, event_id, attached_by, attached_at) VALUES (?, ?, ?, ?)",
                    (row["incident_id"], row["event_id"], case["creator"], case["created_at"]),
                )
    if _table_exists(connection, "incident_notes"):
        for row in connection.execute("SELECT incident_id, user_id, note, created_at FROM incident_notes").fetchall():
            connection.execute(
                "INSERT INTO case_notes (case_id, author_id, body, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                (row["incident_id"], row["user_id"], row["note"], row["created_at"] or now, row["created_at"] or now),
            )
    connection.execute(
        "INSERT INTO schema_meta (key, value, updated_at) VALUES ('legacy_incidents_migrated', '1', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (now,),
    )


def seed_reference_data(connection: sqlite3.Connection) -> None:
    now = iso_now()
    connection.execute(
        "INSERT OR IGNORE INTO training_workspaces (id, public_id, name, created_at) VALUES (1, 'workspace-default', 'SOCify Training', ?)", (now,)
    )
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


def _execute_schema(connection: sqlite3.Connection, schema: str) -> None:
    statement = ""
    for line in schema.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            connection.execute(statement)
            statement = ""
    if statement.strip():
        raise ValueError("incomplete schema statement")


def ensure_schema(connection: sqlite3.Connection) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        _execute_schema(connection, BASE_SCHEMA)
        _ensure_columns(connection)
        seed_reference_data(connection)
        _normalize_existing_rows(connection)
        _migrate_legacy_incidents(connection)
        _execute_schema(connection, INDEX_SCHEMA)
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def insert_outbox(connection: sqlite3.Connection, workspace_id: int, event_type: str, payload: dict[str, Any]) -> int:
    cursor = connection.execute(
        "INSERT INTO outbox_events (workspace_id, event_type, payload, created_at) VALUES (?, ?, ?, ?)",
        (workspace_id, event_type, json.dumps(payload, ensure_ascii=False, separators=(",", ":")), iso_now()),
    )
    return inserted_id(cursor)


def public_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16].upper()}"
