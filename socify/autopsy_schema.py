import sqlite3

from .timeutils import iso_now

SCHEMA = """
CREATE TABLE IF NOT EXISTS autopsy_case_context (
    case_id INTEGER PRIMARY KEY REFERENCES incident_cases(id),
    reason TEXT NOT NULL,
    objective TEXT NOT NULL,
    classification TEXT NOT NULL DEFAULT 'confidential',
    attack_outcome TEXT NOT NULL DEFAULT 'unknown',
    alert_verdict TEXT NOT NULL DEFAULT 'undetermined',
    legal_hold INTEGER NOT NULL DEFAULT 0,
    retention_until TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS autopsy_case_members (
    case_id INTEGER NOT NULL REFERENCES incident_cases(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    responsibility TEXT NOT NULL DEFAULT 'analyst',
    assigned_by INTEGER NOT NULL REFERENCES users(id),
    assigned_at TEXT NOT NULL,
    PRIMARY KEY(case_id, user_id)
);
CREATE TABLE IF NOT EXISTS autopsy_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES incident_cases(id),
    kind TEXT NOT NULL,
    payload TEXT NOT NULL CHECK(json_valid(payload)),
    created_by INTEGER NOT NULL REFERENCES users(id),
    updated_by INTEGER NOT NULL REFERENCES users(id),
    version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_autopsy_records_case ON autopsy_records(case_id, kind, id);
CREATE TABLE IF NOT EXISTS autopsy_record_revisions (
    record_id INTEGER NOT NULL REFERENCES autopsy_records(id),
    version INTEGER NOT NULL,
    payload TEXT NOT NULL CHECK(json_valid(payload)),
    actor_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    PRIMARY KEY(record_id, version)
);
CREATE TABLE IF NOT EXISTS autopsy_custody (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES incident_cases(id),
    actor_id INTEGER REFERENCES users(id),
    action TEXT NOT NULL,
    details TEXT NOT NULL CHECK(json_valid(details)),
    previous_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_autopsy_custody_case ON autopsy_custody(case_id, id);
CREATE TRIGGER IF NOT EXISTS autopsy_custody_immutable_update
BEFORE UPDATE ON autopsy_custody BEGIN SELECT RAISE(ABORT, 'custody entries are immutable'); END;
CREATE TRIGGER IF NOT EXISTS autopsy_custody_immutable_delete
BEFORE DELETE ON autopsy_custody BEGIN SELECT RAISE(ABORT, 'custody entries are immutable'); END;
CREATE TABLE IF NOT EXISTS autopsy_case_imports (
    case_id INTEGER NOT NULL REFERENCES incident_cases(id),
    job_id INTEGER NOT NULL REFERENCES ingestion_jobs(id),
    attached_by INTEGER NOT NULL REFERENCES users(id),
    attached_at TEXT NOT NULL,
    PRIMARY KEY(case_id, job_id)
);
CREATE TABLE IF NOT EXISTS autopsy_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL REFERENCES training_workspaces(id),
    name TEXT NOT NULL,
    version INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'draft',
    steps TEXT NOT NULL CHECK(json_valid(steps)),
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    UNIQUE(workspace_id, name, version)
);
CREATE TABLE IF NOT EXISTS autopsy_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES incident_cases(id),
    revision INTEGER NOT NULL,
    payload TEXT NOT NULL CHECK(json_valid(payload)),
    sha256 TEXT NOT NULL,
    source_version INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'draft',
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    approved_by INTEGER REFERENCES users(id),
    approved_at TEXT,
    UNIQUE(case_id, revision)
);
CREATE TABLE IF NOT EXISTS autopsy_report_files (
    report_id INTEGER NOT NULL REFERENCES autopsy_reports(id),
    format TEXT NOT NULL,
    content BLOB NOT NULL,
    sha256 TEXT NOT NULL,
    PRIMARY KEY(report_id, format)
);
CREATE TRIGGER IF NOT EXISTS autopsy_report_snapshot_immutable
BEFORE UPDATE OF case_id, revision, payload, sha256, source_version, created_by, created_at ON autopsy_reports
BEGIN SELECT RAISE(ABORT, 'report snapshots are immutable'); END;
CREATE TRIGGER IF NOT EXISTS autopsy_report_file_immutable_update
BEFORE UPDATE ON autopsy_report_files
BEGIN SELECT RAISE(ABORT, 'report files are immutable'); END;
CREATE TRIGGER IF NOT EXISTS autopsy_report_file_immutable_delete
BEFORE DELETE ON autopsy_report_files
BEGIN SELECT RAISE(ABORT, 'report files are immutable'); END;
CREATE TABLE IF NOT EXISTS autopsy_intel_bundles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL REFERENCES training_workspaces(id),
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    source TEXT NOT NULL,
    license TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    payload TEXT NOT NULL CHECK(json_valid(payload)),
    sha256 TEXT NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    UNIQUE(workspace_id, name, version)
);
CREATE TABLE IF NOT EXISTS autopsy_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES incident_cases(id),
    kind TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'queued',
    parameters TEXT NOT NULL CHECK(json_valid(parameters)),
    result TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(result)),
    error_code TEXT,
    created_by INTEGER NOT NULL REFERENCES users(id),
    worker_id TEXT,
    lease_expires_at TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_autopsy_jobs_queue ON autopsy_jobs(state, id);
CREATE INDEX IF NOT EXISTS idx_autopsy_jobs_case ON autopsy_jobs(case_id, id);
CREATE VIRTUAL TABLE IF NOT EXISTS autopsy_log_search USING fts5(title, description, source_ip, destination_ip, hostname, username, raw_data, content='security_events', content_rowid='id');
CREATE TRIGGER IF NOT EXISTS autopsy_search_insert AFTER INSERT ON security_events BEGIN
    INSERT INTO autopsy_log_search(rowid, title, description, source_ip, destination_ip, hostname, username, raw_data)
    VALUES (new.id, new.title, new.description, new.source_ip, new.destination_ip, new.hostname, new.username, new.raw_data);
END;
CREATE TRIGGER IF NOT EXISTS autopsy_search_delete AFTER DELETE ON security_events BEGIN
    INSERT INTO autopsy_log_search(autopsy_log_search, rowid, title, description, source_ip, destination_ip, hostname, username, raw_data)
    VALUES ('delete', old.id, old.title, old.description, old.source_ip, old.destination_ip, old.hostname, old.username, old.raw_data);
END;
CREATE TRIGGER IF NOT EXISTS autopsy_search_update AFTER UPDATE OF title, description, source_ip, destination_ip, hostname, username, raw_data ON security_events BEGIN
    INSERT INTO autopsy_log_search(autopsy_log_search, rowid, title, description, source_ip, destination_ip, hostname, username, raw_data)
    VALUES ('delete', old.id, old.title, old.description, old.source_ip, old.destination_ip, old.hostname, old.username, old.raw_data);
    INSERT INTO autopsy_log_search(rowid, title, description, source_ip, destination_ip, hostname, username, raw_data)
    VALUES (new.id, new.title, new.description, new.source_ip, new.destination_ip, new.hostname, new.username, new.raw_data);
END;
"""


def migrate(connection: sqlite3.Connection) -> None:
    statement = ""
    for line in SCHEMA.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            connection.execute(statement)
            statement = ""
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
    if "operations_role" not in columns:
        connection.execute("ALTER TABLE users ADD COLUMN operations_role TEXT")
    if not connection.execute("SELECT 1 FROM schema_meta WHERE key = 'autopsy_search_version'").fetchone():
        connection.execute("INSERT INTO autopsy_log_search(autopsy_log_search) VALUES ('rebuild')")
        connection.execute("INSERT INTO schema_meta(key, value, updated_at) VALUES ('autopsy_search_version', '1', ?)", (iso_now(),))
    job_columns = {row["name"] for row in connection.execute("PRAGMA table_info(ingestion_jobs)")}
    if "case_id" not in job_columns:
        connection.execute("ALTER TABLE ingestion_jobs ADD COLUMN case_id INTEGER REFERENCES incident_cases(id)")
    if "autopsy_options" not in job_columns:
        connection.execute("ALTER TABLE ingestion_jobs ADD COLUMN autopsy_options TEXT NOT NULL DEFAULT '{}'")
    if "original_filename" not in job_columns:
        connection.execute("ALTER TABLE ingestion_jobs ADD COLUMN original_filename TEXT")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_autopsy_import_case ON ingestion_jobs(case_id, id)")
    for table in ("security_events", "alerts"):
        columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
        if "owner_case_id" not in columns:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN owner_case_id INTEGER REFERENCES incident_cases(id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_events_case_time ON security_events(owner_case_id, event_time, id)")
    for table in (
        "case_notes",
        "case_evidence",
        "case_events",
        "case_alerts",
        "case_tasks",
        "case_technique_annotations",
        "autopsy_case_members",
        "autopsy_case_imports",
    ):
        for operation, reference in (("INSERT", "new"), ("UPDATE", "new"), ("DELETE", "old")):
            connection.execute(
                f"CREATE TRIGGER IF NOT EXISTS autopsy_version_{table}_{operation.lower()} AFTER {operation} ON {table} WHEN EXISTS (SELECT 1 FROM autopsy_case_context WHERE case_id = {reference}.case_id) BEGIN UPDATE incident_cases SET version = version + 1 WHERE id = {reference}.case_id; END;"
            )
    connection.execute(
        "INSERT INTO schema_meta(key, value, updated_at) VALUES ('autopsy_schema_version', '3', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at WHERE schema_meta.value != excluded.value",
        (iso_now(),),
    )
