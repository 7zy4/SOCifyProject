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
    connection.execute("INSERT INTO schema_meta(key, value, updated_at) VALUES ('autopsy_schema_version', '1', ?) ON CONFLICT(key) DO NOTHING", (iso_now(),))
