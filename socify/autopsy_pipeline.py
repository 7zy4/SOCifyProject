import hashlib
import sqlite3

from .db import get_db
from .security import actor_id, current_user


def guard_batch_scope():
    from flask import request

    from .cases import _case_row
    from .security import error_response

    case_id = (request.view_args or {}).get("case_id")
    if not case_id or not current_user():
        return None
    if not _case_row(case_id):
        return None
    if case_full_access(case_id):
        return None
    allowed = request.endpoint in {"autopsy.case_get", "cases.case_detail", "ui.dashboard"} and request.method == "GET"
    allowed = allowed or request.blueprint == "autopsy_ingestion"
    allowed = allowed or request.endpoint == "autopsy_investigation.case_timeline" and request.method == "GET"
    if not allowed:
        return error_response("BATCH_SCOPE_REQUIRED", "صلاحيتك تخص دفعات محددة؛ عرض سياق القضية الكامل يتطلب الوصول إلى جميع دفعاتها", 403)
    return None


def migrate(connection: sqlite3.Connection) -> None:
    definitions = {
        "autopsy_jobs": {"available_at": "TEXT"},
        "ingestion_jobs": {"executor_id": "INTEGER REFERENCES users(id)", "active_version": "INTEGER NOT NULL DEFAULT 1 CHECK(active_version IN (0,1))"},
        "security_events": {
            "import_job_id": "INTEGER REFERENCES ingestion_jobs(id)",
            "autopsy_active": "INTEGER NOT NULL DEFAULT 1 CHECK(autopsy_active IN (0,1))",
        },
        "case_events": {
            "event_time": "TEXT",
            "time_known": "INTEGER NOT NULL DEFAULT 0",
            "import_job_id": "INTEGER",
            "active_event": "INTEGER NOT NULL DEFAULT 1",
            "event_severity": "TEXT",
        },
    }
    for table, columns in definitions.items():
        existing = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
        for column, definition in columns.items():
            if column not in existing:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
    connection.execute(
        "CREATE TABLE IF NOT EXISTS autopsy_batch_access(job_id INTEGER PRIMARY KEY REFERENCES ingestion_jobs(id), restricted INTEGER NOT NULL DEFAULT 0 CHECK(restricted IN (0,1)), changed_by INTEGER NOT NULL REFERENCES users(id), changed_at TEXT NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS autopsy_batch_members(job_id INTEGER NOT NULL REFERENCES ingestion_jobs(id), user_id INTEGER NOT NULL REFERENCES users(id), PRIMARY KEY(job_id,user_id))"
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_autopsy_events_job ON security_events(import_job_id, autopsy_active, event_time, id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_autopsy_events_active_time ON security_events(owner_case_id, autopsy_active, event_time, id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_autopsy_case_events_order ON case_events(case_id, active_event, event_time, event_id)")
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_autopsy_case_events_time_known ON case_events(case_id, active_event, time_known DESC, event_time, event_id)"
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_autopsy_case_events_event ON case_events(event_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_autopsy_case_events_access ON case_events(case_id,active_event,import_job_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_autopsy_import_authorization ON ingestion_jobs(case_id,created_by,id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_autopsy_import_scope ON ingestion_jobs(id,case_id,created_by)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_autopsy_case_events_job ON case_events(case_id,import_job_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_autopsy_batch_restricted ON autopsy_batch_access(restricted,job_id)")
    projection = "e.event_time, CASE WHEN json_valid(e.normalized_fields) THEN COALESCE(json_extract(e.normalized_fields, '$.event_time_known'),0) ELSE 0 END, e.import_job_id, e.autopsy_active, e.severity"
    connection.execute(
        f"CREATE TRIGGER IF NOT EXISTS autopsy_case_event_projection AFTER INSERT ON case_events BEGIN UPDATE case_events SET (event_time,time_known,import_job_id,active_event,event_severity) = (SELECT {projection} FROM security_events e WHERE e.id = NEW.event_id) WHERE case_id = NEW.case_id AND event_id = NEW.event_id; END"
    )
    connection.execute(
        f"CREATE TRIGGER IF NOT EXISTS autopsy_event_projection_update AFTER UPDATE OF event_time, normalized_fields, import_job_id, autopsy_active, severity ON security_events BEGIN UPDATE case_events SET (event_time,time_known,import_job_id,active_event,event_severity) = (SELECT {projection} FROM security_events e WHERE e.id = NEW.id) WHERE event_id = NEW.id; END"
    )
    if not connection.execute("SELECT 1 FROM schema_meta WHERE key = 'autopsy_pipeline_version'").fetchone():
        for job in connection.execute("SELECT id, case_id, content_hash, autopsy_options FROM ingestion_jobs WHERE case_id IS NOT NULL"):
            prefix = f"case:{job['case_id']}:pipeline:{hashlib.sha256(job['autopsy_options'].encode()).hexdigest()}:import:{job['content_hash']}:%"
            connection.execute(
                "UPDATE security_events SET import_job_id = ? WHERE owner_case_id = ? AND idempotency_key LIKE ? AND import_job_id IS NULL",
                (job["id"], job["case_id"], prefix),
            )
        connection.execute(
            "UPDATE ingestion_jobs AS j SET active_version = CASE WHEN j.id = (SELECT MAX(k.id) FROM ingestion_jobs k WHERE k.case_id = j.case_id AND k.content_hash = j.content_hash AND k.status IN ('completed','completed_with_errors') AND k.accepted > 0) THEN 1 ELSE 0 END WHERE j.case_id IS NOT NULL AND EXISTS (SELECT 1 FROM ingestion_jobs k WHERE k.case_id = j.case_id AND k.content_hash = j.content_hash AND k.status IN ('completed','completed_with_errors') AND k.accepted > 0)"
        )
        connection.execute(
            "UPDATE security_events SET autopsy_active = COALESCE((SELECT active_version FROM ingestion_jobs WHERE id = security_events.import_job_id), 1)"
        )
        connection.execute("INSERT INTO schema_meta(key,value,updated_at) VALUES ('autopsy_pipeline_version','1',strftime('%Y-%m-%dT%H:%M:%fZ','now'))")
    if not connection.execute("SELECT 1 FROM schema_meta WHERE key = 'autopsy_event_projection_version'").fetchone():
        connection.execute(
            f"UPDATE case_events SET (event_time,time_known,import_job_id,active_event,event_severity) = (SELECT {projection} FROM security_events e WHERE e.id = case_events.event_id)"
        )
        connection.execute("INSERT INTO schema_meta(key,value,updated_at) VALUES ('autopsy_event_projection_version','1',strftime('%Y-%m-%dT%H:%M:%fZ','now'))")


def active_event_sql(alias: str = "e") -> str:
    if alias not in {"e", "security_events", "candidate", "event"}:
        raise ValueError("Unknown event SQL alias")
    return f"{alias}.autopsy_active = 1"


def _manager(user):
    return user and user.get("role") in {"soc_manager", "admin"}


def job_visible(job_id: int, user: dict | None = None) -> bool:
    principal = user if user is not None else current_user()
    if not principal:
        return False
    if _manager(principal):
        return True
    return bool(
        get_db()
        .execute(
            "SELECT 1 FROM ingestion_jobs j LEFT JOIN autopsy_batch_access a ON a.job_id = j.id WHERE j.id = ? AND (COALESCE(a.restricted,0) = 0 OR j.created_by = ? OR EXISTS (SELECT 1 FROM autopsy_batch_members m WHERE m.job_id = j.id AND m.user_id = ?))",
            (job_id, principal["id"], principal["id"]),
        )
        .fetchone()
    )


def visibility_sql(alias: str = "e", user: dict | None = None) -> tuple[str, list[object]]:
    if alias not in {"e", "security_events", "candidate", "event", "ce"}:
        raise ValueError("Unknown event SQL alias")
    principal = user if user is not None else current_user()
    if not principal:
        return "0 = 1", []
    if _manager(principal):
        return "1 = 1", []
    return (
        f"({alias}.import_job_id IS NULL OR {alias}.import_job_id NOT IN (SELECT a.job_id FROM autopsy_batch_access a WHERE a.restricted=1 AND NOT EXISTS (SELECT 1 FROM ingestion_jobs j WHERE j.id=a.job_id AND j.created_by=?) AND NOT EXISTS (SELECT 1 FROM autopsy_batch_members m WHERE m.job_id=a.job_id AND m.user_id=?)))",
        [principal["id"], principal["id"]],
    )


def event_visible(case_id: int, event_id: int, user: dict | None = None, active_only: bool = True) -> bool:
    scope, arguments = visibility_sql("e", user)
    active = " AND e.autopsy_active = 1" if active_only else ""
    return bool(
        get_db()
        .execute(
            f"SELECT 1 FROM security_events e JOIN case_events ce ON ce.event_id = e.id WHERE ce.case_id = ? AND e.id = ? AND {scope}{active}",
            (case_id, event_id, *arguments),
        )
        .fetchone()
    )


def case_full_access(case_id: int, user: dict | None = None) -> bool:
    principal = user if user is not None else current_user()
    if not principal:
        return False
    if _manager(principal):
        return True
    return not bool(
        get_db()
        .execute(
            """SELECT 1 FROM autopsy_batch_access a
            CROSS JOIN ingestion_jobs j INDEXED BY idx_autopsy_import_scope ON j.id=a.job_id
            WHERE a.restricted=1 AND j.created_by != ?
            AND NOT EXISTS (SELECT 1 FROM autopsy_batch_members m WHERE m.job_id=j.id AND m.user_id=?)
            AND (j.case_id=?
                OR EXISTS (SELECT 1 FROM case_events ce WHERE ce.case_id=? AND ce.import_job_id=j.id)
                OR EXISTS (SELECT 1 FROM case_evidence ev JOIN security_events e ON e.id=CAST(ev.reference_id AS INTEGER)
                    WHERE ev.case_id=? AND ev.evidence_type='event' AND ev.reference_id=CAST(e.id AS TEXT) AND e.import_job_id=j.id)
                OR EXISTS (SELECT 1 FROM case_alerts ca JOIN alert_events ae ON ae.alert_id=ca.alert_id
                    JOIN security_events e ON e.id=ae.event_id WHERE ca.case_id=? AND e.import_job_id=j.id)
                OR EXISTS (SELECT 1 FROM case_evidence ev JOIN alert_events ae ON ae.alert_id=CAST(ev.reference_id AS INTEGER)
                    JOIN security_events e ON e.id=ae.event_id WHERE ev.case_id=? AND ev.evidence_type='alert'
                    AND ev.reference_id=CAST(ae.alert_id AS TEXT) AND e.import_job_id=j.id)) LIMIT 1""",
            (principal["id"], principal["id"], case_id, case_id, case_id, case_id, case_id),
        )
        .fetchone()
    )


def activate_import(job, actor: int | None = None) -> None:
    from .autopsy_domain import custody, touch_case

    if job["status"] not in {"completed", "completed_with_errors"} or job["accepted"] <= 0:
        raise ValueError("Activate a completed nonempty derived version")
    connection = get_db()
    connection.execute(
        "UPDATE ingestion_jobs SET active_version = CASE WHEN id = ? THEN 1 ELSE 0 END WHERE case_id = ? AND content_hash = ?",
        (job["id"], job["case_id"], job["content_hash"]),
    )
    connection.execute(
        "UPDATE security_events SET autopsy_active = CASE WHEN import_job_id = ? THEN 1 ELSE 0 END WHERE owner_case_id = ? AND import_job_id IN (SELECT id FROM ingestion_jobs WHERE case_id = ? AND content_hash = ?)",
        (job["id"], job["case_id"], job["case_id"], job["content_hash"]),
    )
    custody(
        job["case_id"],
        "derived_import_activated",
        {
            "job_id": job["id"],
            "original_sha256": job["content_hash"],
            "policy": "one active derivation per immutable original; historical alerts retained; rescan active case rules",
        },
        actor=actor if actor is not None else actor_id(),
    )
    touch_case(job["case_id"])
