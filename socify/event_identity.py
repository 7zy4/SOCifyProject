"""Conservative import identity, with one retained occurrence per input row.

A declared source is a namespace, never an access grant. Unidentified records
remain separate. Raw values and effective facts must both match; only JSON
object ordering and transport whitespace are insignificant.
"""

import hashlib
import json


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def identity_key(event, job):
    if job is None or job["case_id"] is None:
        return None
    raw = json.loads(event["raw_data"])
    fields = json.loads(event["normalized_fields"])
    provenance = json.loads(event["provenance"])
    if provenance.get("format") != "structured" or not isinstance(raw, dict):
        return None
    explicit = next(((key, raw[key]) for key in ("external_id", "id") if raw.get(key) is not None), None)
    if explicit is None or type(explicit[1]) not in {str, int} or not str(explicit[1]).strip():
        return None
    known_time = fields.get("event_time_known", any(raw.get(key) not in (None, "") for key in ("event_time", "timestamp", "time")))
    if known_time is not True:
        return None
    fields["event_time_known"] = True
    options = json.loads(job["autopsy_options"] or "{}")
    if job["source_id"] is not None:
        namespace = ["registered", job["source_id"]]
    else:
        label = options.get("source_label")
        if not isinstance(label, str) or label.strip() in {"", "file-import"}:
            label = raw.get("source")
        if not isinstance(label, str) or not label.strip() or label.strip() == "file-import" or len(label) > 100:
            return None
        namespace = ["declared", label]
    from .content_inspection import RESERVED_FIELDS

    # Derived inspection annotations are reproducible results, not source facts.
    facts = {
        key: event[key]
        for key in (
            "source",
            "source_type",
            "severity",
            "category",
            "event_type",
            "title",
            "description",
            "event_time",
            "source_ip",
            "destination_ip",
            "username",
            "hostname",
            "process_name",
            "parent_process",
            "file_hash",
            "http_status",
            "action",
            "outcome",
            "parser_version",
        )
    }
    facts.update(
        raw=raw,
        normalized={key: value for key, value in fields.items() if key not in RESERVED_FIELDS},
        tags=json.loads(event["tags"]),
        mitre_ids=json.loads(event["mitre_ids"]),
    )
    policy = {"mapping": options.get("mapping", {}), "source_timezone": options.get("source_timezone", "UTC")}
    if "source_year" in options:
        policy["source_year"] = options["source_year"]
    value = [1, job["workspace_id"], job["case_id"], job["training_run_id"], namespace, explicit, facts, policy]
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def occurrence_key(provenance, fallback):
    # A pointer distinguishes expanded structured rows sharing a physical line.
    return canonical([provenance.get("row", fallback), provenance.get("row_pointer")])


def retain_occurrence(connection, event_id, job, provenance, *, repeated, row_key=None):
    if job is None:
        return
    connection.execute(
        """INSERT OR IGNORE INTO autopsy_event_occurrences(case_id,job_id,event_id,row_key,provenance,disposition)
        VALUES (?,?,?,?,?,?)""",
        (
            job["case_id"],
            job["id"],
            event_id,
            row_key or occurrence_key(provenance, f"event:{event_id}"),
            canonical(provenance),
            "repeated" if repeated else "accepted",
        ),
    )
    connection.execute(
        """UPDATE security_events SET autopsy_active=EXISTS (
            SELECT 1 FROM autopsy_event_occurrences o JOIN ingestion_jobs j ON j.id=o.job_id
            WHERE o.event_id=security_events.id AND j.active_version=1) WHERE id=?""",
        (event_id,),
    )


def job_event_sql(alias="e"):
    if alias not in {"e", "ce", "f", "security_events", "case_events"}:
        raise ValueError("Unknown event SQL alias")
    key = "event_id" if alias in {"ce", "case_events"} else "id"
    return f"""(EXISTS (SELECT 1 FROM autopsy_event_occurrences o WHERE o.event_id={alias}.{key} AND o.job_id=?)
        OR (NOT EXISTS (SELECT 1 FROM autopsy_event_occurrences o WHERE o.event_id={alias}.{key}) AND {alias}.import_job_id=?))"""


def visible_provenance(connection, event_id, principal, job_id=None):
    """Select evidence metadata only from an occurrence this reader may see."""
    if not principal:
        return None
    clauses, args = ["o.event_id=?"], [event_id]
    if job_id is not None:
        clauses.append("o.job_id=?")
        args.append(job_id)
    if principal.get("role") not in {"admin", "soc_manager"}:
        clauses.append("(COALESCE(a.restricted,0)=0 OR j.created_by=? OR EXISTS (SELECT 1 FROM autopsy_batch_members m WHERE m.job_id=j.id AND m.user_id=?))")
        args.extend((principal["id"], principal["id"]))
    return connection.execute(
        "SELECT o.provenance,o.job_id,j.created_by,j.created_at,j.active_version FROM autopsy_event_occurrences o JOIN ingestion_jobs j ON j.id=o.job_id LEFT JOIN autopsy_batch_access a ON a.job_id=j.id WHERE "
        + " AND ".join(clauses)
        + " ORDER BY j.active_version DESC,o.job_id,o.row_key LIMIT 1",
        args,
    ).fetchone()


def restore_declared_identities(connection, case_id):
    """Re-scope declared evidence after restore, without reconnecting sources."""
    for job in connection.execute("SELECT * FROM ingestion_jobs WHERE case_id=? ORDER BY id", (case_id,)):
        options = json.loads(job["autopsy_options"])
        if options.get("capsule_source_kind") != "declared" or job["source_id"] is not None:
            continue
        rows = connection.execute(
            "SELECT e.*,o.provenance AS occurrence_provenance FROM autopsy_event_occurrences o JOIN security_events e ON e.id=o.event_id WHERE o.job_id=? ORDER BY e.id",
            (job["id"],),
        )
        for row in rows:
            event = {**dict(row), "provenance": row["occurrence_provenance"]}
            key = identity_key(event, job)
            if key:
                connection.execute("INSERT OR IGNORE INTO autopsy_event_identities(identity_key,event_id) VALUES (?,?)", (key, event["id"]))


def migrate(connection):
    connection.execute("""CREATE TABLE IF NOT EXISTS autopsy_event_identities(
        identity_key TEXT PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES security_events(id))""")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_event_identity_event ON autopsy_event_identities(event_id)")
    connection.execute("""CREATE TABLE IF NOT EXISTS autopsy_event_occurrences(
        case_id INTEGER NOT NULL REFERENCES incident_cases(id), job_id INTEGER NOT NULL REFERENCES ingestion_jobs(id),
        event_id INTEGER NOT NULL REFERENCES security_events(id), row_key TEXT NOT NULL, provenance TEXT NOT NULL,
        disposition TEXT NOT NULL CHECK(disposition IN ('accepted','repeated')), PRIMARY KEY(job_id,row_key))""")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_event_occurrence_event ON autopsy_event_occurrences(event_id,job_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_event_occurrence_case ON autopsy_event_occurrences(case_id,job_id,event_id)")
    if connection.execute("SELECT 1 FROM schema_meta WHERE key='event_occurrences'").fetchone():
        return
    # Never merge historical rows or change their IDs, alert links or reports.
    # Earliest matching row is used only for subsequent imports.
    for job in connection.execute("SELECT * FROM ingestion_jobs WHERE case_id IS NOT NULL ORDER BY id"):
        for event in connection.execute("SELECT * FROM security_events WHERE import_job_id=? ORDER BY id", (job["id"],)):
            provenance = json.loads(event["provenance"] or "{}")
            retain_occurrence(connection, event["id"], job, provenance, repeated=False, row_key=canonical(["historical", event["id"]]))
            key = identity_key(event, job)
            if key:
                connection.execute("INSERT OR IGNORE INTO autopsy_event_identities(identity_key,event_id) VALUES (?,?)", (key, event["id"]))
    connection.execute("INSERT INTO schema_meta(key,value,updated_at) VALUES ('event_occurrences','1',strftime('%Y-%m-%dT%H:%M:%fZ','now'))")
