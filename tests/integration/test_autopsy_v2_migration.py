import base64
import gzip
import hashlib
import json
from pathlib import Path

from socify import create_app
from socify.db import connect_path
from socify.operations import backup_database, migration_dry_run, restore_database, verify_database
from socify.schema import ensure_schema
from socify.security import cipher

FIXTURE = Path(__file__).parents[1] / "fixtures" / "v2" / "synthetic-v2.db.gz"
PRESERVED = (
    "users",
    "workspace_memberships",
    "training_scenarios",
    "security_events",
    "ingestion_jobs",
    "incident_cases",
    "case_events",
    "case_evidence",
    "case_evidence_content",
    "case_reports",
    "case_history",
    "case_notes",
    "case_tasks",
)


def test_actual_v2_database_migration_preserves_evidence_reports_relations_and_backup_restore(tmp_path):
    metadata = json.loads(FIXTURE.with_suffix(".manifest.json").read_text())
    compressed = FIXTURE.read_bytes()
    assert hashlib.sha256(compressed).hexdigest() == metadata["compressed_sha256"]
    content = gzip.decompress(compressed)
    assert hashlib.sha256(content).hexdigest() == metadata["sha256"]
    original, migrated, backup, restored = [tmp_path / name for name in ("original-v2.db", "upgrade.db", "backup-v2.db", "rollback.db")]
    original.write_bytes(content)
    connection = connect_path(str(original), True)
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "autopsy_case_context" not in tables
    snapshots = {}
    for table in PRESERVED:
        if table in tables:
            columns = [row["name"] for row in connection.execute(f"PRAGMA table_info({table})")]
            snapshots[table] = (columns, [tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid")])
    assert len(snapshots["case_reports"][1]) == 2
    assert len(snapshots["case_events"][1]) == 2
    assert snapshots["case_evidence_content"][1]
    connection.close()
    assert backup_database(str(original), str(backup))["integrity"] == "ok"
    assert migration_dry_run(str(original))["foreign_key_violations"] == 0
    assert original.read_bytes() == content
    backup_database(str(original), str(migrated))
    connection = connect_path(str(migrated), True)
    ensure_schema(connection)
    ensure_schema(connection)
    for table, (columns, rows) in snapshots.items():
        projection = ",".join(f'"{column}"' for column in columns)
        assert [tuple(row) for row in connection.execute(f"SELECT {projection} FROM {table} ORDER BY rowid")] == rows, table
    assert connection.execute("SELECT value FROM schema_meta WHERE key='autopsy_schema_version'").fetchone()[0] == "3"
    assert all(row[0] == 1 for row in connection.execute("SELECT active_event FROM case_events"))
    connection.close()
    assert verify_database(str(migrated))["foreign_key_violations"] == 0
    app = create_app(
        {
            "DATABASE": str(migrated),
            "TESTING": True,
            "LEGACY_TRAINING_TESTS": False,
            "WTF_CSRF_ENABLED": False,
            "SECRET_KEY": "test-session-key",
            "CREDENTIAL_KEY": metadata["credential_key"],
        }
    )
    with app.app_context():
        connection = connect_path(str(migrated), True)
        raw = connection.execute("SELECT evidence_ciphertext FROM ingestion_jobs WHERE id=?", (metadata["import_id"],)).fetchone()[0]
        assert hashlib.sha256(base64.b64decode(cipher().decrypt(raw), validate=True)).hexdigest() == metadata["import_plaintext_sha256"]
        encrypted = connection.execute(
            "SELECT e.sha256,c.ciphertext FROM case_evidence e JOIN case_evidence_content c ON c.evidence_id=e.id WHERE e.id=?", (metadata["evidence_id"],)
        ).fetchone()
        assert hashlib.sha256(cipher().decrypt(encrypted["ciphertext"])).hexdigest() == encrypted["sha256"]
        actor = connection.execute("SELECT id FROM users WHERE role='analyst'").fetchone()[0]
        connection.close()
    client = app.test_client()
    with client.session_transaction() as state:
        state.update(user_id=actor, workspace_id=1)
    assert client.get(f"/api/cases/{metadata['case_id']}").status_code == 200
    assert client.get(f"/api/cases/{metadata['case_id']}").json["approval"]["source"] == "v3_migration"
    assert client.post("/api/investigation-selection", json={"case_ids": [metadata["case_id"]]}).status_code == 200
    assert client.get(f"/api/cases/{metadata['case_id']}/logs").json["total"] == 2
    assert client.get("/api/training/scenarios").status_code == 410
    assert restore_database(str(backup), str(restored))["integrity"] == "ok"
    connection = connect_path(str(restored), True)
    assert not connection.execute("SELECT 1 FROM sqlite_master WHERE name='autopsy_case_context'").fetchone()
    for table, (_columns, rows) in snapshots.items():
        assert [tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid")] == rows
    connection.close()
