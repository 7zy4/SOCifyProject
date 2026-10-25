import argparse
import gzip
import hashlib
import json
import sqlite3
import tempfile
from pathlib import Path

from socify import create_app
from socify.cases import _generate_reports
from socify.db import connect_path
from socify.seeding import seed_demo_data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="socify-v2-fixture-") as directory:
        path = Path(directory) / "legacy.db"
        app = create_app(
            {"DATABASE": str(path), "TESTING": True, "WTF_CSRF_ENABLED": False, "SECRET_KEY": "test-session-key", "CREDENTIAL_KEY": "test-credential-key"}
        )
        connection = connect_path(str(path), True)
        seed_demo_data(connection, "Training-Safe-Password-2026!")
        identifier = connection.execute("SELECT id FROM users WHERE role='analyst'").fetchone()[0]
        client = app.test_client()
        with client.session_transaction() as state:
            state.update(user_id=identifier, workspace_id=1)
        content = "\n".join(
            json.dumps(
                {
                    "source": "v2-migration-fixture",
                    "event_type": "retained_access",
                    "severity": "high",
                    "title": f"Synthetic V2 retained event {index}",
                    "event_time": f"2026-10-20T10:00:0{index}Z",
                    "source_ip": "192.0.2.40",
                }
            )
            for index in range(2)
        )
        imported = client.post("/api/imports", json={"filename": "retained-v2.jsonl", "format": "jsonl", "content": content})
        assert imported.status_code in {200, 201, 202}, imported.json
        events = [row[0] for row in connection.execute("SELECT id FROM security_events WHERE source='v2-migration-fixture'")]
        assert len(events) == 2
        created = client.post("/api/incidents", json={"title": "Historical V2 investigation", "event_ids": events, "severity": "high"})
        assert created.status_code == 201, created.json
        case_id = created.json["id"]
        evidence = client.post(
            f"/api/incidents/{case_id}/evidence",
            json={
                "type": "raw_log",
                "reference_id": "v2-local-evidence",
                "title": "Preserved V2 evidence",
                "content": "Synthetic original evidence with Arabic: دليل محفوظ",
            },
        )
        assert evidence.status_code == 201, evidence.json
        assert client.post(f"/api/incidents/{case_id}/notes", json={"body": "Historical investigator conclusion", "visibility": "team"}).status_code == 201
        assert (
            client.post(
                f"/api/incidents/{case_id}/tasks", json={"title": "Retain historical review task", "required": True, "assignee": identifier}
            ).status_code
            == 201
        )
        with client:
            client.get(f"/api/incidents/{case_id}")
            _generate_reports(case_id)
        connection.close()
        with sqlite3.connect(path) as final:
            final.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        raw = path.read_bytes()
        options.output.parent.mkdir(parents=True, exist_ok=True)
        with options.output.open("wb") as target, gzip.GzipFile(fileobj=target, mode="wb", mtime=0, filename="") as compressed:
            compressed.write(raw)
        metadata = {
            "source_commit": "ee50518ce3b1d0fb5a09215f4644fb3d9f416d83",
            "schema_origin": "Actual socify-version-2 code from git archive; no V3 imports",
            "synthetic_only": True,
            "credential_key": "test-credential-key",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "compressed_sha256": hashlib.sha256(options.output.read_bytes()).hexdigest(),
            "case_id": case_id,
            "import_id": imported.json["id"],
            "event_ids": events,
            "evidence_id": evidence.json["id"],
            "import_plaintext_sha256": hashlib.sha256(content.encode()).hexdigest(),
        }
        options.output.with_suffix(".manifest.json").write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    main()
