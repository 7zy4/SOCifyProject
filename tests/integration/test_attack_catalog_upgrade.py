import json
import sqlite3
from pathlib import Path

from socify.attack_snapshot import load_stix_snapshot
from socify.schema import ensure_schema


def test_explicit_attack_upgrade_survives_multiple_schema_starts(database: sqlite3.Connection, tmp_path: Path) -> None:
    path = tmp_path / "attack-versioned.json"
    path.write_text(
        json.dumps(
            {
                "techniques": [
                    {
                        "technique_id": "T1110",
                        "name": "Brute Force - Imported Version",
                        "tactics": ["credential-access"],
                        "description": "Explicitly imported catalog entry",
                        "source_url": "https://attack.mitre.org/techniques/T1110/",
                        "is_subtechnique": False,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    assert load_stix_snapshot(database, str(path), "99.99-test", allow_partial=True) == 1
    for _ in range(3):
        ensure_schema(database)
        row = database.execute("SELECT name, attack_version FROM attack_techniques WHERE technique_id = 'T1110'").fetchone()
        version = database.execute("SELECT value FROM schema_meta WHERE key = 'attack_version'").fetchone()
        assert row["name"] == "Brute Force - Imported Version"
        assert row["attack_version"] == "99.99-test"
        assert version["value"] == "99.99-test"
