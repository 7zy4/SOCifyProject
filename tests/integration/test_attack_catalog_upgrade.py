import json
import sqlite3
from pathlib import Path

import pytest

from socify.attack_snapshot import activate_attack_version, load_stix_snapshot
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


def _write_catalog(path: Path, techniques: list[dict[str, object]]) -> None:
    path.write_text(json.dumps({"source_url": "https://attack.mitre.org/", "techniques": techniques}), encoding="utf-8")


def test_catalog_upgrade_tracks_transition_and_supports_rollback(database: sqlite3.Connection, tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    _write_catalog(
        first,
        [
            {
                "technique_id": "T1110",
                "name": "Brute Force v1",
                "tactics": ["credential-access"],
                "source_url": "https://attack.mitre.org/techniques/T1110/",
            }
        ],
    )
    _write_catalog(
        second,
        [
            {
                "technique_id": "T1110",
                "name": "Brute Force v2",
                "tactics": ["credential-access"],
                "source_url": "https://attack.mitre.org/techniques/T1110/",
                "deprecated": True,
            },
            {
                "technique_id": "T1059.001",
                "name": "PowerShell",
                "tactics": ["execution"],
                "source_url": "https://attack.mitre.org/techniques/T1059/001/",
                "is_subtechnique": True,
                "revoked": True,
            },
        ],
    )
    load_stix_snapshot(database, str(first), "test-1", allow_partial=True)
    load_stix_snapshot(database, str(second), "test-2", allow_partial=True)

    active = database.execute("SELECT version, technique_count FROM attack_catalog_versions WHERE active = 1").fetchone()
    assert dict(active) == {"version": "test-2", "technique_count": 2}
    current = database.execute("SELECT technique_id, attack_version, deprecated, revoked FROM attack_techniques ORDER BY technique_id").fetchall()
    assert [dict(row) for row in current] == [
        {"technique_id": "T1059.001", "attack_version": "test-2", "deprecated": 0, "revoked": 1},
        {"technique_id": "T1110", "attack_version": "test-2", "deprecated": 1, "revoked": 0},
    ]
    transition = database.execute("SELECT * FROM attack_catalog_transitions ORDER BY id DESC LIMIT 1").fetchone()
    assert transition["from_version"] == "test-1"
    assert transition["to_version"] == "test-2"
    assert transition["added_count"] == 1
    assert transition["changed_count"] == 1
    assert transition["deprecated_count"] == 1
    assert transition["revoked_count"] == 1

    assert activate_attack_version(database, "test-1") is True
    restored = database.execute("SELECT name, attack_version FROM attack_techniques").fetchone()
    assert dict(restored) == {"name": "Brute Force v1", "attack_version": "test-1"}
    assert database.execute("SELECT COUNT(*) FROM attack_technique_versions WHERE version = 'test-2'").fetchone()[0] == 2


def test_catalog_version_is_immutable(database: sqlite3.Connection, tmp_path: Path) -> None:
    snapshot = tmp_path / "catalog.json"
    technique = {
        "technique_id": "T1110",
        "name": "Original",
        "tactics": ["credential-access"],
        "source_url": "https://attack.mitre.org/techniques/T1110/",
    }
    _write_catalog(snapshot, [technique])
    load_stix_snapshot(database, str(snapshot), "immutable", allow_partial=True)
    _write_catalog(snapshot, [{**technique, "name": "Tampered"}])
    with pytest.raises(ValueError, match="different content"):
        load_stix_snapshot(database, str(snapshot), "immutable", allow_partial=True)
    assert database.execute("SELECT name FROM attack_techniques WHERE technique_id = 'T1110'").fetchone()[0] == "Original"
