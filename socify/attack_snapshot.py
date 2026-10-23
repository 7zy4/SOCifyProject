import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from .timeutils import iso_now

Technique = tuple[str, str, str, str, str, int, int, int]


def _parse_techniques(payload: object) -> list[Technique]:
    compact = payload.get("techniques") if isinstance(payload, dict) else None
    techniques: list[Technique] = []
    if isinstance(compact, list):
        for item in compact:
            if not isinstance(item, dict):
                continue
            tactics = item.get("tactics")
            if not isinstance(tactics, list):
                raise ValueError("compact ATT&CK techniques require a tactics list")
            techniques.append(
                (
                    str(item["technique_id"]).upper(),
                    str(item["name"]),
                    ",".join(sorted(str(value) for value in tactics)),
                    str(item.get("description") or ""),
                    str(item["source_url"]),
                    1 if item.get("is_subtechnique") else 0,
                    1 if item.get("deprecated") else 0,
                    1 if item.get("revoked") else 0,
                )
            )
    objects = payload.get("objects") if isinstance(payload, dict) else None
    if not techniques and not isinstance(objects, list):
        raise ValueError("STIX bundle objects are required")
    for item in objects or []:
        if not isinstance(item, dict) or item.get("type") != "attack-pattern":
            continue
        reference = next(
            (
                value
                for value in item.get("external_references", [])
                if isinstance(value, dict) and value.get("source_name") == "mitre-attack" and value.get("external_id")
            ),
            None,
        )
        if not reference:
            continue
        technique_id = str(reference["external_id"]).upper()
        if not technique_id.startswith("T"):
            continue
        tactics = sorted(
            {
                str(value.get("phase_name"))
                for value in item.get("kill_chain_phases", [])
                if isinstance(value, dict) and value.get("kill_chain_name") == "mitre-attack" and value.get("phase_name")
            }
        )
        techniques.append(
            (
                technique_id,
                str(item.get("name") or technique_id),
                ",".join(tactics) or "unknown",
                str(item.get("description") or ""),
                str(reference.get("url") or f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"),
                1 if item.get("x_mitre_is_subtechnique") else 0,
                1 if item.get("x_mitre_deprecated") else 0,
                1 if item.get("revoked") else 0,
            )
        )
    identifiers = [item[0] for item in techniques]
    if any(not re.fullmatch(r"T\d{4}(?:\.\d{3})?", value) for value in identifiers):
        raise ValueError("snapshot contains an invalid ATT&CK technique identifier")
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("snapshot contains duplicate ATT&CK technique identifiers")
    return sorted(techniques)


def _transition_counts(connection: sqlite3.Connection, old_version: str | None, new_version: str) -> dict[str, int]:
    keys = ("name", "tactic", "description", "source_url", "is_subtechnique", "deprecated", "revoked")
    new_rows = {
        row["technique_id"]: tuple(row[key] for key in keys)
        for row in connection.execute("SELECT * FROM attack_technique_versions WHERE version = ?", (new_version,)).fetchall()
    }
    old_rows: dict[str, tuple[Any, ...]] = {}
    if old_version:
        old_rows = {
            row["technique_id"]: tuple(row[key] for key in keys)
            for row in connection.execute("SELECT * FROM attack_technique_versions WHERE version = ?", (old_version,)).fetchall()
        }
    shared = old_rows.keys() & new_rows.keys()
    return {
        "added": len(new_rows.keys() - old_rows.keys()),
        "removed": len(old_rows.keys() - new_rows.keys()),
        "changed": sum(old_rows[key] != new_rows[key] for key in shared),
        "deprecated": sum(value[-2] == 1 for value in new_rows.values()),
        "revoked": sum(value[-1] == 1 for value in new_rows.values()),
    }


def _activate(connection: sqlite3.Connection, version: str) -> bool:
    catalog = connection.execute("SELECT * FROM attack_catalog_versions WHERE version = ?", (version,)).fetchone()
    if not catalog:
        raise ValueError("ATT&CK catalog version does not exist")
    active = connection.execute("SELECT version FROM attack_catalog_versions WHERE active = 1").fetchone()
    old_version = str(active["version"]) if active else None
    if old_version == version:
        return False
    counts = _transition_counts(connection, old_version, version)
    now = iso_now()
    connection.execute("UPDATE attack_catalog_versions SET active = CASE WHEN version = ? THEN 1 ELSE 0 END", (version,))
    connection.execute("DELETE FROM attack_techniques")
    connection.execute(
        """INSERT INTO attack_techniques
        (technique_id, name, tactic, description, source_url, attack_version, is_subtechnique, deprecated, revoked)
        SELECT technique_id, name, tactic, description, source_url, version, is_subtechnique, deprecated, revoked
        FROM attack_technique_versions WHERE version = ?""",
        (version,),
    )
    metadata = {
        "attack_version": version,
        "attack_snapshot_count": str(catalog["technique_count"]),
        "attack_snapshot_source": str(catalog["source_url"]),
        "attack_snapshot_sha256": str(catalog["source_sha256"]),
    }
    connection.executemany(
        "INSERT INTO schema_meta (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        [(key, value, now) for key, value in metadata.items()],
    )
    connection.execute(
        """INSERT INTO attack_catalog_transitions
        (from_version, to_version, added_count, removed_count, changed_count, deprecated_count, revoked_count, activated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (old_version, version, counts["added"], counts["removed"], counts["changed"], counts["deprecated"], counts["revoked"], now),
    )
    return True


def activate_attack_version(connection: sqlite3.Connection, version: str) -> bool:
    connection.execute("BEGIN IMMEDIATE")
    try:
        changed = _activate(connection, version)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return changed


def load_stix_snapshot(connection: sqlite3.Connection, filename: str, version: str, allow_partial: bool = False) -> int:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", version):
        raise ValueError("invalid ATT&CK catalog version")
    path = Path(filename)
    raw = path.read_bytes()
    payload = json.loads(raw)
    techniques = _parse_techniques(payload)
    if not techniques or (not allow_partial and len(techniques) < 600):
        raise ValueError("snapshot does not contain a complete Enterprise ATT&CK technique set")
    digest = hashlib.sha256(raw).hexdigest()
    declared_source = payload.get("source_url") if isinstance(payload, dict) else None
    source = str(declared_source or path.resolve().as_uri())
    connection.execute("BEGIN IMMEDIATE")
    try:
        existing = connection.execute("SELECT source_sha256 FROM attack_catalog_versions WHERE version = ?", (version,)).fetchone()
        if existing and existing["source_sha256"] != digest:
            raise ValueError("ATT&CK catalog version already exists with different content")
        if not existing:
            connection.execute(
                "INSERT INTO attack_catalog_versions (version, source_url, source_sha256, technique_count, imported_at, active) VALUES (?, ?, ?, ?, ?, 0)",
                (version, source, digest, len(techniques), iso_now()),
            )
            connection.executemany(
                """INSERT INTO attack_technique_versions
                (version, technique_id, name, tactic, description, source_url, is_subtechnique, deprecated, revoked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [(version, *technique) for technique in techniques],
            )
        _activate(connection, version)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return len(techniques)
