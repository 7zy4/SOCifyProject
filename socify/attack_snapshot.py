import json
import sqlite3
from pathlib import Path

from .timeutils import iso_now


def load_stix_snapshot(connection: sqlite3.Connection, filename: str, version: str, allow_partial: bool = False) -> int:
    path = Path(filename)
    payload = json.loads(path.read_text(encoding="utf-8"))
    compact = payload.get("techniques") if isinstance(payload, dict) else None
    if isinstance(compact, list):
        techniques = [
            (
                str(item["technique_id"]),
                str(item["name"]),
                ",".join(str(value) for value in item["tactics"]),
                str(item.get("description") or ""),
                str(item["source_url"]),
                version,
                1 if item.get("is_subtechnique") else 0,
                0,
                0,
            )
            for item in compact
            if isinstance(item, dict)
        ]
    else:
        techniques = []
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
        technique_id = str(reference["external_id"])
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
                version,
                1 if item.get("x_mitre_is_subtechnique") else 0,
                1 if item.get("x_mitre_deprecated") else 0,
                1 if item.get("revoked") else 0,
            )
        )
    if not techniques or not allow_partial and len(techniques) < 600:
        raise ValueError("snapshot does not contain a complete Enterprise ATT&CK technique set")
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.executemany(
            """INSERT INTO attack_techniques
            (technique_id, name, tactic, description, source_url, attack_version, is_subtechnique, deprecated, revoked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(technique_id) DO UPDATE SET name = excluded.name, tactic = excluded.tactic,
            description = excluded.description, source_url = excluded.source_url, attack_version = excluded.attack_version,
            is_subtechnique = excluded.is_subtechnique, deprecated = excluded.deprecated, revoked = excluded.revoked""",
            techniques,
        )
        connection.execute(
            "INSERT INTO schema_meta (key, value, updated_at) VALUES ('attack_version', ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            (version, iso_now()),
        )
        connection.execute(
            "INSERT INTO schema_meta (key, value, updated_at) VALUES ('attack_snapshot_count', ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            (str(len(techniques)), iso_now()),
        )
        connection.execute(
            "INSERT INTO schema_meta (key, value, updated_at) VALUES ('attack_snapshot_source', ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            (str(path.resolve()), iso_now()),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return len(techniques)
