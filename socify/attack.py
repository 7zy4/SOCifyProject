from .db import get_db


def _metadata() -> dict[str, object]:
    values = {
        row["key"]: row["value"]
        for row in get_db()
        .execute(
            "SELECT key, value FROM schema_meta WHERE key IN ('attack_version', 'attack_snapshot_count', 'attack_snapshot_source', 'attack_snapshot_sha256')"
        )
        .fetchall()
    }
    count = int(get_db().execute("SELECT COUNT(*) FROM attack_techniques").fetchone()[0])
    return {
        "attack_version": values.get("attack_version", "unknown"),
        "snapshot_count": int(values.get("attack_snapshot_count", count)),
        "snapshot_source": values.get("attack_snapshot_source", "unknown"),
        "snapshot_sha256": values.get("attack_snapshot_sha256", "unknown"),
        "offline_snapshot": True,
    }
