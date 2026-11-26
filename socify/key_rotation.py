"""Re-encrypt every stored ciphertext with the current credential key.

Rotation: set SOCIFY_CREDENTIAL_KEY to the new key and SOCIFY_CREDENTIAL_KEY_PREVIOUS to the old one, restart, run
``python -m scripts.rotate_credential_key`` and, once it reports nothing left under the previous key, remove
SOCIFY_CREDENTIAL_KEY_PREVIOUS. The plaintext of evidence never changes; only the key that protects it does.
"""

import sqlite3

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from .security import BINARY_MARKER, fernet_for

# Every column that holds a Fernet token; these fixed names are the only identifiers interpolated into SQL below. tests/security/test_key_rotation.py fails when the schema gains one that is not listed.
ENCRYPTED_COLUMNS: tuple[tuple[str, str], ...] = (
    ("mfa_enrollments", "secret_ciphertext"),
    ("event_sources", "credential_ciphertext"),
    ("case_evidence_content", "ciphertext"),
    ("ingestion_jobs", "evidence_ciphertext"),
    ("autopsy_samples", "ciphertext"),
    ("autopsy_report_files", "content"),
    ("autopsy_capsule_archives", "ciphertext"),
    ("intake_integrations", "hmac_secret_ciphertext"),
    ("intake_alerts", "raw_ciphertext"),
)


class RotationError(RuntimeError):
    """A stored value could not be decrypted with either key; nothing was changed."""


def _token(value: str | bytes) -> tuple[bytes, str]:
    """Split a stored value into its Fernet token and the marker to keep in front of the re-encrypted token."""
    raw = value.encode() if isinstance(value, str) else bytes(value)
    marker = BINARY_MARKER.encode()
    return (raw[len(marker) :], BINARY_MARKER) if raw.startswith(marker) else (raw, "")


def _stored(original: str | bytes, marker: str, token: bytes) -> str | bytes:
    return marker + token.decode() if isinstance(original, str) else marker.encode() + token


def _uses_current(current: Fernet, token: bytes) -> bool:
    try:
        current.decrypt(token)
    except InvalidToken:
        return False
    return True


def survey(connection: sqlite3.Connection, current_key: str | bytes) -> dict[str, dict[str, int]]:
    """Count, per column, the values already under the current key and the values that still need the previous one."""
    current = fernet_for(current_key)
    report = {}
    for table, column in ENCRYPTED_COLUMNS:
        counts = {"current": 0, "previous": 0}
        for (value,) in connection.execute(f"SELECT {column} FROM {table} WHERE {column} IS NOT NULL AND {column} <> ''"):  # nosec B608
            counts["current" if _uses_current(current, _token(value)[0]) else "previous"] += 1
        report[f"{table}.{column}"] = counts
    return report


def rotate(connection: sqlite3.Connection, current_key: str | bytes, previous_key: str | bytes) -> dict[str, dict[str, int]]:
    """Re-encrypt values held under the previous key, in one transaction, verifying each plaintext is unchanged.

    Evidence tables refuse updates through triggers. Those triggers are lifted for this transaction only and restored
    before it commits; any failure rolls everything back, triggers included.
    """
    current, previous = fernet_for(current_key), fernet_for(previous_key)
    both = MultiFernet([current, previous])
    report: dict[str, dict[str, int]] = {}
    connection.execute("BEGIN IMMEDIATE")
    try:
        for table, column in ENCRYPTED_COLUMNS:
            guards = connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ? AND sql LIKE '%BEFORE UPDATE%'", (table,)
            ).fetchall()
            for name, _sql in guards:
                connection.execute(f'DROP TRIGGER "{name}"')
            counts = {"rotated": 0, "already_current": 0}
            rows = connection.execute(f"SELECT rowid, {column} FROM {table} WHERE {column} IS NOT NULL AND {column} <> ''").fetchall()  # nosec B608
            for rowid, value in rows:
                token, marker = _token(value)
                if _uses_current(current, token):
                    counts["already_current"] += 1
                    continue
                try:
                    plaintext = both.decrypt(token)
                except InvalidToken as exc:
                    raise RotationError(f"{table}.{column} row {rowid} cannot be decrypted with the current or the previous key") from exc
                replacement = current.encrypt(plaintext)
                if current.decrypt(replacement) != plaintext:
                    raise RotationError(f"{table}.{column} row {rowid} did not survive re-encryption")
                connection.execute(f"UPDATE {table} SET {column} = ? WHERE rowid = ?", (_stored(value, marker, replacement), rowid))  # nosec B608
                counts["rotated"] += 1
            for _name, sql in guards:
                connection.execute(sql)
            report[f"{table}.{column}"] = counts
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return report
