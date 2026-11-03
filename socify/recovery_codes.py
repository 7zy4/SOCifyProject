"""Salted recovery-code verifiers, including protection of existing digests."""

import hashlib
import sqlite3

import bcrypt

LEGACY_PREFIX = "bcrypt-sha256$"


def hash_recovery_code(code: str) -> str:
    return bcrypt.hashpw(code.strip().upper().encode("ascii"), bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_recovery_code(code: str, encoded: str) -> bool:
    normalized = code.strip().upper()
    if len(normalized) not in {10, 32} or any(char not in "0123456789ABCDEF" for char in normalized):
        return False
    supplied = normalized.encode("ascii")
    if encoded.startswith(LEGACY_PREFIX):
        # Old codes cannot be recovered from their digests. Their existing
        # digests are wrapped in salted bcrypt at migration; SHA-256 is only
        # the compatibility prehash, never the persisted password verifier.
        supplied = hashlib.sha256(supplied).hexdigest().encode("ascii")
        encoded = encoded[len(LEGACY_PREFIX) :]
    elif not encoded.startswith(("$2b$", "$2a$")):
        return False
    try:
        return bcrypt.checkpw(supplied, encoded.encode("ascii"))
    except (ValueError, UnicodeError):
        return False


def protect_existing_recovery_codes(connection: sqlite3.Connection) -> None:
    for row in connection.execute("SELECT id, code_hash FROM mfa_backup_codes WHERE length(code_hash)=64 AND consumed_at IS NULL").fetchall():
        identifier, digest = row[0], row[1]
        if any(char not in "0123456789abcdef" for char in digest):
            continue
        protected = LEGACY_PREFIX + bcrypt.hashpw(digest.encode("ascii"), bcrypt.gensalt(rounds=12)).decode("ascii")
        connection.execute("UPDATE mfa_backup_codes SET code_hash=? WHERE id=? AND code_hash=?", (protected, identifier, digest))
