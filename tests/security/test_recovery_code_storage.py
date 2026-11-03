import hashlib

import pytest

from socify.auth import _backup_code_valid
from socify.recovery_codes import LEGACY_PREFIX, hash_recovery_code, verify_recovery_code
from socify.schema import ensure_schema


def test_new_recovery_verifiers_are_salted_and_slow():
    code = "7AF3" * 8
    first, second = hash_recovery_code(code), hash_recovery_code(code)
    assert first.startswith("$2b$12$") and second.startswith("$2b$12$") and first != second
    assert code not in first and hashlib.sha256(code.encode()).hexdigest() not in first
    assert verify_recovery_code("  " + code.lower() + "  ", first)
    assert not verify_recovery_code("7AF2" * 8, first)


def test_existing_codes_are_protected_on_schema_upgrade_and_still_single_use(app, database, user_ids):
    code = "AB1234CD56"  # pragma: allowlist secret -- synthetic recovery fixture, never an account credential
    digest = hashlib.sha256(code.encode()).hexdigest()
    identifier = database.execute(
        "INSERT INTO mfa_backup_codes(user_id, code_hash, created_at) VALUES (?, ?, '2026-11-03T00:00:00Z') RETURNING id",
        (user_ids["analyst"], digest),
    ).fetchone()[0]
    ensure_schema(database)
    protected = database.execute("SELECT code_hash FROM mfa_backup_codes WHERE id=?", (identifier,)).fetchone()[0]
    assert protected.startswith(LEGACY_PREFIX + "$2b$12$") and digest not in protected
    ensure_schema(database)
    assert database.execute("SELECT code_hash FROM mfa_backup_codes WHERE id=?", (identifier,)).fetchone()[0] == protected
    with app.app_context():
        assert _backup_code_valid(user_ids["analyst"], code)
        assert not _backup_code_valid(user_ids["analyst"], code)


@pytest.mark.parametrize(
    "code",
    ["", "1" * 6, "a" * 31, "a" * 33, "a" * 100000, "\ud800" * 32, "Z" * 32, "é" * 32],
    ids=["empty", "totp", "short", "long", "oversized", "surrogates", "nonhex", "nonascii"],
)
def test_invalid_recovery_inputs_are_rejected_before_expensive_verification(code):
    assert not verify_recovery_code(code, "$2b$malformed")


def test_raw_legacy_digest_is_never_accepted_as_a_password_verifier():
    code = "AB1234CD56"  # pragma: allowlist secret -- synthetic recovery fixture, never an account credential
    assert not verify_recovery_code(code, hashlib.sha256(code.encode()).hexdigest())
