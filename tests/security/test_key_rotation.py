import base64
import hashlib
import sqlite3

import pytest

from socify import create_app
from socify.key_rotation import ENCRYPTED_COLUMNS, RotationError, rotate, survey
from socify.security import decrypt_bytes, decrypt_secret, encrypt_bytes, encrypt_secret, fernet_for

OLD, NEW = "previous-credential-key", "current-credential-key"  # pragma: allowlist secret


def _app(app, key, previous=None):
    base = {name: app.config[name] for name in ("DATABASE", "TESTING", "WTF_CSRF_ENABLED", "SECRET_KEY")}
    return create_app({**base, "CREDENTIAL_KEY": key, "CREDENTIAL_KEY_PREVIOUS": previous})


def test_every_ciphertext_column_in_the_schema_is_rotated(database):
    found = set()
    for (table,) in database.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall():
        for column in database.execute(f"PRAGMA table_info({table})").fetchall():
            if "ciphertext" in column[1]:
                found.add((table, column[1]))
    assert found | {("autopsy_report_files", "content")} == set(ENCRYPTED_COLUMNS)


def test_previous_key_reads_old_values_and_new_values_use_the_current_key(app):
    with _app(app, OLD).app_context():
        text, binary = encrypt_secret("source credential"), encrypt_bytes(b"\x00raw evidence\xff")
    with _app(app, NEW).app_context():
        with pytest.raises(ValueError, match="cannot be decrypted"):
            decrypt_secret(text)
        with pytest.raises(ValueError, match="cannot be decrypted"):
            decrypt_bytes(binary)
    with _app(app, NEW, OLD).app_context():
        assert decrypt_secret(text) == "source credential" and decrypt_bytes(binary) == b"\x00raw evidence\xff"
        fresh = encrypt_secret("written during rotation")
    with _app(app, NEW).app_context():
        assert decrypt_secret(fresh) == "written during rotation"


def test_binary_evidence_is_stored_once_and_legacy_base64_rows_still_open(app):
    content = bytes(range(256)) * 400
    with app.app_context():
        stored = encrypt_bytes(content)
        legacy = encrypt_secret(base64.b64encode(content).decode())
        assert decrypt_bytes(stored) == content and decrypt_bytes(legacy) == content
        assert len(stored) < 0.8 * len(legacy)
        # Content that is itself base64 text must come back unchanged, not decoded a second time.
        assert decrypt_bytes(encrypt_bytes(b"QUJDRA==")) == b"QUJDRA=="


def test_rotation_moves_every_value_to_the_current_key_and_keeps_plaintext_and_triggers(app, database, user_ids):
    key = app.config["CREDENTIAL_KEY"]
    evidence = b"\x00\x01 rotation evidence \xfe\xff"
    with app.app_context():
        from socify.security import cipher

        secret, marked, sample = encrypt_secret("JBSWY3DPEHPK3PXP"), encrypt_bytes(evidence), cipher().encrypt(evidence)
    database.execute("PRAGMA foreign_keys = OFF")  # the rows below stand alone; rotation never follows references
    for user, value in ((user_ids["analyst"], secret), (user_ids["admin"], marked)):
        database.execute("INSERT INTO mfa_enrollments(user_id, secret_ciphertext, enabled, updated_at) VALUES (?, ?, 1, '2026-01-01T00:00:00Z')", (user, value))
    database.execute(
        "INSERT INTO autopsy_samples(case_id, evidence_id, filename, sha256, size, ciphertext, created_by, created_at) VALUES (1, 1, 'rotation.bin', ?, ?, ?, ?, '2026-01-01T00:00:00Z')",
        (hashlib.sha256(evidence).hexdigest(), len(evidence), sample, user_ids["admin"]),
    )
    triggers = database.execute("SELECT name, sql FROM sqlite_master WHERE type = 'trigger' ORDER BY name").fetchall()
    before = survey(database, key)
    assert before["mfa_enrollments.secret_ciphertext"] == {"current": 2, "previous": 0} and before["autopsy_samples.ciphertext"] == {
        "current": 1,
        "previous": 0,
    }
    waiting = survey(database, NEW)
    assert waiting["mfa_enrollments.secret_ciphertext"] == {"current": 0, "previous": 2}

    report = rotate(database, NEW, key)
    assert report["mfa_enrollments.secret_ciphertext"] == {"rotated": 2, "already_current": 0}
    assert report["autopsy_samples.ciphertext"] == {"rotated": 1, "already_current": 0}
    assert all(counts["previous"] == 0 for counts in survey(database, NEW).values())
    assert database.execute("SELECT name, sql FROM sqlite_master WHERE type = 'trigger' ORDER BY name").fetchall() == triggers
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        database.execute("UPDATE autopsy_samples SET filename = 'changed'")
    stored = database.execute("SELECT ciphertext FROM autopsy_samples WHERE filename = 'rotation.bin'").fetchone()[0]
    assert isinstance(stored, bytes) and fernet_for(NEW).decrypt(stored) == evidence
    rows = dict(database.execute("SELECT user_id, secret_ciphertext FROM mfa_enrollments").fetchall())
    with _app(app, NEW).app_context():
        assert decrypt_secret(rows[user_ids["analyst"]]) == "JBSWY3DPEHPK3PXP"
        assert rows[user_ids["admin"]].startswith("b1:") and decrypt_bytes(rows[user_ids["admin"]]) == evidence
    assert rotate(database, NEW, key)["autopsy_samples.ciphertext"] == {"rotated": 0, "already_current": 1}


def test_rotation_changes_nothing_when_a_value_fits_neither_key(app, database, user_ids):
    key = app.config["CREDENTIAL_KEY"]
    with app.app_context():
        good = encrypt_secret("JBSWY3DPEHPK3PXP")
    database.execute(
        "INSERT INTO mfa_enrollments(user_id, secret_ciphertext, enabled, updated_at) VALUES (?, ?, 1, '2026-01-01T00:00:00Z')", (user_ids["analyst"], good)
    )
    foreign = fernet_for("some-other-key").encrypt(b"lost").decode()
    database.execute(
        "INSERT INTO mfa_enrollments(user_id, secret_ciphertext, enabled, updated_at) VALUES (?, ?, 1, '2026-01-01T00:00:00Z')", (user_ids["admin"], foreign)
    )
    with pytest.raises(RotationError, match="mfa_enrollments.secret_ciphertext"):
        rotate(database, NEW, key)
    rows = dict(database.execute("SELECT user_id, secret_ciphertext FROM mfa_enrollments").fetchall())
    assert rows == {user_ids["analyst"]: good, user_ids["admin"]: foreign}
    assert not database.in_transaction
