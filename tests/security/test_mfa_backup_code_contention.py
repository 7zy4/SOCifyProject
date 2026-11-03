import hashlib
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from socify import auth, recovery_codes


def test_recovery_code_can_only_be_consumed_once_after_concurrent_reads(app, database, user_ids, monkeypatch):
    code = "AB" * 5
    user_id = user_ids["analyst"]
    database.execute(
        "INSERT INTO mfa_backup_codes(user_id, code_hash, created_at) VALUES (?, ?, ?)",
        (user_id, hashlib.sha256(code.encode()).hexdigest(), "2026-10-26T00:00:00Z"),
    )
    recovery_codes.protect_existing_recovery_codes(database)
    readers = Barrier(2)
    compare = recovery_codes.bcrypt.checkpw

    def compare_after_both_reads(left, right):
        matched = compare(left, right)
        readers.wait(timeout=10)
        return matched

    monkeypatch.setattr(recovery_codes.bcrypt, "checkpw", compare_after_both_reads)

    def consume():
        with app.app_context():
            return auth._backup_code_valid(user_id, "  " + code.lower() + "  ")

    with ThreadPoolExecutor(max_workers=2) as executor:
        attempts = [executor.submit(consume) for _ in range(2)]
        assert sorted(attempt.result(timeout=15) for attempt in attempts) == [False, True]

    monkeypatch.setattr(recovery_codes.bcrypt, "checkpw", compare)
    with app.app_context():
        assert auth._backup_code_valid(user_id, code) is False
    assert database.execute("SELECT consumed_at FROM mfa_backup_codes WHERE user_id = ?", (user_id,)).fetchone()[0] is not None
