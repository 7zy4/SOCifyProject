import hashlib
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from socify import auth


def test_recovery_code_can_only_be_consumed_once_after_concurrent_reads(app, database, user_ids, monkeypatch):
    code = "A1B2C3D4E5"
    user_id = user_ids["analyst"]
    database.execute(
        "INSERT INTO mfa_backup_codes(user_id, code_hash, created_at) VALUES (?, ?, ?)",
        (user_id, hashlib.sha256(code.encode()).hexdigest(), "2026-10-26T00:00:00Z"),
    )
    readers = Barrier(2)
    compare = auth.secrets.compare_digest

    def compare_after_both_reads(left, right):
        matched = compare(left, right)
        readers.wait(timeout=10)
        return matched

    monkeypatch.setattr(auth.secrets, "compare_digest", compare_after_both_reads)

    def consume():
        with app.app_context():
            return auth._backup_code_valid(user_id, "  " + code.lower() + "  ")

    with ThreadPoolExecutor(max_workers=2) as executor:
        attempts = [executor.submit(consume) for _ in range(2)]
        assert sorted(attempt.result(timeout=15) for attempt in attempts) == [False, True]

    monkeypatch.setattr(auth.secrets, "compare_digest", compare)
    with app.app_context():
        assert auth._backup_code_valid(user_id, code) is False
    assert database.execute("SELECT consumed_at FROM mfa_backup_codes WHERE user_id = ?", (user_id,)).fetchone()[0] is not None
