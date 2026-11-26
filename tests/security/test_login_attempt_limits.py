"""Sign-in attempt limits count real mistakes only: the MFA step and earlier mistakes before a success never lock a user out."""

import hashlib
import time
from datetime import timedelta

import pytest

from socify.security import encrypt_secret, generate_totp_secret, totp_code
from socify.timeutils import iso_now
from tests.conftest import DEMO_LOGIN_VALUE

ANALYST = "analyst@socify.local"
WRONG = "Invalid-Sample-Value"


@pytest.fixture
def mfa_secret(app, database, user_ids):
    """Enable MFA for the analyst as a verified enrollment stores it, and return the authenticator secret."""
    secret = generate_totp_secret()
    with app.app_context():
        ciphertext = encrypt_secret(secret)
    database.execute(
        "INSERT INTO mfa_enrollments (user_id, secret_ciphertext, enabled, verified_at, updated_at) VALUES (?, ?, 1, ?, ?)",
        (user_ids["analyst"], ciphertext, iso_now(), iso_now()),
    )
    return secret


def _login(client, password=DEMO_LOGIN_VALUE, **extra):
    return client.post("/api/auth/login", json={"email": ANALYST, "password": password, **extra})


def _failures(database):
    return database.execute("SELECT COUNT(*) FROM login_attempts WHERE succeeded = 0").fetchone()[0]


def test_repeated_two_step_sign_ins_inside_one_window_all_succeed(client, database, mfa_secret, user_ids):
    # The test application allows three failures; six two-step sign-ins used to lock the account at the fourth.
    for _ in range(6):
        challenge = _login(client)
        assert challenge.status_code == 428 and challenge.json["error"]["code"] == "MFA_REQUIRED"
        signed_in = _login(client, mfa_code=totp_code(mfa_secret, int(time.time())))
        assert signed_in.status_code == 200, signed_in.json
        client.post("/api/auth/logout", json={})
        # A code opens one session only; let the same 30-second code open the next sign-in of this test.
        database.execute("UPDATE mfa_enrollments SET last_totp_counter = NULL WHERE user_id = ?", (user_ids["analyst"],))
    assert _failures(database) == 0


def test_a_missing_code_is_not_a_failed_attempt(client, database, mfa_secret):
    for _ in range(5):
        assert _login(client).status_code == 428
    assert _failures(database) == 0
    assert _login(client, mfa_code=totp_code(mfa_secret, int(time.time()))).status_code == 200


def _wrong_code(secret):
    now = int(time.time())
    valid = {totp_code(secret, now + offset) for offset in (-60, -30, 0, 30, 60)}
    return next(candidate for candidate in ("000000", "111111", "222222", "333333", "444444", "555555") if candidate not in valid)


def test_a_wrong_code_counts_and_reaches_the_limit(client, database, mfa_secret):
    for _ in range(3):
        refused = _login(client, mfa_code=_wrong_code(mfa_secret))
        assert refused.status_code == 401 and refused.json["error"]["code"] == "INVALID_MFA_CODE"
    assert _failures(database) == 3
    limited = _login(client, mfa_code=totp_code(mfa_secret, int(time.time())))
    assert limited.status_code == 429 and limited.json["error"]["code"] == "LOGIN_RATE_LIMITED"


def test_a_wrong_password_still_counts(client, database):
    for _ in range(3):
        assert _login(client, password=WRONG).status_code == 401
    assert _login(client).status_code == 429


def test_failures_before_a_success_do_not_count_after_it(client, database):
    for _ in range(2):
        assert _login(client, password=WRONG).status_code == 401
    assert _login(client).status_code == 200
    client.post("/api/auth/logout", json={})
    for _ in range(2):
        assert _login(client, password=WRONG).status_code == 401
    assert _login(client).status_code == 200
    client.post("/api/auth/logout", json={})
    for _ in range(3):
        assert _login(client, password=WRONG).status_code == 401
    assert _login(client).status_code == 429


def test_the_address_limit_counts_failures_across_accounts_and_a_success_does_not_reset_it(app, client, database):
    assert app.config["RATE_LIMIT_LOGIN_IP_ATTEMPTS"] == 50
    stamp = iso_now()
    database.executemany(
        "INSERT INTO login_attempts (identifier_hash, ip_address, succeeded, occurred_at) VALUES (?, '127.0.0.1', 0, ?)",
        [(hashlib.sha256(f"guess-{index}".encode()).hexdigest(), stamp) for index in range(48)],
    )
    assert _login(client).status_code == 200
    client.post("/api/auth/logout", json={})
    assert client.post("/api/auth/login", json={"email": "someone@example.test", "password": WRONG}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "another@example.test", "password": WRONG}).status_code == 401
    limited = _login(client)
    assert limited.status_code == 429 and limited.json["error"]["code"] == "LOGIN_RATE_LIMITED"


class Clock:
    """Moves the application's clock forward without waiting."""

    def __init__(self, monkeypatch):
        import socify.auth
        import socify.timeutils

        self.offset = timedelta()
        real = socify.timeutils.utc_now
        monkeypatch.setattr(socify.timeutils, "utc_now", lambda: real() + self.offset)
        monkeypatch.setattr(socify.auth, "utc_now", lambda: real() + self.offset)

    def advance(self, **delta):
        self.offset += timedelta(**delta)


def _from(client, address, email=ANALYST, password=WRONG):
    return client.post("/api/auth/login", json={"email": email, "password": password}, environ_base={"REMOTE_ADDR": address})


@pytest.fixture
def account_limit(app):
    app.config.update(RATE_LIMIT_LOGIN_ACCOUNT_ATTEMPTS=4)


def test_failures_spread_over_many_addresses_throttle_the_account_with_a_growing_wait(client, database, monkeypatch, account_limit, user_ids):
    clock = Clock(monkeypatch)
    for index in range(4):
        assert _from(client, f"198.51.100.{index + 1}").status_code == 401
    throttled = _from(client, "198.51.100.50", password=DEMO_LOGIN_VALUE)
    assert throttled.status_code == 429 and throttled.json["error"]["code"] == "LOGIN_RATE_LIMITED"
    assert 25 <= int(throttled.headers["Retry-After"]) <= 30 and throttled.json["error"]["details"]["retry_after"] == int(throttled.headers["Retry-After"])
    waits = []
    for step in range(3):
        clock.advance(seconds=31 * 2**step)
        assert _from(client, f"198.51.100.{60 + step}").status_code == 401
        waits.append(int(_from(client, "198.51.100.99").headers["Retry-After"]))
    assert waits[0] > 50 and waits[1] > 110 and waits[2] > 230 and waits == sorted(waits)
    audited = database.execute("SELECT resource_id, workspace_id, details FROM security_audit_logs WHERE action = 'login_throttled'").fetchall()
    assert len(audited) == 4 and {row["resource_id"] for row in audited} == {str(user_ids["analyst"])} and {row["workspace_id"] for row in audited} == {1}


def test_the_wait_doubles_and_never_exceeds_the_window(app, account_limit):
    from socify.auth import _account_throttle_delay

    app.config.update(RATE_LIMIT_LOGIN_WINDOW_SECONDS=200)
    with app.app_context():
        assert [_account_throttle_delay(failures) for failures in (4, 5, 6, 7, 40, 10**6)] == [30, 60, 120, 200, 200, 200]


def test_an_address_the_owner_signed_in_from_is_not_throttled_and_a_success_resets_the_account(client, account_limit):
    assert _from(client, "192.0.2.10", password=DEMO_LOGIN_VALUE).status_code == 200
    client.post("/api/auth/logout", json={})
    for index in range(4):
        _from(client, f"198.51.100.{index + 1}")
    assert _from(client, "198.51.100.40").status_code == 429
    owner = _from(client, "192.0.2.10", password=DEMO_LOGIN_VALUE)
    assert owner.status_code == 200
    notice = client.get("/api/auth/me").json
    assert notice["security_notice"] == {"failed_sign_ins": 4}
    assert "security_notice" not in client.get("/api/auth/me").json
    client.post("/api/auth/logout", json={})
    assert _from(client, "198.51.100.41").status_code == 401


def test_another_account_and_unknown_accounts_are_handled_alike(client, account_limit):
    for index in range(4):
        _from(client, f"198.51.100.{index + 1}")
        _from(client, f"203.0.113.{index + 1}", email="nobody@example.test")
    assert _from(client, "198.51.100.30").status_code == 429
    unknown = _from(client, "203.0.113.30", email="nobody@example.test")
    assert unknown.status_code == 429 and "Retry-After" in unknown.headers
    assert _from(client, "198.51.100.31", email="manager@socify.local", password=DEMO_LOGIN_VALUE).status_code == 200
