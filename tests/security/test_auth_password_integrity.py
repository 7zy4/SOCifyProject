import pytest

from tests.conftest import DEMO_LOGIN_VALUE


@pytest.mark.parametrize("stored", ["not-a-bcrypt-digest", "", "$2b$12$broken"])
def test_damaged_password_digest_rejects_login_without_server_error(client, database, stored):
    database.execute("UPDATE users SET password_hash=? WHERE email='analyst@socify.local'", (stored,))
    response = client.post("/api/auth/login", json={"email": "analyst@socify.local", "password": DEMO_LOGIN_VALUE})
    assert response.status_code == 401
    assert response.json["error"]["code"] == "INVALID_CREDENTIALS"
    assert client.get("/api/auth/me").status_code == 401
    assert database.execute("SELECT COUNT(*) FROM login_attempts WHERE succeeded=0").fetchone()[0] == 1
    assert database.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0] == 0


@pytest.mark.parametrize("route", ["password", "mfa_enroll", "mfa_disable"])
def test_damaged_digest_cannot_authorize_sensitive_account_changes(client, database, login_as, route):
    login_as("analyst")
    database.execute("UPDATE users SET password_hash='damaged' WHERE email='analyst@socify.local'")
    if route == "password":
        response = client.post("/api/profile/password", json={"current_password": DEMO_LOGIN_VALUE, "new_password": "Synthetic-New-Password-2026!"})
    elif route == "mfa_enroll":
        client.application.config["LEGACY_TRAINING_TESTS"] = False
        response = client.post("/api/auth/mfa/enroll", json={"current_password": DEMO_LOGIN_VALUE})
    else:
        response = client.delete("/api/auth/mfa", json={"current_password": DEMO_LOGIN_VALUE, "code": "123456"})
    assert response.status_code == 403
    assert database.execute("SELECT password_hash FROM users WHERE email='analyst@socify.local'").fetchone()[0] == "damaged"


def test_login_form_explains_rate_limit_without_exposing_password_or_account(app, client):
    app.config["RATE_LIMIT_LOGIN_ATTEMPTS"] = 1
    fields = {"email": "missing-login@example.test", "password": "Synthetic-Invalid-Password!"}
    client.post("/login", data=fields)
    response = client.post("/login", data=fields, follow_redirects=True)
    assert "محاولات دخول كثيرة" in response.text
    assert fields["email"] not in response.text and fields["password"] not in response.text


def test_login_form_explains_required_mfa_without_disabling_it(client, database):
    from socify.security import encrypt_secret, generate_totp_secret

    with client.application.app_context():
        ciphertext = encrypt_secret(generate_totp_secret())
    user = database.execute("SELECT id FROM users WHERE email='analyst@socify.local'").fetchone()[0]
    database.execute("INSERT INTO mfa_enrollments(user_id,secret_ciphertext,enabled,updated_at) VALUES (?,?,1,'2026-10-26T00:00:00Z')", (user, ciphertext))
    response = client.post("/login", data={"email": "analyst@socify.local", "password": DEMO_LOGIN_VALUE}, follow_redirects=True)
    assert "أدخل رمز المصادقة متعددة العوامل" in response.text
    assert client.get("/api/auth/me").status_code == 401
    assert database.execute("SELECT enabled FROM mfa_enrollments WHERE user_id=?", (user,)).fetchone()[0] == 1


def test_case_insensitive_account_lookup_uses_index_without_rewriting_users(database):
    rows = [tuple(row) for row in database.execute("SELECT * FROM users ORDER BY id")]
    plan = database.execute("EXPLAIN QUERY PLAN SELECT id FROM users WHERE lower(email)=?", ("analyst@socify.local",)).fetchall()
    assert any("idx_users_email_lower" in row[3] for row in plan)
    assert [tuple(row) for row in database.execute("SELECT * FROM users ORDER BY id")] == rows


def test_registration_does_not_duplicate_an_existing_mixed_case_email(client, database):
    database.execute("UPDATE users SET email='Analyst@SOCify.Local' WHERE email='analyst@socify.local'")
    before = database.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    response = client.post("/api/auth/register", json={"email": "analyst@socify.local", "password": DEMO_LOGIN_VALUE, "name": "Duplicate"})
    assert response.status_code == 409
    assert database.execute("SELECT COUNT(*) FROM users").fetchone()[0] == before
