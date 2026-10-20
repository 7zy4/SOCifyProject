from socify.auth import re_email
from tests.conftest import DEMO_LOGIN_VALUE


def test_browser_forms_redirect_and_register_without_privilege_escalation(client, database):
    assert client.get("/register").status_code == 200
    assert client.post("/register", data={}).headers["Location"].endswith("/register")
    payload = {"email": "form-user@example.test", "name": "Form Trainee", "password": DEMO_LOGIN_VALUE, "role": "admin"}
    created = client.post("/register", data=payload)
    assert created.status_code == 302
    assert created.headers["Location"].endswith("/login")
    assert database.execute("SELECT role FROM users WHERE email = ?", (payload["email"],)).fetchone()[0] == "analyst"
    assert client.post("/register", json=payload).status_code == 409
    assert client.post("/login", data={}).headers["Location"].endswith("/login")
    signed_in = client.post("/login", data=payload)
    assert signed_in.status_code == 302
    assert signed_in.headers["Location"].endswith("/dashboard")
    assert client.get("/login").headers["Location"].endswith("/dashboard")
    assert client.post("/logout").status_code == 302
    assert client.get("/api/auth/me").status_code == 401
    assert client.post("/login", json=payload).status_code == 200
    assert client.post("/logout", json={}).status_code == 200


def test_registration_disable_and_password_policy(app, client):
    assert not re_email("invalid")
    assert not re_email("a" * 255 + "@example.test")
    assert not re_email("a @example.test")
    assert client.post("/api/auth/register", json={"email": "policy@example.test", "name": "Trainee", "password": "short"}).status_code == 422
    app.config["ALLOW_REGISTRATION"] = False
    assert client.get("/register").status_code == 403
    assert client.post("/api/auth/register", json={}).status_code == 403


def test_session_revocation_is_immediate(client):
    assert client.post("/api/auth/login", json={"email": "analyst@socify.local", "password": DEMO_LOGIN_VALUE}).status_code == 200
    identifier = client.get("/api/auth/sessions").json["items"][0]["id"]
    assert client.delete(f"/api/auth/sessions/{identifier}").status_code == 204
    assert client.get("/api/auth/me").status_code == 401


def test_invalid_mfa_and_unreadable_enrollment_fail_closed(client, login_as, database, user_ids):
    login_as("analyst")
    assert client.post("/api/profile/password", json={}).status_code == 422
    assert client.post("/api/auth/mfa/verify", json={"code": "invalid"}).status_code == 404
    assert client.delete("/api/auth/mfa", json={}).status_code == 403
    assert client.post("/api/auth/mfa/enroll", json={}).status_code == 200
    assert client.post("/api/auth/mfa/verify", json={"code": "invalid"}).status_code == 422
    database.execute("UPDATE mfa_enrollments SET secret_ciphertext = 'invalid-ciphertext', enabled = 1 WHERE user_id = ?", (user_ids["analyst"],))
    assert client.post("/api/auth/mfa/verify", json={"code": "123456"}).status_code == 409
    client.post("/api/auth/logout", json={})
    assert client.post("/api/auth/login", json={"email": "analyst@socify.local", "password": DEMO_LOGIN_VALUE, "mfa_code": "123456"}).status_code == 401


def test_inactive_account_and_missing_session_are_rejected(app, client, login_as, database, user_ids):
    login_as("analyst")
    database.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_ids["analyst"],))
    assert client.get("/api/auth/me").status_code == 401
    login_as("admin")
    app.config["TESTING"] = False
    assert client.get("/api/auth/me").status_code == 401
    app.config["SESSION_COOKIE_SECURE"] = True
    response = client.get("/nonexistent-page")
    assert response.status_code == 404
    assert response.headers["Strict-Transport-Security"].startswith("max-age=")
