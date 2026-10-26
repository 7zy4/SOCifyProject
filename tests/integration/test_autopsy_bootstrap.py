import secrets

import bcrypt
import pytest

from scripts.bootstrap_team import create_manager, reset_password
from socify.security import encrypt_secret, generate_totp_secret, totp_code


def test_internal_bootstrap_preserves_existing_accounts_and_creates_private_team(app, database):
    original = [tuple(row) for row in database.execute("SELECT id, email, password_hash FROM users ORDER BY id")]
    password = secrets.token_urlsafe(24)
    user_id = create_manager(app, "manager@internal.example.test", "Team Owner", "Internal Response", password)
    user = database.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    assert user["role"] == "soc_manager"
    assert user["workspace_id"] != 1
    assert bcrypt.checkpw(password.encode(), user["password_hash"].encode())
    assert database.execute("SELECT name FROM training_workspaces WHERE id = ?", (user["workspace_id"],)).fetchone()[0] == "Internal Response"
    assert [tuple(row) for row in database.execute("SELECT id, email, password_hash FROM users WHERE id != ? ORDER BY id", (user_id,))] == original
    with pytest.raises(ValueError, match="الحساب موجود"):
        create_manager(app, "manager@internal.example.test", "Replacement", "Replacement", password)


def test_internal_bootstrap_rejects_invalid_identity_and_weak_password(app):
    with pytest.raises(ValueError):
        create_manager(app, "invalid", "Manager", "Internal Team", secrets.token_urlsafe(24))
    with pytest.raises(ValueError):
        create_manager(app, "valid@example.test", "Manager", "Internal Team", "short")


def test_local_password_recovery_preserves_team_evidence_and_revokes_every_session(app, client, database):
    original = secrets.token_urlsafe(24)
    replacement = secrets.token_urlsafe(24)
    user_id = create_manager(app, "recovery@example.test", "Recovery owner", "Retained team", original)
    credentials = {"email": "recovery@example.test", "password": original}
    assert client.post("/api/auth/login", json=credentials).status_code == 200
    second = app.test_client()
    assert second.post("/api/auth/login", json=credentials).status_code == 200
    case = client.post("/api/incidents", json={"title": "Evidence retained through recovery"})
    assert case.status_code == 201, case.json
    before = tuple(database.execute("SELECT id,email,role,team,workspace_id,is_active FROM users WHERE id=?", (user_id,)).fetchone())
    assert reset_password(app, "RECOVERY@example.test", replacement) == user_id
    assert tuple(database.execute("SELECT id,email,role,team,workspace_id,is_active FROM users WHERE id=?", (user_id,)).fetchone()) == before
    assert database.execute("SELECT 1 FROM incident_cases WHERE id=?", (case.json["id"],)).fetchone()
    assert client.get("/api/auth/me").status_code == 401
    assert second.get("/api/auth/me").status_code == 401
    assert app.test_client().post("/api/auth/login", json=credentials).status_code == 401
    assert app.test_client().post("/api/auth/login", json={**credentials, "password": replacement}).status_code == 200
    audit = database.execute("SELECT * FROM security_audit_logs WHERE action='password_reset' AND resource_id=?", (str(user_id),)).fetchone()
    assert audit and audit["actor_id"] is None and audit["workspace_id"] == before[4]
    assert original not in audit["details"] and replacement not in audit["details"]


def test_local_password_recovery_does_not_disable_or_replace_mfa(app, database):
    user_id = create_manager(app, "mfa-recovery@example.test", "MFA owner", "MFA team", secrets.token_urlsafe(24))
    secret = generate_totp_secret()
    with app.app_context():
        encrypted = encrypt_secret(secret)
    database.execute("INSERT INTO mfa_enrollments(user_id,secret_ciphertext,enabled,updated_at) VALUES (?,?,1,'2026-10-26T00:00:00Z')", (user_id, encrypted))
    retained = tuple(database.execute("SELECT * FROM mfa_enrollments WHERE user_id=?", (user_id,)).fetchone())
    replacement = secrets.token_urlsafe(24)
    reset_password(app, "mfa-recovery@example.test", replacement)
    assert tuple(database.execute("SELECT * FROM mfa_enrollments WHERE user_id=?", (user_id,)).fetchone()) == retained
    credentials = {"email": "mfa-recovery@example.test", "password": replacement}
    assert app.test_client().post("/api/auth/login", json=credentials).status_code == 428
    assert app.test_client().post("/api/auth/login", json={**credentials, "mfa_code": totp_code(secret)}).status_code == 200


@pytest.mark.parametrize("state", ["missing", "disabled", "weak"])
def test_local_password_recovery_rejects_invalid_requests_without_changing_accounts(app, database, state):
    user_id = create_manager(app, "guarded@example.test", "Guarded owner", "Guarded team", secrets.token_urlsafe(24))
    if state == "disabled":
        database.execute("UPDATE users SET is_active=0 WHERE id=?", (user_id,))
    before = [tuple(row) for row in database.execute("SELECT * FROM users ORDER BY id")]
    with pytest.raises(ValueError):
        reset_password(app, "missing@example.test" if state == "missing" else "guarded@example.test", "short" if state == "weak" else secrets.token_urlsafe(24))
    assert [tuple(row) for row in database.execute("SELECT * FROM users ORDER BY id")] == before
    assert not database.execute("SELECT 1 FROM security_audit_logs WHERE action='password_reset'").fetchone()


def test_local_account_status_never_requests_or_exposes_a_password(app, database, monkeypatch, capsys):
    from scripts import bootstrap_team

    password = secrets.token_urlsafe(24)
    create_manager(app, "status@example.test", "Status owner", "Status team", password)
    before = [tuple(row) for row in database.execute("SELECT * FROM users ORDER BY id")]
    monkeypatch.setenv("SOCIFY_ENV", "production")
    monkeypatch.setattr(bootstrap_team, "create_app", lambda: app)
    monkeypatch.setattr("sys.argv", ["bootstrap_team", "--email", "status@example.test", "--status"])
    monkeypatch.setattr(bootstrap_team.getpass, "getpass", lambda prompt: pytest.fail("Status must not prompt for credentials"))
    bootstrap_team.main()
    output = capsys.readouterr().out
    assert "Account found" in output and str(app.config["DATABASE"]) in output
    assert password not in output
    assert [tuple(row) for row in database.execute("SELECT * FROM users ORDER BY id")] == before


def test_local_recovery_confirmation_mismatch_preserves_the_original_password(app, database, monkeypatch, capsys):
    from scripts import bootstrap_team

    user_id = create_manager(app, "confirm@example.test", "Confirmation owner", "Confirmation team", secrets.token_urlsafe(24))
    original = database.execute("SELECT password_hash FROM users WHERE id=?", (user_id,)).fetchone()[0]
    values = iter((secrets.token_urlsafe(24), secrets.token_urlsafe(24)))
    monkeypatch.setenv("SOCIFY_ENV", "production")
    monkeypatch.setattr(bootstrap_team, "create_app", lambda: app)
    monkeypatch.setattr("sys.argv", ["bootstrap_team", "--email", "confirm@example.test", "--reset-password"])
    monkeypatch.setattr(bootstrap_team.getpass, "getpass", lambda prompt: next(values))
    with pytest.raises(SystemExit) as rejected:
        bootstrap_team.main()
    assert rejected.value.code == 2
    assert database.execute("SELECT password_hash FROM users WHERE id=?", (user_id,)).fetchone()[0] == original
    assert "غير متطابقتين" in capsys.readouterr().err
