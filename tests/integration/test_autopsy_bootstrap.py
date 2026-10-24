import secrets

import bcrypt
import pytest

from scripts.bootstrap_team import create_manager


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
