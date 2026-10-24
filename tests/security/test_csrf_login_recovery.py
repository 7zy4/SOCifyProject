import re

from scripts.start_codespace import load_environment
from socify import create_app


def token(response):
    value = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert value is not None
    return value.group(1)


def test_html_login_failure_returns_protected_form_and_no_store(app, client):
    app.config["WTF_CSRF_ENABLED"] = True
    page = client.get("/login")
    assert page.headers["Cache-Control"] == "no-store"
    original = token(page)
    missing = client.post("/login", data={"email": "analyst@socify.local", "password": "Training-Safe-Password-2026!"})
    assert missing.status_code == 400
    assert missing.mimetype == "text/html"
    assert "الرمز يُنشأ تلقائيًا" in missing.text
    assert "Training-Safe-Password-2026!" not in missing.text
    assert token(missing)
    invalid = client.post("/login", data={"csrf_token": "invalid", "email": "analyst@socify.local", "password": "Training-Safe-Password-2026!"})
    assert invalid.status_code == 400
    accepted = client.post("/login", data={"csrf_token": original, "email": "analyst@socify.local", "password": "Training-Safe-Password-2026!"})
    assert accepted.status_code == 302
    assert accepted.headers["Location"] == "/dashboard"
    assert client.get("/api/auth/me").status_code == 200
    api_missing = client.post("/api/incidents", json={"title": "Token remains required"})
    assert api_missing.status_code == 400
    assert api_missing.json["error"]["code"] == "CSRF_VALIDATION_FAILED"


def test_registration_form_csrf_failure_stays_protected(app, client):
    app.config["WTF_CSRF_ENABLED"] = True
    failed = client.post("/register", data={"name": "CSRF fixture", "email": "fixture@example.test", "password": "Training-Safe-Password-2026!"})
    assert failed.status_code == 400
    assert failed.mimetype == "text/html"
    assert token(failed)
    assert failed.headers["Cache-Control"] == "no-store"


def test_persistent_codespace_keys_validate_csrf_across_app_instances(app, client, monkeypatch, tmp_path):
    for key in ("SOCIFY_ENV", "SOCIFY_SECRET_KEY", "SOCIFY_CREDENTIAL_KEY", "SOCIFY_DATABASE"):
        monkeypatch.delenv(key, raising=False)
    load_environment(tmp_path)
    saved = (tmp_path / "instance" / "codespaces.env").read_bytes()
    first = create_app({"DATABASE": app.config["DATABASE"], "TESTING": True})
    a = first.test_client()
    csrf = token(a.get("/login"))
    cookie = a.get_cookie("session")
    assert cookie is not None
    monkeypatch.delenv("SOCIFY_SECRET_KEY")
    monkeypatch.delenv("SOCIFY_CREDENTIAL_KEY")
    load_environment(tmp_path)
    assert (tmp_path / "instance" / "codespaces.env").read_bytes() == saved
    second = create_app({"DATABASE": app.config["DATABASE"], "TESTING": True})
    b = second.test_client()
    b.set_cookie("session", cookie.value)
    response = b.post("/login", data={"csrf_token": csrf, "email": "analyst@socify.local", "password": "Training-Safe-Password-2026!"})
    assert response.status_code == 302
    assert b.get("/api/auth/me").status_code == 200
