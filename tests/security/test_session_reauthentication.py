from tests.conftest import DEMO_LOGIN_VALUE


def test_account_switch_cannot_reuse_the_previous_documents_write_token(app, client):
    app.config.update(WTF_CSRF_ENABLED=True, LEGACY_TRAINING_TESTS=False)
    token = client.get("/api/auth/csrf").json["csrf_token"]
    first = client.post("/api/auth/login", json={"email": "analyst@socify.local", "password": DEMO_LOGIN_VALUE}, headers={"X-CSRFToken": token})
    assert first.status_code == 200
    analyst = client.get("/api/auth/me")
    assert analyst.headers["Cache-Control"] == "no-store"
    token = analyst.json["csrf_token"]
    second = client.post("/api/auth/login", json={"email": "manager@socify.local", "password": DEMO_LOGIN_VALUE}, headers={"X-CSRFToken": token})
    assert second.status_code == 200
    manager = client.get("/api/auth/me").json
    assert manager["user"]["id"] != analyst.json["user"]["id"]
    assert manager["csrf_token"] != token
    rejected = client.post("/api/auth/logout", headers={"X-CSRFToken": token})
    assert rejected.status_code == 400 and rejected.json["error"]["code"] == "CSRF_VALIDATION_FAILED"
    assert client.get("/api/auth/me").json["user"]["id"] == manager["user"]["id"]
    assert client.post("/api/auth/logout", headers={"X-CSRFToken": manager["csrf_token"]}).status_code == 200
    assert client.get("/api/auth/me").status_code == 401
