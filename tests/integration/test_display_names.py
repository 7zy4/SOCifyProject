import pytest


def test_own_display_names_follow_language_without_changing_identity(client, login_as, database, user_ids, app):
    app.config["LEGACY_TRAINING_TESTS"] = False
    login_as("soc_manager")
    actor = user_ids["soc_manager"]
    original = dict(database.execute("SELECT id,name,email,role FROM users WHERE id=?", (actor,)).fetchone())
    assert client.put("/api/profile/display-name", json={"name_ar": "نورة", "name_en": "Noura"}).status_code == 200
    for language, name in (("ar", "نورة"), ("en", "Noura")):
        headers = {"X-SOCify-Language": language}
        profile = client.get("/api/auth/me", headers=headers).json["user"]
        assert profile["name"] == name and profile["id"] == actor
        assert profile["account_name"] == original["name"]
        case = client.post("/api/cases", json={"title": "Name display check"}, headers=headers).json
        monitored = client.get("/api/cases", headers=headers).json["items"]
        assert next(item for item in monitored if item["id"] == case["id"])["assignee_name"] == name
    assert dict(database.execute("SELECT id,name,email,role FROM users WHERE id=?", (actor,)).fetchone()) == original
    login_as("analyst")
    assert client.get("/api/auth/me").json["user"]["name_ar"] == ""
    assert client.put("/api/profile/display-name", json={"name_ar": "", "name_en": ""}).status_code == 200
    assert (
        client.get("/api/auth/me", headers={"X-SOCify-Language": "en"}).json["user"]["name"]
        == database.execute("SELECT name FROM users WHERE id=?", (user_ids["analyst"],)).fetchone()[0]
    )


@pytest.mark.parametrize(
    "data",
    [
        None,
        {},
        {"name_ar": "A", "name_en": "B", "user_id": 1},
        {"name_ar": 4, "name_en": "B"},
        {"name_ar": "x" * 101, "name_en": "B"},
        {"name_ar": "A\u202eB", "name_en": "B"},
    ],
)
def test_invalid_display_names_cannot_change_accounts(client, login_as, data):
    login_as("analyst")
    assert client.put("/api/profile/display-name", json=data).status_code == 422


def test_display_name_requires_authentication(client):
    assert client.put("/api/profile/display-name", json={"name_ar": "أ", "name_en": "A"}).status_code == 401
