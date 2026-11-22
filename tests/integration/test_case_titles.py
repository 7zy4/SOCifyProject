"""A case named in Arabic and English shows the name of the interface language, in lists, searches and the case itself."""

import pytest

BODY = {
    "title": "تخمين كلمات مرور على VPN",
    "title_en": "VPN password guessing",
    "reason": "alert_review",
    "objective": "Establish impact from retained evidence",
}


def english(client, path):
    return client.get(path, headers={"X-SOCify-Language": "en"}).json


def test_each_language_reads_its_own_case_name(client, login_as):
    login_as("analyst")
    created = client.post("/api/cases", json=BODY)
    assert created.status_code == 201, created.json
    case_id = created.json["id"]
    arabic = client.get(f"/api/cases/{case_id}", headers={"X-SOCify-Language": "ar"}).json
    assert arabic["title"] == BODY["title"]
    assert (arabic["title_ar"], arabic["title_en"]) == (BODY["title"], BODY["title_en"])
    assert english(client, f"/api/cases/{case_id}")["title"] == BODY["title_en"]
    listed = next(item for item in english(client, "/api/cases")["items"] if item["id"] == case_id)
    assert listed["title"] == BODY["title_en"]
    assert [item["id"] for item in english(client, "/api/cases?q=password")["items"]] == [case_id]


def test_a_case_without_an_english_name_keeps_its_name_in_english(client, login_as):
    login_as("analyst")
    case_id = client.post("/api/cases", json={key: value for key, value in BODY.items() if key != "title_en"}).json["id"]
    assert english(client, f"/api/cases/{case_id}")["title"] == BODY["title"]


@pytest.mark.parametrize("value", ["ab", 7, "x" * 256])
def test_an_english_name_must_be_a_real_name(client, login_as, value):
    login_as("analyst")
    assert client.post("/api/cases", json={**BODY, "title_en": value}).status_code == 422
