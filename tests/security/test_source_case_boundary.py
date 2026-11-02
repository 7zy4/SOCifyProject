import pytest


@pytest.mark.parametrize("case_scoped", [True, False])
def test_machine_source_key_cannot_choose_another_case(app, client, login_as, case_scoped):
    app.config.update(LEGACY_TRAINING_TESTS=False, REQUIRE_CASE_APPROVAL=False, REQUIRE_INVESTIGATION_SELECTION=False)
    login_as("admin")
    own = client.post("/api/cases", json={"title": "Authorized source case"}).json["id"]
    other = client.post("/api/cases", json={"title": "Separate source case"}).json["id"]
    path = f"/api/cases/{own}/siem-connectors" if case_scoped else "/api/sources"
    created = client.post(path, json={"name": "Identity gateway", "type": "http", "generate_ingest_key": True})
    assert created.status_code == 201
    assert created.json["status"] == "not_tested"
    ingest = f"/api/sources/{created.json['id']}/ingest"
    headers = {"X-SOCify-Source-Key": created.json["ingest_key"]}
    records = {"events": [{"title": "Authorized identity review"}]}
    denied = client.post(f"{ingest}?case_id={other}", headers=headers, json=records)
    assert denied.status_code == 403
    assert denied.json["error"]["code"] == "SOURCE_CASE_MISMATCH"
    assert client.get(f"/api/cases/{other}/logs").json["total"] == 0
    accepted = client.post(f"{ingest}?case_id={own}" if case_scoped else ingest, headers=headers, json=records)
    assert accepted.status_code == 201 and accepted.json["accepted"] == 1
    assert client.get(f"/api/cases/{own}/logs").json["total"] == (1 if case_scoped else 0)
