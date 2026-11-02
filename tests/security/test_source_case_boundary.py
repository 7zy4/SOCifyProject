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


@pytest.mark.parametrize("case_query", ["9" * 5000, "-1", "invalid"], ids=["oversized", "negative", "not-numeric"])
def test_source_rejects_invalid_case_query_without_interrupting_delivery(autopsy_case, client, case_query):
    created = client.post(f"/api/cases/{autopsy_case}/siem-connectors", json={"name": "Gateway", "type": "http"}).json
    path = f"/api/sources/{created['id']}/ingest"
    headers = {"X-SOCify-Source-Key": created["ingest_key"]}
    payload = {"events": [{"title": "Retained gateway event"}]}
    response = client.post(path, query_string={"case_id": case_query}, headers=headers, json=payload)
    assert response.status_code in {403, 422}
    assert client.get(f"/api/cases/{autopsy_case}/logs").json["total"] == 0
    assert client.post(path, headers=headers, json=payload).json["accepted"] == 1


def test_delivery_retries_preserve_case_evidence_and_remain_scoped(autopsy_case, client, database):
    case_path = f"/api/cases/{autopsy_case}"
    payload = {"events": [{"title": "Retained gateway event"}]}
    created = client.post(case_path + "/siem-connectors", json={"name": "Gateway", "type": "http"}).json
    path = f"/api/sources/{created['id']}/ingest"
    headers = {"X-SOCify-Source-Key": created["ingest_key"]}
    assert client.post(path, headers=headers, json=payload).json["accepted"] == 1
    before = client.get(case_path).json
    assert client.post(path, headers=headers, json=payload).json["skipped"] == 1
    after = client.get(case_path).json
    assert after["version"] == before["version"] and after["evidence"] == before["evidence"]
    assert len(client.get(case_path + "/imports").json["items"]) == 1
    assert database.execute("SELECT COUNT(*) FROM security_audit_logs WHERE action = 'ingest_retry'").fetchone()[0] == 1
    other = client.post(case_path + "/siem-connectors", json={"name": "Separate gateway", "type": "http"}).json
    assert client.post(f"/api/sources/{other['id']}/ingest", headers={"X-SOCify-Source-Key": other["ingest_key"]}, json=payload).json["accepted"] == 1
    assert client.get(case_path + "/logs").json["total"] == 2
    database.execute("UPDATE incident_cases SET status = 'closed' WHERE id = ?", (autopsy_case,))
    assert client.post(path, headers=headers, json=payload).status_code == 422
