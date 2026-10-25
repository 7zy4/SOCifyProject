import pytest

from socify.request_limits import validate_json_structure


@pytest.mark.parametrize("number", [2**63, -(2**63) - 1, 2**200, float("inf"), float("-inf"), float("nan")])
def test_http_numeric_overflow_rejected_before_sql_or_json_canonicalization(autopsy_case, client, number):
    base = f"/api/cases/{autopsy_case}"
    for path, payload in (
        (
            "/records/indicator",
            {"type": "ip", "value": "192.0.2.20", "classification": "observable", "source": "Synthetic overflow fixture", "evidence_id": number},
        ),
        ("/samples/1/analyze", {"yara_pack_id": number}),
        ("/context", {"version": number}),
    ):
        response = client.patch(base + path, json=payload) if path == "/context" else client.post(base + path, json=payload)
        assert response.status_code == 422
        assert response.json["error"]["code"] == "NUMERIC_INPUT_OUT_OF_RANGE"
    assert client.get(base).status_code == 200


def test_uploaded_log_numbers_preserved_as_original_data_without_becoming_sql_identifiers(autopsy_case, client):
    base = f"/api/cases/{autopsy_case}"
    content = '{"title":"Untrusted source counter","raw_payload":{"counter":1267650600228229401496703205376}}'
    uploaded = client.post(base + "/imports", json={"filename": "counter.json", "content": content})
    assert uploaded.status_code == 201
    assert client.get(base + f"/imports/{uploaded.json['id']}/original").data == content.encode()
    validate_json_structure({"archived_source_counter": 2**100})
