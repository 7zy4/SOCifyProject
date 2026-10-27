from socify.autopsy_domain import ASSET_TYPES, KINDS
from socify.autopsy_report_render import render_html


def test_extended_investigation_catalog_is_persisted_and_validated(autopsy_case, client):
    base = f"/api/cases/{autopsy_case}/records"
    for kind in ("identity_provider", "email_gateway", "mobile_device", "storage", "virtual_machine", "industrial_device"):
        assert kind in ASSET_TYPES
        response = client.post(base + "/asset", json={"name": "Case asset", "type": kind, "role": "defender"})
        assert response.status_code == 201, response.json
        assert response.json["payload"]["type"] == kind
    assert client.post(f"/api/cases/{autopsy_case}/imports", json={"filename": "evidence.json", "content": '[{"title":"Retained log"}]'}).status_code == 201
    evidence_id = client.get(f"/api/cases/{autopsy_case}").json["evidence"][0]["id"]
    for category in ("unpatched_software", "weak_authentication", "insecure_remote_access", "insufficient_segmentation", "data_exposure", "process_gap"):
        assert category in KINDS["root_cause"]["category"]["choices"]
        response = client.post(
            base + "/root_cause", json={"category": category, "conclusion": "Recorded conclusion requires case evidence", "evidence_id": evidence_id}
        )
        assert response.status_code == 201, response.json
        assert response.json["payload"]["category"] == category
    assert client.post(base + "/asset", json={"name": "Invalid", "type": "invented", "role": "defender"}).status_code == 422


def test_report_contents_links_reach_escaped_sections_without_changing_snapshot():
    payload = {"case": {"title": '<script>alert("evidence")</script>', "reference": "CASE-17"}, "revision": 1, "summary": {"text": "<untrusted>"}}
    before = repr(payload)
    document = render_html(payload)
    assert 'href="#report-section-1"' in document
    assert 'id="report-section-1"' in document
    assert "&lt;script&gt;" in document and "<script>" not in document
    assert repr(payload) == before
