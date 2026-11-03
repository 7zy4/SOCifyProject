from tests.integration.test_autopsy_reports import request_report


def test_reader_can_review_redacted_snapshot_without_gaining_full_report_access(autopsy_case, client, login_as, user_ids):
    base = f"/api/cases/{autopsy_case}"
    full = request_report(client, autopsy_case)
    assert full.status_code == 202
    full_path = base + f"/reports/{full.json['id']}"
    login_as("soc_manager")
    assert client.post(base + "/members", json={"user_id": user_ids["auditor"], "responsibility": "reviewer"}).status_code == 200
    login_as("auditor")
    withheld = client.get(full_path)
    assert withheld.status_code == 200 and "payload" not in withheld.json
    assert withheld.json["profile"] == "full"
    redacted = request_report(client, autopsy_case, "metadata_only_v1")
    assert redacted.status_code == 202
    visible = client.get(base + f"/reports/{redacted.json['id']}")
    assert visible.status_code == 200
    assert visible.json["profile"] == visible.json["payload"]["profile"] == "metadata_only_v1"
    assert visible.json["payload"]["records"] == {}
    assert "reason" not in visible.json["payload"]["context"]
    assert "Internal incident review" not in visible.text
    assert request_report(client, autopsy_case).status_code == 403
    assert client.post(base + f"/reports/{redacted.json['id']}/approve", json={"version": client.get(base).json["version"]}).status_code == 403
