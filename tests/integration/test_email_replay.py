import json

import pytest


@pytest.mark.parametrize("subject", ["Subject: Retained review\n", ""])
def test_identical_mail_preserves_review_evidence_version_and_report_snapshot(autopsy_case, client, database, subject):
    base = f"/api/cases/{autopsy_case}"
    mail = f"From: sender@example.test\nTo: review@internal.test\n{subject}\nRetained body"
    first = client.post(base + "/email-triage", json={"filename": "retained.eml", "raw_eml": mail})
    assert first.status_code == 201
    review = first.json
    case = client.get(base).json
    report = client.post(base + "/reports", json={"profile": "metadata_only_v1", "version": case["version"]})
    assert report.status_code == 202, report.json
    path = f"{base}/reports/{report.json['id']}"
    snapshot = client.get(path).json["payload"]
    history = database.execute("SELECT COUNT(*) FROM autopsy_custody WHERE case_id=?", (autopsy_case,)).fetchone()[0]
    repeated = client.post(base + "/email-triage", json={"filename": "renamed.eml", "raw_eml": mail})
    assert repeated.status_code == 200 and repeated.json["duplicate"] is True
    assert repeated.json["id"] == review["id"] and repeated.json["payload"] == review["payload"]
    assert client.get(base).json["version"] == case["version"]
    assert client.get(path).json["payload"] == snapshot
    assert database.execute("SELECT COUNT(*) FROM autopsy_custody WHERE case_id=?", (autopsy_case,)).fetchone()[0] == history
    assert database.execute("SELECT COUNT(*) FROM autopsy_samples WHERE case_id=?", (autopsy_case,)).fetchone()[0] == 1
    assert len(client.get(base + "/email-reviews").json["items"]) == 1
    changed = client.post(base + "/email-triage", json={"filename": "retained.eml", "raw_eml": mail + " changed"})
    assert changed.status_code == 201 and changed.json["sample_id"] != review["sample_id"]
    assert client.get(base).json["version"] > case["version"]
    assert client.get(path).json["payload"] == snapshot


def test_changed_analysis_is_retained_and_other_cases_do_not_share_review_identity(autopsy_case, client, database):
    base = f"/api/cases/{autopsy_case}"
    mail = {"filename": "retained.eml", "raw_eml": "From: sender@example.test\nSubject: Retained review\n\nRetained body"}
    first = client.post(base + "/email-triage", json=mail).json
    # Model an older persisted result without changing the message or granting access.
    previous = {**first["payload"], "limitations": "An older inspection result"}
    database.execute("UPDATE autopsy_records SET payload=? WHERE id=?", (json.dumps(previous), first["id"]))
    refreshed = client.post(base + "/email-triage", json=mail)
    assert refreshed.status_code == 201 and refreshed.json["id"] != first["id"]
    assert refreshed.json["sample_id"] == first["sample_id"]
    assert client.post(base + "/email-triage", json=mail).json["id"] == refreshed.json["id"]
    second = client.post("/api/cases", json={"title": "Independent mail review"}).json["id"]
    isolated = client.post(f"/api/cases/{second}/email-triage", json=mail)
    assert isolated.status_code == 201
    assert isolated.json["sample_id"] != first["sample_id"] and isolated.json["id"] != refreshed.json["id"]
    assert isolated.json["payload"]["sha256"] == first["payload"]["sha256"]
