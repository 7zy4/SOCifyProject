"""Exercise workbench validation, report state changes and case access boundaries."""

import io
import json
import sqlite3
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from socify import autopsy_samples
from socify.quick_reports import QUICK_REPORT_QUESTIONS

# Explicit fixture decisions; production forms start unanswered.
TEST_ANSWERS = {q["id"]: q["options"][0]["value"] for q in QUICK_REPORT_QUESTIONS}


@pytest.fixture
def case_base(autopsy_case):
    return f"/api/cases/{autopsy_case}"


@pytest.mark.parametrize("answers", [None, [], {}, {"unknown": "value"}, {"incident_classification": 42}])
def test_report_rejects_incomplete_answers_without_saving(case_base, client, answers):
    response = client.put(case_base + "/quick-report", json={"answers": answers})
    assert response.status_code == 422
    assert client.get(case_base + "/quick-report").json["report"] is None


def test_report_validation_and_manager_decision(case_base, client, login_as, database):
    path = case_base + "/quick-report"
    assert client.put(path, json=[]).status_code == 400
    assert client.post(path + "/escalate", json={}).status_code == 422
    assert client.post(path + "/escalate", json=[1]).status_code == 400
    for verb, endpoint in ((client.put, path), (client.post, path + "/escalate")):
        assert verb(endpoint, json={"answers": TEST_ANSWERS, "executive_note": "x" * 281}).status_code == 422
    assert client.get(case_base.replace("/api", "") + "/quick-report/print").status_code == 409
    assert client.post(path + "/escalate", json={"answers": TEST_ANSWERS, "executive_note": "Initial"}).status_code == 200
    updated = client.put(path, json={"answers": TEST_ANSWERS, "executive_note": "Updated evidence"})
    assert updated.json["report"]["status"] == "escalated"
    assert updated.json["report"]["executive_note"] == "Updated evidence"
    assert client.post(path + "/escalate", json={"answers": TEST_ANSWERS}).status_code == 200
    login_as("soc_manager")
    assert client.post(path + "/acknowledge", json=[]).status_code == 400
    assert client.post(path + "/acknowledge", json={"decision": "invalid"}).status_code == 422
    assert client.post(path + "/acknowledge", json={"decision": "closed", "comment": "x" * 501}).status_code == 422
    accepted = client.post(path + "/acknowledge", json={"decision": "approved", "comment": "Reviewed retained evidence"})
    assert accepted.status_code == 200
    assert accepted.json["report"]["manager_decision"] == "approved"
    assert client.get(case_base).json["status"] == "escalated"
    printed = client.get(case_base.replace("/api", "") + "/quick-report/print").get_data(as_text=True)
    assert "Reviewed retained evidence" in printed
    revised = client.put(path, json={"answers": TEST_ANSWERS}).json["report"]
    assert revised["status"] == "draft"
    assert revised["manager_decision"] is None and revised["acknowledged_at"] is None
    assert "Reviewed retained evidence" not in client.get(case_base.replace("/api", "") + "/quick-report/print").get_data(as_text=True)
    for payload in ({}, {"answers": TEST_ANSWERS}):
        assert client.post(path + "/acknowledge", json={"decision": "approved"}).status_code == 200
        resubmitted = client.post(path + "/escalate", json=payload).json["report"]
        assert resubmitted["status"] == "escalated"
        assert resubmitted["manager_decision"] is None and resubmitted["acknowledged_by"] is None
    case_id = int(case_base.rsplit("/", 1)[1])
    database.execute("UPDATE incident_cases SET status='closed' WHERE id=?", (case_id,))
    assert client.put(path, json={"answers": TEST_ANSWERS}).status_code == 409
    assert client.post(path + "/escalate", json={}).status_code == 409


def test_report_inbox_respects_case_membership(case_base, client, login_as):
    assert client.post(case_base + "/quick-report/escalate", json={"answers": TEST_ANSWERS}).status_code == 200
    login_as("soc_manager")
    private = client.post("/api/cases", json={"title": "Restricted manager evidence", "classification": "restricted"}).json["id"]
    private_base = f"/api/cases/{private}"
    assert client.post(private_base + "/quick-report/acknowledge", json={"decision": "approved"}).status_code == 404
    assert client.post(private_base + "/quick-report/escalate", json={"answers": TEST_ANSWERS}).status_code == 200
    assert private in {r["case_id"] for r in client.get("/api/reports/escalated").json["items"]}
    login_as("analyst")
    assert private not in {r["case_id"] for r in client.get("/api/reports/escalated").json["items"]}
    for method, route in (("GET", "/quick-report"), ("PUT", "/quick-report"), ("POST", "/quick-report/escalate")):
        assert client.open(private_base + route, method=method, json={"answers": TEST_ANSWERS}).status_code == 404
    assert client.get(f"/cases/{private}/quick-report/print").status_code == 404
    login_as("soc_manager")
    assert client.post("/api/cases/999999/quick-report/acknowledge", json={"decision": "approved"}).status_code == 404


@pytest.mark.parametrize(
    "body",
    [
        [],
        {"type": "unsupported", "value": "abc"},
        {"type": "email", "value": "broken"},
        {"type": "cidr", "value": "broken"},
        {"type": "domain", "value": "bad domain"},
        {"type": "url", "value": "file:///etc/passwd"},
        {"type": "sha256", "value": "abc"},
        {"type": "ip", "value": ""},
        {"type": "email", "value": "x" * 513},
        {"type": "ip", "value": "192.0.2.1", "severity": "unknown"},
        {"type": "ip", "value": "192.0.2.1", "note": "x" * 501},
        {"type": "ip", "value": "192.0.2.1", "source_case_id": True},
    ],
)
def test_watchlist_rejects_invalid_entries(case_base, client, body):
    assert client.post("/api/watchlist", json=body).status_code in {400, 404, 422}
    assert client.get("/api/watchlist").json["total"] == 0


def test_watchlist_filters_reactivation_and_validation(case_base, client):
    case_id = int(case_base.rsplit("/", 1)[1])
    body = {"type": "ip", "value": "[::ffff:192.0.2.1]", "note": "Review", "source_case_id": case_id}
    created = client.post("/api/watchlist", json=body)
    assert created.status_code == 201
    path = f"/api/watchlist/{created.json['id']}"
    assert created.json["value"] == "192.0.2.1"
    assert client.patch(path, json={"is_active": False}).status_code == 200
    assert client.get("/api/watchlist?active_only=1").json["total"] == 0
    again = client.post("/api/watchlist", json={**body, "note": ""})
    assert again.status_code == 200 and again.json["duplicate"] and again.json["is_active"]
    assert again.json["note"] == "Review"
    assert client.get("/api/watchlist?type=ip&q=review&active_only=1").json["total"] == 1
    assert client.get("/api/watchlist?type=domain").json["total"] == 0
    assert client.get("/api/watchlist?type=invalid").status_code == 422
    assert client.patch(path, json=[]).status_code == 400
    for body in ({"is_active": 1}, {"severity": "invalid"}, {"note": "x" * 501}):
        assert client.patch(path, json=body).status_code == 422
    assert client.patch("/api/watchlist/999999", json={}).status_code == 404
    assert client.delete("/api/watchlist/999999").status_code == 404
    assert client.post("/api/cases/999999/watchlist-scan", json={}).status_code == 404


def test_watchlist_correlates_domain_url_hash_and_preserves_evidence(case_base, client, database):
    digest = "ab" * 32
    indicators = [("domain", "EVIL.EXAMPLE."), ("url", "https://evil.example/path"), ("sha256", digest.upper())]
    entries = []
    for kind, value in indicators:
        response = client.post("/api/watchlist", json={"type": kind, "value": value})
        assert response.status_code == 201
        entries.append(response.json["id"])
    content = json.dumps([{"title": "Retained URL https://evil.example/path", "hostname": "sub.evil.example", "file_hash": digest}])
    assert client.post(case_base + "/imports", json={"filename": "evidence.json", "content": content}).status_code == 201
    items = client.get("/api/watchlist").json["items"]
    assert {item["id"] for item in items if item["hits_count"] == 1} == set(entries)
    assert client.post(case_base + "/watchlist-scan", json={}).json["alerts_created"] == 0
    database.execute("UPDATE incident_cases SET status='closed' WHERE id=?", (int(case_base.rsplit("/", 1)[1]),))
    assert client.post(case_base + "/watchlist-scan", json={}).status_code == 409


def test_triage_upload_and_retained_sample_integrity(case_base, client, database, monkeypatch):
    path = case_base + "/quick-file-triage"
    assert client.post(path).status_code == 422
    for name, data in (("../evidence.txt", b"data"), ("empty.txt", b"")):
        assert client.post(path, data={"file": (io.BytesIO(data), name)}).status_code == 422

    def upload():
        return client.post(path, data={"file": (io.BytesIO(b"Inert retained evidence"), "evidence.txt")})

    created = upload()
    assert created.status_code == 201
    assert upload().json["duplicate_sample"] is True
    sample_id = created.json["sample_id"]
    assert client.post(case_base + "/samples/999999/quick-triage", json={}).status_code == 404
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        database.execute("UPDATE autopsy_samples SET sha256=? WHERE id=?", ("0" * 64, sample_id))
    # Simulate a storage/key failure without disabling the database's evidence protections.
    for decryptor in (SimpleNamespace(decrypt=lambda _: b"changed bytes"), Fernet(Fernet.generate_key())):
        with monkeypatch.context() as patch:
            patch.setattr(autopsy_samples, "cipher", lambda retained=decryptor: retained)
            assert client.post(case_base + f"/samples/{sample_id}/quick-triage", json={}).status_code == 409
    assert client.post(case_base + "/email-triage", json={}).status_code == 422
    email = "From: sender@example.test\nTo: analyst@example.test\nSubject: Retained message\n\nInert evidence"
    parsed = client.post(case_base + "/email-triage", json={"raw_eml": email, "filename": "message"})
    assert parsed.status_code == 201
    summary = client.get(case_base + "/quick-report").json["auto_summary"]
    assert any(item["kind"] == "email" and "sender@example.test" in item["detail"] for item in summary["static_triage_items"])
    database.execute("UPDATE incident_cases SET status='closed' WHERE id=?", (int(case_base.rsplit("/", 1)[1]),))
    assert upload().status_code == 409
    assert client.post(case_base + "/email-triage", json={"raw_eml": email}).status_code == 409
    assert client.post(case_base + f"/samples/{sample_id}/quick-triage", json={}).status_code == 409
