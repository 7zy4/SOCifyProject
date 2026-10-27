import hashlib
import io
import json
import sqlite3
import zipfile

import pytest

from socify.autopsy_domain import canonical
from socify.autopsy_report_render import bundled_report_asset_fetcher
from socify.autopsy_reports import case_metrics, duration
from socify.autopsy_worker import run_autopsy_worker_once


def request_report(client, case_id, profile="full"):
    version = client.get(f"/api/cases/{case_id}").json["version"]
    return client.post(f"/api/cases/{case_id}/reports", json={"version": version, "profile": profile})


def transition(client, case_id, status, path="/api/cases"):
    version = client.get(f"/api/cases/{case_id}").json["version"]
    return client.post(f"{path}/{case_id}/transitions", json={"status": status, "version": version, "reason": "Documented investigation decision"})


def test_local_report_formats_snapshot_review_and_closure(autopsy_case, app, client, login_as, database, user_ids):
    case_id = autopsy_case
    base = f"/api/cases/{case_id}"
    for visibility, body in (("private", "PRIVATE_NOTE_NOT_FOR_REPORT"), ("team", "SHARED_DECISION_FOR_REPORT")):
        assert client.post(base + "/records/war_room", json={"title": "Decision", "body": body, "visibility": visibility}).status_code == 201
    assert client.post(base + "/imports", json={"filename": "evidence.json", "content": '[{"title":"Retained log"}]'}).status_code == 201
    assert (
        client.post(base + "/records/root_cause", json={"category": "unknown", "conclusion": "Insufficient logs to establish initial access"}).status_code
        == 201
    )
    assert (
        client.post(
            base + "/records/response",
            json={
                "title": "Review validation",
                "phase": "validation",
                "status": "not_applicable",
                "details": "This evidence review did not authorize containment actions",
            },
        ).status_code
        == 201
    )
    assert transition(client, case_id, "investigating").status_code == 200
    for task in client.get(base).json["tasks"]:
        assert client.patch(f"/api/incidents/{case_id}/tasks/{task['id']}", json={"status": "completed"}).status_code == 200
    assert transition(client, case_id, "awaiting_review").status_code == 200
    created = request_report(client, case_id)
    assert created.status_code == 202, created.json
    report_id = created.json["id"]
    path = base + f"/reports/{report_id}"
    snapshot = client.get(path).json["payload"]
    assert snapshot["custody"]["integrity_valid"] is True
    assert "PRIVATE_NOTE_NOT_FOR_REPORT" not in canonical(snapshot)
    assert "SHARED_DECISION_FOR_REPORT" in canonical(snapshot)
    assert hashlib.sha256(canonical(snapshot).encode()).hexdigest() == created.json["sha256"]
    assert client.get(path + "/files/pdf").status_code == 404
    with app.app_context():
        assert run_autopsy_worker_once("integration-renderer") == created.json["job_id"]
    ready = client.get(path).json
    assert ready["job"]["state"] == "completed", ready
    assert set(ready["formats"]) == {"pdf", "docx", "md", "html", "json"}
    pdf = client.get(path + "/files/pdf")
    assert pdf.data.startswith(b"%PDF-")
    assert hashlib.sha256(pdf.data).hexdigest() == pdf.headers["X-Content-SHA256"]
    html = client.get(path + "/files/html").text
    assert "font/woff2;base64," in html
    assert "SHARED_DECISION_FOR_REPORT" in html and "PRIVATE_NOTE_NOT_FOR_REPORT" not in html
    assert "<script" not in html
    assert json.loads(client.get(path + "/files/json").data) == snapshot
    markdown = client.get(path + "/files/md").text
    assert "```text" in markdown and "الملخص التنفيذي" in markdown
    with zipfile.ZipFile(io.BytesIO(client.get(path + "/files/docx").data)) as archive:
        assert "word/document.xml" in archive.namelist()
        assert not any("vbaProject" in name for name in archive.namelist())
        relationships = archive.read("word/_rels/document.xml.rels")
        assert b'TargetMode="External"' not in relationships
        assert "SHARED_DECISION_FOR_REPORT" in archive.read("word/document.xml").decode()
    with pytest.raises(sqlite3.IntegrityError):
        database.execute("UPDATE autopsy_reports SET payload = '{}' WHERE id = ?", (report_id,))
    with pytest.raises(sqlite3.IntegrityError):
        database.execute("DELETE FROM autopsy_report_files WHERE report_id = ?", (report_id,))
    assert client.post(path + "/approve", json={"version": snapshot["source_version"]}).status_code == 403
    login_as("soc_manager")
    missing = transition(client, case_id, "closed")
    assert missing.status_code == 409 and "تقرير كامل معتمد" in str(missing.json)
    assert client.post(path + "/approve", json={"version": snapshot["source_version"]}).status_code == 200
    assert transition(client, case_id, "closed").status_code == 200
    assert client.get(base).json["status"] == "closed"
    assert client.post(base + "/records/asset", json={"name": "Late edit", "type": "workstation", "role": "defender"}).status_code == 409
    login_as("analyst")
    postmortem = client.post(base + "/postmortems", json={"version": client.get(base).json["version"]})
    assert postmortem.status_code == 201, postmortem.json
    corrective = client.post(
        base + "/records/corrective",
        json={
            "title": "Retain missing initial-access logs",
            "owner_id": user_ids["analyst"],
            "due_at": "2026-11-01T10:00:00Z",
            "status": "open",
            "root_cause_id": client.get(base + "/records?kind=root_cause").json["items"][0]["id"],
        },
    )
    assert corrective.status_code == 201, corrective.json
    login_as("soc_manager")
    reviewed = client.post(
        base + f"/postmortems/{postmortem.json['id']}/review",
        json={
            "version": 1,
            "case_version": client.get(base).json["version"],
            "executive_summary": "Retained evidence reviewed after closure",
            "lessons": "Improve initial-access source retention",
            "limitations": "Initial access remains unverified",
        },
    )
    assert reviewed.status_code == 409 and reviewed.json["error"]["code"] == "STALE_POSTMORTEM"
    login_as("analyst")
    current_draft = client.post(base + "/postmortems", json={"version": client.get(base).json["version"]})
    assert current_draft.status_code == 201
    login_as("soc_manager")
    reviewed = client.post(
        base + f"/postmortems/{current_draft.json['id']}/review",
        json={
            "version": 1,
            "case_version": client.get(base).json["version"],
            "executive_summary": "Retained evidence and corrective plan reviewed after closure",
            "lessons": "Improve initial-access source retention",
            "limitations": "Initial access remains unverified",
        },
    )
    assert reviewed.status_code == 200, reviewed.json
    resolved = client.patch(
        base + f"/records/{corrective.json['id']}",
        json={
            "version": 1,
            "payload": {**corrective.json["payload"], "status": "validated", "validation": "Verified source retention in a synthetic recurrence exercise"},
        },
    )
    assert resolved.status_code == 200, resolved.json
    assert client.get(base).json["status"] == "closed"
    assert client.get(path + "/files/pdf").data == pdf.data
    assert client.get(path).json["payload"] == snapshot
    assert transition(client, case_id, "reopened").status_code == 200
    assert client.get(path + "/files/pdf").data == pdf.data
    newer = request_report(client, case_id)
    assert newer.json["revision"] == 2
    assert client.get(path).json["payload"] == snapshot
    assert database.execute("SELECT content FROM autopsy_report_files WHERE report_id = ? AND format = 'pdf'", (report_id,)).fetchone()[0][:5] != b"%PDF-"


def test_stale_approval_and_closure_cannot_use_legacy_override(autopsy_case, app, client, login_as, monkeypatch):
    from socify import autopsy_worker

    monkeypatch.setattr(
        autopsy_worker, "compute_report", lambda payload: {kind: b"Test artifact for approval boundary" for kind in ("json", "html", "md", "pdf", "docx")}
    )
    assert transition(client, autopsy_case, "investigating").status_code == 200
    assert transition(client, autopsy_case, "awaiting_review").status_code == 200
    report = request_report(client, autopsy_case).json
    with app.app_context():
        run_autopsy_worker_once()
    version = client.get(f"/api/cases/{autopsy_case}").json["version"]
    assert (
        client.post(
            f"/api/cases/{autopsy_case}/records/hypothesis",
            json={"title": "Later observation", "statement": "New data changes the review basis", "assessment": "open"},
        ).status_code
        == 201
    )
    login_as("soc_manager")
    assert client.post(f"/api/cases/{autopsy_case}/reports/{report['id']}/approve", json={"version": version}).status_code == 409
    assert transition(client, autopsy_case, "closed", "/api/incidents").status_code == 409
    assert (
        client.post(
            f"/api/incidents/{autopsy_case}/transitions",
            json={
                "status": "closed",
                "reason": "Legacy override attempt",
                "override": True,
                "override_reason": "Must never bypass V3 approval",
                "version": client.get(f"/api/cases/{autopsy_case}").json["version"],
            },
        ).status_code
        == 422
    )
    newer = request_report(client, autopsy_case).json
    with app.app_context():
        run_autopsy_worker_once()
    version = client.get(f"/api/cases/{autopsy_case}").json["version"]
    own = f"/api/cases/{autopsy_case}/reports/{newer['id']}/approve"
    assert client.post(own, json={"version": version}).status_code == 403
    assert client.post(own, json={"version": version, "override_reason": "Documented small-team independent review exception"}).status_code == 200


def test_report_bola_redaction_and_revoked_worker_access(autopsy_case, app, client, login_as, user_ids):
    created = request_report(client, autopsy_case).json
    base = f"/api/cases/{autopsy_case}"
    login_as("auditor")
    assert client.get(base + f"/reports/{created['id']}").status_code == 404
    assert client.get(base + f"/jobs/{created['job_id']}").status_code == 404
    login_as("soc_manager")
    assert client.post(base + "/members", json={"user_id": user_ids["auditor"], "responsibility": "reviewer"}).status_code == 200
    login_as("auditor")
    assert "payload" not in client.get(base + f"/reports/{created['id']}").json
    assert request_report(client, autopsy_case).status_code == 403
    redacted = request_report(client, autopsy_case, "metadata_only_v1")
    assert redacted.status_code == 202
    login_as("soc_manager")
    assert client.post(base + f"/jobs/{created['job_id']}/cancel").status_code == 200
    login_as("auditor")
    with app.app_context():
        run_autopsy_worker_once()
    downloaded = client.get(base + f"/reports/{redacted.json['id']}/files/json")
    assert downloaded.status_code == 200
    assert downloaded.json["records"] == {}
    assert "reason" not in downloaded.json["context"]
    assert "Internal incident review" not in downloaded.text


@pytest.mark.parametrize("url", ["https://example.com/font.woff2", "file:///etc/passwd", "data:text/html;base64,QQ==", "data:font/woff2;base64,QQ=="])
def test_renderer_rejects_every_unbundled_resource(url):
    from weasyprint.urls import URLFetchingError

    with pytest.raises(URLFetchingError):
        bundled_report_asset_fetcher(url)


def test_evidence_based_metrics_do_not_invent_unknown_or_negative_durations():
    assert duration(None, "2026-10-24T12:00:00Z") is None
    assert duration("2026-10-24T12:00:00Z", "2026-10-24T11:00:00Z") is None
    metrics = case_metrics(
        {
            "foothold": [{"payload": {"first_observed_at": "2026-10-24T10:00:00Z", "evidence_id": 1}}],
            "response": [{"payload": {"phase": "detection", "status": "succeeded", "performed_at": "2026-10-24T10:03:00Z", "evidence_id": 2}}],
        }
    )
    assert metrics["detection_delay_seconds"] == 180
    assert metrics["containment_delay_seconds"] is None
    assert metrics["acknowledgement_delay_seconds"] is None
