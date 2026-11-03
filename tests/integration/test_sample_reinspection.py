import base64
import hashlib
import io
import json

import pytest

from socify.autopsy_static_analysis import inspect_static_bytes, validate_yara
from socify.autopsy_worker import run_autopsy_worker_once


def inspect(client, base, content=b"Retained maintenance note", name="review.txt", **fields):
    return client.post(base + "/quick-file-triage", data={"file": (io.BytesIO(content), name, "text/plain"), **fields})


def test_identical_file_inspection_and_retained_sample_reuse_do_not_change_case_or_report(autopsy_case, client):
    base = f"/api/cases/{autopsy_case}"
    first = inspect(client, base)
    assert first.status_code == 201
    version = client.get(base).json["version"]
    report = client.post(base + "/reports", json={"version": version, "profile": "metadata_only_v1"}).json
    before = client.get(base + f"/reports/{report['id']}").json["payload"]
    duplicate = inspect(client, base)
    assert duplicate.status_code == 200 and duplicate.json["duplicate"]
    retained = client.post(base + f"/samples/{first.json['sample_id']}/quick-triage", json={})
    assert retained.status_code == 200 and retained.json["id"] == first.json["id"]
    assert client.get(base).json["version"] == version
    assert client.get(base + f"/reports/{report['id']}").json["payload"] == before
    assert inspect(client, base, b"Changed retained maintenance note").status_code == 201
    assert client.get(base).json["version"] > version


def test_renamed_executable_keeps_a_new_filename_risk_assessment_without_duplicate_evidence(autopsy_case, client):
    base = f"/api/cases/{autopsy_case}"
    content = b"MZ" + b"\x00" * 70
    first = inspect(client, base, content, "review.exe")
    changed = inspect(client, base, content, "review.pdf")
    assert changed.status_code == 201
    assert changed.json["triage"]["extension_mismatch"] and not first.json["triage"]["extension_mismatch"]
    assert changed.json["sample_id"] == first.json["sample_id"] and changed.json["id"] != first.json["id"]


def test_selected_published_yara_pack_is_actually_applied_and_retained(autopsy_case, client, database, user_ids):
    # A published immutable package fixture, not a simulated user or mocked inspection result.
    source = 'rule Retained_Marker { strings: $a = "RETAINED_MARKER" condition: $a }'
    fixtures = {"positive": [base64.b64encode(b"RETAINED_MARKER").decode()], "negative": [base64.b64encode(b"Routine bytes").decode()]}
    validation = validate_yara({"rules": source, "fixtures": fixtures})
    assert validation["valid"]
    workspace = database.execute("SELECT workspace_id FROM users WHERE id=?", (user_ids["analyst"],)).fetchone()[0]
    pack = database.execute(
        "INSERT INTO autopsy_yara_packs(workspace_id,name,version,source,license,origin,sha256,validation,created_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            workspace,
            "Retained marker",
            1,
            source,
            "Internal",
            "Local fixture",
            hashlib.sha256(source.encode()).hexdigest(),
            json.dumps(validation),
            user_ids["analyst"],
            "2026-11-03T00:00:00Z",
        ),
    ).lastrowid
    base = f"/api/cases/{autopsy_case}"
    matching = inspect(client, base, b"RETAINED_MARKER", yara_pack_id=str(pack))
    assert matching.status_code == 201, matching.json
    assert matching.json["triage"]["yara_matches"][0]["rule"] == "Retained_Marker"
    assert matching.json["triage"]["yara_pack"]["id"] == pack
    repeated = client.post(base + f"/samples/{matching.json['sample_id']}/quick-triage", json={"yara_pack_id": pack})
    assert repeated.status_code == 200 and repeated.json["id"] == matching.json["id"]


@pytest.mark.parametrize("value,status", [("unknown", 422), ("0", 422), ("99999999", 404)])
def test_invalid_selected_pack_never_silently_runs_another_rule_set(autopsy_case, client, value, status):
    base = f"/api/cases/{autopsy_case}"
    assert inspect(client, base, yara_pack_id=value).status_code == status
    assert client.get(base + "/samples").json["items"] == []


def test_sample_progress_is_retained_and_cancel_retry_keep_the_same_job(autopsy_case, client):
    base = f"/api/cases/{autopsy_case}"
    sample = client.post(base + "/samples", data={"file": (io.BytesIO(b"Retained bytes"), "review.bin")}).json
    queued = client.post(base + f"/samples/{sample['id']}/analyze", json={}).json
    path = base + f"/jobs/{queued['id']}"
    assert client.get(base + "/samples").json["items"][0]["last_job"] == client.get(path).json
    assert client.get(path).json["can_cancel"] and not client.get(path).json["can_retry"]
    assert client.post(path + "/cancel").status_code == 200
    assert client.get(path).json["can_retry"] and not client.get(path).json["can_cancel"]
    assert client.post(path + "/retry").status_code == 200
    assert client.get(path).json["state"] == "queued"
    other = client.post("/api/cases", json={"title": "Separate evidence"}).json["id"]
    assert client.get(f"/api/cases/{other}/jobs/{queued['id']}").status_code == 404
    assert client.get(f"/api/cases/{other}/samples").json["items"] == []


def test_read_only_creator_cannot_restart_a_cancelled_sample_job(autopsy_case, client, login_as):
    base = f"/api/cases/{autopsy_case}"
    sample = client.post(base + "/samples", data={"file": (io.BytesIO(b"Retained bytes"), "review.bin")}).json
    queued = client.post(base + f"/samples/{sample['id']}/analyze", json={}).json
    path = base + f"/jobs/{queued['id']}"
    assert client.post(path + "/cancel").status_code == 200
    login_as("soc_manager")
    assert client.put("/api/team/roles/analyst", json={"permissions": ["cases.read"]}).status_code == 200
    login_as("analyst")
    assert not client.get(path).json["can_retry"]
    assert client.post(path + "/retry").status_code == 403
    assert client.get(path).json["state"] == "cancelled"


def test_queued_sample_cannot_modify_a_closed_case(autopsy_case, app, client, database, monkeypatch):
    base = f"/api/cases/{autopsy_case}"
    sample = client.post(base + "/samples", data={"file": (io.BytesIO(b"Retained bytes"), "review.bin")}).json
    queued = client.post(base + f"/samples/{sample['id']}/analyze", json={}).json
    database.execute("UPDATE incident_cases SET status='closed' WHERE id=?", (autopsy_case,))
    version = client.get(base).json["version"]
    calls = []
    monkeypatch.setattr("socify.autopsy_worker.compute_sample", lambda payload: calls.append(payload))
    with app.app_context():
        run_autopsy_worker_once("closed-case-analysis-guard")
    job = client.get(base + f"/jobs/{queued['id']}").json
    assert job["state"] == "failed" and job["error_code"] == "ACCESS_REVOKED"
    assert not job["can_retry"] and not calls
    assert client.get(base + "/records?kind=analysis").json["items"] == []
    assert client.get(base).json["version"] == version


@pytest.mark.parametrize("source", ["rule Broken { invalid syntax }", "x" * 65537], ids=["invalid-rule", "oversized-rules"])
def test_failed_yara_evaluation_is_not_presented_as_no_matches(source):
    with pytest.raises(ValueError, match="YARA"):
        inspect_static_bytes("retained.txt", b"Retained sample", yara_source=source)
