import base64
import hashlib
import io
import json
import sqlite3

import pytest

from socify.autopsy_samples import parse_vt_report
from socify.autopsy_static_analysis import analyze_sample
from socify.autopsy_worker import run_autopsy_worker_once


def sample_upload(client, case_id, content=b"Synthetic specimen; never execute", name="sample.bin"):
    return client.post(f"/api/cases/{case_id}/samples", data={"file": (io.BytesIO(content), name)})


def vt_document(sha):
    return {
        "data": {
            "id": sha,
            "type": "file",
            "attributes": {
                "sha256": sha,
                "last_analysis_date": 1790000000,
                "last_analysis_stats": {"malicious": 1, "undetected": 4},
                "last_analysis_results": {"Synthetic engine": {"category": "malicious", "result": "Synthetic.Test.Signature"}},
            },
        }
    }


def test_quarantine_local_analysis_and_manual_virustotal_join_the_case(autopsy_case, app, client, login_as, database):
    content = b"Synthetic EICAR-STANDARD-ANTIVIRUS-TEST-FILE acceptance marker; not malware"
    created = sample_upload(client, autopsy_case, content)
    assert created.status_code == 201, created.json
    base = f"/api/cases/{autopsy_case}"
    sample_id, digest = created.json["id"], hashlib.sha256(content).hexdigest()
    assert created.json["sha256"] == digest
    assert client.get(base + "/samples").json["items"][0]["sha256"] == digest
    assert sample_upload(client, autopsy_case, content).json["duplicate"]
    assert client.get(base + f"/samples/{sample_id}/download").status_code == 403
    assert client.get(f"/api/incidents/{autopsy_case}/evidence/{created.json['evidence_id']}/content").status_code == 409
    queued = client.post(base + f"/samples/{sample_id}/analyze", json={})
    assert queued.status_code == 202
    assert client.post(base + f"/samples/{sample_id}/analyze", json={}).json["duplicate"]
    with app.app_context():
        assert run_autopsy_worker_once("sample-integration") == queued.json["id"]
    assert client.get(base + f"/jobs/{queued.json['id']}").json["state"] == "completed"
    records = client.get(base + "/records?kind=analysis").json["items"]
    assert records[0]["payload"]["sha256"] == digest
    assert records[0]["payload"]["execution"] == "never executed"
    assert records[0]["payload"]["yara_matches"][0]["rule"] == "SOCify_EICAR_Test_Marker"
    assert records[0]["payload"]["evidence_id"] == created.json["evidence_id"]
    raw_report = b"\xef\xbb\xbf" + json.dumps(vt_document(digest)).encode()

    def upload_report():
        return client.post(base + "/reputation/virustotal", data={"sample_id": str(sample_id), "file": (io.BytesIO(raw_report), "vt.json")})

    imported = upload_report()
    assert imported.status_code == 201, imported.json
    assert imported.json["payload"]["authenticity"].startswith("unverified")
    assert imported.json["payload"]["source_sha256"] == hashlib.sha256(raw_report).hexdigest()
    assert upload_report().json["duplicate"]
    source_id = imported.json["payload"]["evidence_id"]
    version = client.get(base).json["version"]
    assert client.get(f"/api/incidents/{autopsy_case}/evidence/{source_id}/content").data == raw_report
    assert client.get(base).json["version"] == version
    login_as("soc_manager")
    downloaded = client.get(base + f"/samples/{sample_id}/download")
    assert downloaded.data == content
    assert downloaded.headers["X-SOCify-Quarantined"] == "true"
    assert downloaded.headers["Content-Security-Policy"] == "default-src 'none'; sandbox"
    assert "attachment" in downloaded.headers["Content-Disposition"]
    assert database.execute("SELECT ciphertext FROM autopsy_samples WHERE id = ?", (sample_id,)).fetchone()[0] != content
    with pytest.raises(sqlite3.IntegrityError):
        database.execute("UPDATE autopsy_samples SET ciphertext = ? WHERE id = ?", (b"modified", sample_id))
    login_as("auditor")
    assert client.get(base + "/samples").status_code == 404
    assert sample_upload(client, autopsy_case).status_code == 403


@pytest.mark.parametrize("name,content", [("../sample.bin", b"x"), ("empty.bin", b"")])
def test_sample_rejects_paths_and_empty_bytes(autopsy_case, client, name, content):
    assert sample_upload(client, autopsy_case, content, name).status_code == 422


def test_browser_windows_filename_is_canonicalized_without_using_a_filesystem_path(autopsy_case, client):
    created = sample_upload(client, autopsy_case, b"Synthetic", "a\\sample.bin")
    assert created.status_code == 201
    name = client.get(f"/api/cases/{autopsy_case}/samples").json["items"][0]["filename"]
    assert name.endswith("sample.bin") and "/" not in name and "\\" not in name


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(data=[]),
        lambda d: d["data"].update(id="f" * 64),
        lambda d: d["data"]["attributes"].update(sha256="f" * 64),
        lambda d: d["data"]["attributes"].update(last_analysis_date=True),
        lambda d: d["data"]["attributes"].update(last_analysis_stats={"malicious": -1}),
        lambda d: d["data"]["attributes"].update(last_analysis_stats={"malicious": True}),
        lambda d: d["data"]["attributes"].update(last_analysis_results={"bad": []}),
        lambda d: d["data"]["attributes"].update(last_analysis_results={"bad": {"category": "unknown-category"}}),
    ],
)
def test_reputation_invalid_or_mismatched_reports_fail_closed(change):
    digest = "a" * 64
    document = vt_document(digest)
    change(document)
    with pytest.raises(ValueError):
        parse_vt_report(json.dumps(document).encode(), digest)


def test_static_analysis_is_bounded_and_does_not_claim_malware_absence():
    content = b"MZ" + b"\x00" * 58 + (64).to_bytes(4, "little") + b"PE\x00\x00" + b"\x4c\x01\x02\x00" + b"\x00" * 16
    payload = {"content": base64.b64encode(content).decode(), "sha256": hashlib.sha256(content).hexdigest(), "sample_id": 1, "evidence_id": 1}
    result = analyze_sample(payload)
    assert result["pe_header"]["machine"] == 0x14C
    assert result["pe_header"]["sections"] == 2
    assert result["yara_matches"] == []
    assert result["execution"] == "never executed"
    assert result["limitations"]
    with pytest.raises(ValueError):
        analyze_sample({**payload, "sha256": "0" * 64})
    with pytest.raises(ValueError):
        analyze_sample({**payload, "rules": "a" * 65537})
    import yara

    with pytest.raises(yara.SyntaxError):
        analyze_sample({**payload, "rules": 'include "/etc/passwd"'})
