import hashlib
import io
import json
import struct
import zipfile

import pytest

from socify import autopsy_capsules
from socify.autopsy_worker import run_autopsy_worker_once


def rebuild(content, mutation):
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        files = {name: archive.read(name) for name in archive.namelist() if name != "manifest.json"}
        manifest = json.loads(archive.read("manifest.json"))
    data = json.loads(files["data.json"])
    mutation(data, files)
    files["data.json"] = json.dumps(data).encode()
    manifest["members"] = [{"path": path, "size": len(value), "sha256": hashlib.sha256(value).hexdigest()} for path, value in files.items()]
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        for path, value in files.items():
            archive.writestr(path, value)
    return output.getvalue()


def test_complete_backup_reencrypts_samples_evidence_reports_and_keeps_legacy_bytes(autopsy_case, app, client, login_as, database, user_ids):
    base = f"/api/cases/{autopsy_case}"
    login_as("soc_manager")
    imported = client.post(base + "/imports", json={"filename": "retained.json", "content": '[{"title":"Retained forensic source"}]'}).json
    event = client.get(base + "/logs").json["items"][0]["id"]
    assert client.post(base + f"/logs/{event}/exhibit", json={}).status_code == 201
    sample = b"Synthetic quarantined evidence, never executable"
    uploaded = client.post(base + "/samples", data={"file": (io.BytesIO(sample), "synthetic.bin")})
    assert uploaded.status_code == 201, uploaded.json
    legacy = '{"synthetic":"retained legacy report bytes"}'
    database.execute(
        "INSERT INTO case_reports(case_id,revision,format,content,sha256,created_by,created_at) VALUES (?,1,'json',?,?,?,'2026-10-24T00:00:00Z')",
        (autopsy_case, legacy, hashlib.sha256(legacy.encode()).hexdigest(), user_ids["soc_manager"]),
    )
    report = client.post(base + "/reports", json={"version": client.get(base).json["version"]})
    assert report.status_code == 202
    with app.app_context():
        run_autopsy_worker_once()
    original_pdf = client.get(base + f"/reports/{report.json['id']}/files/pdf").data
    assert original_pdf.startswith(b"%PDF-")
    exported = client.get(base + "/capsule?profile=backup")
    assert exported.status_code == 200
    manifest, snapshot, files = autopsy_capsules.inspect_capsule(exported.data)
    assert files[f"samples/{uploaded.json['id']}.bin"] == sample
    assert files[f"reports/{report.json['id']}/pdf"] == original_pdf
    assert any(value == legacy.encode() for name, value in files.items() if name.startswith("legacy_reports/"))
    response = client.post("/api/cases/import-capsule", data={"file": (io.BytesIO(exported.data), "backup.zip")})
    assert response.status_code == 201, response.json
    restored = f"/api/cases/{response.json['case_id']}"
    new_sample = response.json["id_map"]["samples"][str(uploaded.json["id"])]
    assert client.get(restored + f"/samples/{new_sample}/download").data == sample
    archive = restored + f"/capsules/{response.json['capsule_id']}"
    assert client.get(archive + f"/file/reports/{report.json['id']}/pdf").data == original_pdf
    assert client.get(restored).json["reports"] == []
    assert client.get(restored + "/capsules").json["items"][0]["profile"] == "backup"
    restored_original = response.json["id_map"]["imports"][str(imported["id"])]
    assert client.get(restored + f"/imports/{restored_original}/original").data == files[f"originals/{imported['id']}.bin"]
    login_as("analyst")
    assert client.get(archive + "/snapshot").status_code == 404


@pytest.mark.parametrize(
    "attack",
    [
        "schema",
        "case_type",
        "list_type",
        "row_type",
        "table_type",
        "id_bool",
        "id_duplicate",
        "record_payload",
        "revision_payload",
        "event_json",
        "evidence_hash",
        "private_revision",
        "team_report_payload",
        "team_report_file",
        "event_link",
        "missing_original",
    ],
)
def test_capsule_rejects_semantically_invalid_even_with_correct_manifest_hashes(autopsy_case, client, login_as, database, attack):
    base = f"/api/cases/{autopsy_case}"
    client.post(base + "/imports", json={"filename": "source.json", "content": '[{"title":"Synthetic retained source"}]'})
    client.post(base + "/records/war_room", json={"title": "Decision", "body": "Synthetic shared decision", "visibility": "team"})
    login_as("soc_manager")
    exported = client.get(base + "/capsule?profile=team").data

    def mutate(data, files):
        if attack == "schema":
            data["unknown"] = True
        elif attack == "case_type":
            data["case"]["severity"] = []
        elif attack == "list_type":
            data["actors"] = {}
        elif attack == "row_type":
            data["actors"] = [1]
        elif attack == "table_type":
            data["tables"]["case_notes"] = {}
        elif attack == "id_bool":
            data["events"][0]["id"] = True
        elif attack == "id_duplicate":
            data["events"] += data["events"]
        elif attack == "record_payload":
            data["tables"]["autopsy_records"][0]["payload"] = "[]"
        elif attack == "revision_payload":
            data["revisions"][0]["payload"] = "[]"
        elif attack == "event_json":
            data["events"][0]["tags"] = "{}"
        elif attack == "evidence_hash":
            data["tables"]["case_evidence"][0]["sha256"] = "invalid"
        elif attack == "private_revision":
            data["revisions"][0]["payload"] = '{"visibility":"private"}'
        elif attack == "team_report_payload":
            data["tables"]["autopsy_reports"] = [{"id": 1, "payload": "{}"}]
        elif attack == "team_report_file":
            files["reports/1/json"] = b"{}"
        elif attack == "event_link":
            data["event_links"][0]["event_id"] = 999999
        elif attack == "missing_original":
            files.pop(next(key for key in files if key.startswith("originals/")))

    bad = rebuild(exported, mutate)
    before = database.execute("SELECT COUNT(*) FROM incident_cases").fetchone()[0]
    response = client.post("/api/cases/import-capsule", data={"file": (io.BytesIO(bad), "tampered.zip")})
    assert response.status_code == 422, (attack, response.json)
    assert database.execute("SELECT COUNT(*) FROM incident_cases").fetchone()[0] == before


def test_capsule_resource_limits_and_bad_requests_fail_closed(autopsy_case, client, login_as, monkeypatch):
    login_as("soc_manager")
    base = f"/api/cases/{autopsy_case}"
    assert client.get(base + "/capsule?profile=unknown").status_code == 422
    assert client.post("/api/cases/import-capsule", data={}).status_code == 422
    assert client.post("/api/cases/import-capsule", data={"file": (io.BytesIO(b"not-a-zip"), "bad.zip")}).status_code == 422
    assert client.get(base + "/capsules/9999/snapshot").status_code == 404
    assert client.get(base + "/capsules/9999/file/data.json").status_code == 404
    monkeypatch.setattr(autopsy_capsules, "MAX_ROWS", 0)
    assert client.get(base + "/capsule").status_code == 422
    with pytest.raises(ValueError):
        autopsy_capsules.add_file({}, "data.json", b"x" * (autopsy_capsules.MAX_MEMBER + 1))
    for raw in (None, b"{", b"NaN", b'{"one":1,"one":2}', '{"nested":' * 100 + "0" + "}" * 100):
        with pytest.raises(ValueError):
            autopsy_capsules.decode_json(raw)


@pytest.mark.parametrize("attack", ["declared_count", "actual_count", "record_length", "signature", "truncated", "zip64", "comment"])
def test_zip_directory_is_bounded_before_zipfile_allocates_entries(autopsy_case, client, login_as, monkeypatch, attack):
    login_as("soc_manager")
    original = client.get(f"/api/cases/{autopsy_case}/capsule").data
    content = bytearray(original)
    offset = struct.unpack_from("<I", content, len(content) - 6)[0]
    if attack == "declared_count":
        struct.pack_into("<H", content, len(content) - 12, 1)
    elif attack == "actual_count":
        struct.pack_into("<2H", content, len(content) - 14, 3, 3)
    elif attack == "record_length":
        struct.pack_into("<H", content, offset + 28, 201)
    elif attack == "signature":
        content[offset : offset + 4] = b"BAD!"
    elif attack == "truncated":
        content = content[:20]
    elif attack == "zip64":
        struct.pack_into("<2H", content, len(content) - 14, 65535, 65535)
    else:
        content.extend(b"comment")
    called = []
    monkeypatch.setattr(zipfile, "ZipFile", lambda *_args, **_kwargs: called.append(True))
    with pytest.raises(ValueError):
        autopsy_capsules.inspect_capsule(bytes(content))
    assert called == []
