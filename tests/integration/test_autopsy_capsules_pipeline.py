import hashlib
import io
import json
import sqlite3
import stat
import zipfile

import pytest

from socify.autopsy_capsules import inspect_capsule


def upload_capsule(client, content):
    return client.post("/api/cases/import-capsule", data={"file": (io.BytesIO(content), "case.zip")})


def test_capsule_team_backup_restore_provenance_and_no_foreign_authority(autopsy_case, client, login_as, database):
    base = f"/api/cases/{autopsy_case}"
    for visibility in ("private", "team"):
        assert (
            client.post(
                base + "/records/war_room", json={"title": "Decision", "body": f"Synthetic {visibility} decision", "visibility": visibility}
            ).status_code
            == 201
        )
    original = b'[{"title":"Retained synthetic source","source_ip":"192.0.2.8"}]'
    assert client.post(base + "/imports", json={"filename": "original.json", "content": original.decode()}).status_code == 201
    login_as("soc_manager")
    exported = client.get(base + "/capsule?profile=team")
    assert exported.status_code == 200, exported.json
    assert exported.headers["X-Content-SHA256"] == hashlib.sha256(exported.data).hexdigest()
    manifest, snapshot, files = inspect_capsule(exported.data)
    assert manifest["profile"] == "team"
    assert "Synthetic private decision" not in files["data.json"].decode()
    assert "Synthetic team decision" in files["data.json"].decode()
    assert any(value == original for key, value in files.items() if key.startswith("originals/"))
    restored = upload_capsule(client, exported.data)
    assert restored.status_code == 201, restored.json
    case_id, archive_id = restored.json["case_id"], restored.json["capsule_id"]
    assert case_id != autopsy_case
    assert restored.json["foreign_approvals_trusted"] is False
    assert client.get(f"/api/cases/{case_id}").json["status"] == "open"
    restored_logs = client.get(f"/api/cases/{case_id}/logs").json
    assert restored_logs["total"] == 1
    assert restored_logs["items"][0]["id"] != snapshot["events"][0]["id"]
    archived = f"/api/cases/{case_id}/capsules/{archive_id}"
    assert client.get(archived + "/snapshot?section=autopsy_records").json["total"] == 1
    assert client.get(archived + "/snapshot?section=manifest").json["total"] == len(files)
    assert client.get(archived + "/snapshot?section=unknown").status_code == 422
    assert client.get(archived + "/snapshot?limit=0").status_code == 422
    original_path = next(key for key in files if key.startswith("originals/"))
    assert client.get(archived + "/file/" + original_path).data == original
    assert client.get(archived + "/file/originals/99999.bin").status_code == 404
    assert len(client.get(f"/api/cases/{case_id}/capsules").json["items"]) == 1
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        database.execute("DELETE FROM autopsy_capsule_archives WHERE id=?", (archive_id,))
    complete = client.get(base + "/capsule?profile=backup")
    assert complete.status_code == 200
    assert "Synthetic private decision" in inspect_capsule(complete.data)[2]["data.json"].decode()
    assert upload_capsule(client, complete.data).status_code == 201
    login_as("analyst")
    assert client.get(base + "/capsule?profile=backup").status_code == 403
    assert upload_capsule(client, complete.data).status_code == 403
    assert client.get(archived + "/snapshot").status_code == 404


def rewrite_archive(content, mutation):
    with zipfile.ZipFile(io.BytesIO(content)) as source:
        files = {name: source.read(name) for name in source.namelist()}
    mutation(files)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for key, value in files.items():
            archive.writestr(key, value)
    return output.getvalue()


@pytest.mark.parametrize("attack", ["digest", "unlisted", "traversal", "duplicate_json", "type", "missing", "symlink", "duplicate_member"])
def test_capsule_rejects_tampering_traversal_and_invalid_schema_without_partial_restore(autopsy_case, client, login_as, database, attack):
    login_as("soc_manager")
    content = client.get(f"/api/cases/{autopsy_case}/capsule?profile=team").data
    before = database.execute("SELECT COUNT(*) FROM incident_cases").fetchone()[0]

    def mutate(files):
        if attack == "digest":
            files["data.json"] += b" "
        elif attack in {"unlisted", "traversal"}:
            files["unlisted.txt" if attack == "unlisted" else "../outside"] = b"synthetic"
        elif attack == "duplicate_json":
            files["manifest.json"] = b'{"version":1,"version":1}'
        elif attack == "type":
            manifest = json.loads(files["manifest.json"])
            manifest["version"] = True
            files["manifest.json"] = json.dumps(manifest).encode()
        elif attack == "missing":
            files.pop("data.json")

    content = rewrite_archive(content, mutate)
    if attack in {"symlink", "duplicate_member"}:
        output = io.BytesIO(content)
        with zipfile.ZipFile(output, "a") as archive:
            entry = zipfile.ZipInfo("originals/123.bin" if attack == "symlink" else "manifest.json")
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(entry, b"/etc/passwd")
        content = output.getvalue()
    response = upload_capsule(client, content)
    assert response.status_code == 422, response.json
    assert database.execute("SELECT COUNT(*) FROM incident_cases").fetchone()[0] == before


def test_batch_access_blocks_indirect_disclosure_and_filters_all_log_paths(autopsy_case, client, login_as, user_ids):
    base = f"/api/cases/{autopsy_case}"
    login_as("soc_manager")
    jobs = []
    for label in ("Visible batch", "Restricted batch"):
        response = client.post(base + "/imports", json={"filename": "batch.json", "content": json.dumps([{"title": label, "source_ip": "192.0.2.8"}])})
        assert response.status_code == 201
        jobs.append(response.json["id"])
    policy = {"restricted": True, "members": [], "reason": "Confidential batch segregation"}
    assert client.put(base + f"/imports/{jobs[1]}/access", json=policy).status_code == 200
    login_as("analyst")
    summary = client.get(base).json
    assert summary["full_case_access"] is False
    assert summary["counts"]["events"] == 1
    assert not summary["evidence"] and not summary["history"]
    assert len(client.get(base + "/imports").json["items"]) == 1
    assert client.get(base + f"/imports/{jobs[1]}").status_code == 404
    logs = client.get(base + "/logs").json
    assert logs["total"] == 1 and logs["items"][0]["title"] == "Visible batch"
    assert client.get(base + "/timeline").json["total"] == 1
    assert "Restricted batch" not in client.get(base + "/logs/export?format=json").text
    for path in ("/records", "/custody", "/graph", "/observables", "/samples", "/capsules", "/workflow", "/alerts"):
        assert client.get(base + path).status_code == 403, path
    assert client.post(base + "/reports", json={"version": summary["version"]}).status_code == 403
    login_as("soc_manager")
    assert client.put(base + f"/imports/{jobs[1]}/access", json={**policy, "members": [user_ids["analyst"]]}).status_code == 200
    login_as("analyst")
    assert client.get(base).json["full_case_access"] is True
    assert client.get(base + "/logs").json["total"] == 2


def test_derived_activation_preserves_original_and_history(autopsy_case, client, login_as):
    base = f"/api/cases/{autopsy_case}"
    content = '[{"title":"Derived source"}]'
    old = client.post(base + "/imports", json={"filename": "source.json", "content": content}).json
    new = client.post(base + "/imports", json={"filename": "source.json", "content": content, "source_timezone": "Asia/Riyadh"}).json
    assert client.get(base + "/logs").json["total"] == 1
    assert client.get(base + f"/logs?job_id={old['id']}").json["total"] == 1
    login_as("soc_manager")
    activated = client.post(
        base + f"/imports/{old['id']}/activate", json={"version": client.get(base).json["version"], "reason": "Restore independently reviewed derivation"}
    )
    assert activated.status_code == 200
    assert client.get(base + "/logs").json["items"][0]["id"] != client.get(base + f"/logs?job_id={new['id']}").json["items"][0]["id"]
    assert client.get(base + f"/imports/{old['id']}/original").data == content.encode()
