import hashlib
import json
from concurrent.futures import ThreadPoolExecutor

import pytest


def observation(identifier="gateway-001", **changes):
    return {
        "source": "gateway-export",
        "external_id": identifier,
        "timestamp": "2026-11-02T08:00:00Z",
        "hostname": "EXPORT-GATEWAY",
        "title": "Retained gateway observation",
        **changes,
    }


def upload(client, case_id, rows, *, pretty=False, **options):
    content = json.dumps(rows, sort_keys=pretty, indent=2 if pretty else None, ensure_ascii=False)
    response = client.post(f"/api/cases/{case_id}/imports", json={"filename": "gateway.json", "content": content, **options})
    assert response.status_code in {200, 201}, response.json
    return response.json, content.encode()


def logs(client, case_id, suffix=""):
    result = client.get(f"/api/cases/{case_id}/logs" + suffix)
    assert result.status_code == 200, result.json
    return result.json


def test_reordered_json_retains_originals_occurrences_rules_receipts_exports_and_history(autopsy_case, client, database):
    base = f"/api/cases/{autopsy_case}"
    first = observation(process_name="powershell.exe", command_line="powershell.exe -enc AAAA")
    second = observation("gateway-002", timestamp="2026-11-02T08:01:00Z")
    old_job, old_bytes = upload(client, autopsy_case, [first, second])
    original = logs(client, autopsy_case)["items"]
    alert_before = [tuple(row) for row in database.execute("SELECT id,alert_id,dedup_key,evidence FROM alerts WHERE owner_case_id=?", (autopsy_case,))]
    assert alert_before
    before_outbox = database.execute("SELECT COUNT(*) FROM outbox_events WHERE event_type='event.created'").fetchone()[0]
    third = observation("gateway-003", timestamp="2026-11-02T08:02:00Z")
    job, content = upload(client, autopsy_case, [second, first, third], pretty=True)
    assert (job["accepted"], job["skipped"], job["rejected"], job["total"]) == (1, 2, 0, 3)
    current = logs(client, autopsy_case)
    assert current["total"] == 3
    assert [row["id"] for row in current["items"][:2]] == [row["id"] for row in original]
    assert [tuple(row) for row in database.execute("SELECT id,alert_id,dedup_key,evidence FROM alerts WHERE owner_case_id=?", (autopsy_case,))] == alert_before
    assert database.execute("SELECT COUNT(*) FROM outbox_events WHERE event_type='event.created'").fetchone()[0] == before_outbox + 1
    occurrences = database.execute(
        "SELECT job_id,disposition,COUNT(*) FROM autopsy_event_occurrences WHERE case_id=? GROUP BY job_id,disposition", (autopsy_case,)
    ).fetchall()
    assert sorted(tuple(row) for row in occurrences) == sorted([(old_job["id"], "accepted", 2), (job["id"], "accepted", 1), (job["id"], "repeated", 2)])
    for receipt, payload, count in ((old_job, old_bytes, 2), (job, content, 3)):
        downloaded = client.get(base + f"/imports/{receipt['id']}/original")
        assert downloaded.data == payload
        assert downloaded.headers["X-Evidence-SHA256"] == hashlib.sha256(payload).hexdigest()
        assert logs(client, autopsy_case, f"?job_id={receipt['id']}")["total"] == count
        exported = client.get(base + f"/logs/export?format=json&redacted=0&job_id={receipt['id']}").json
        assert len(exported) == count
        assert {row["provenance"]["file_sha256"] for row in exported} == {hashlib.sha256(payload).hexdigest()}
    assert len(client.get(base + "/logs/export?format=json&redacted=0").json) == 3
    retry, _ = upload(client, autopsy_case, [second, first, third], pretty=True)
    assert retry["duplicate"] is True and retry["id"] == job["id"]
    assert database.execute("SELECT COUNT(*) FROM autopsy_event_occurrences WHERE case_id=?", (autopsy_case,)).fetchone()[0] == 5


@pytest.mark.parametrize(
    "change",
    [
        {"source": "other-gateway"},
        {"external_id": "gateway-002"},
        {"external_id": 1},
        {"timestamp": "2026-11-02T08:00:01Z"},
        {"hostname": "OTHER"},
        {"command_line": "different"},
        {"arbitrary": {"nested": [1, 2]}},
        {"title": "Different meaning"},
        {"outcome": "failed"},
    ],
)
def test_same_id_never_drops_changed_source_or_any_facts(autopsy_case, client, change):
    upload(client, autopsy_case, [observation()])
    job, _ = upload(client, autopsy_case, [observation(**change)], pretty=True)
    assert (job["accepted"], job["skipped"]) == (1, 0)
    assert logs(client, autopsy_case)["total"] == 2


@pytest.mark.parametrize("missing", ["source", "external_id", "timestamp"])
def test_missing_identity_is_not_inferred_from_filename_or_row_number(autopsy_case, client, missing):
    row = observation()
    del row[missing]
    upload(client, autopsy_case, [row])
    second, _ = upload(client, autopsy_case, [row], pretty=True)
    assert (second["accepted"], second["skipped"]) == (1, 0)
    assert logs(client, autopsy_case)["total"] == 2


def test_duplicate_rows_keep_each_occurrence_and_different_case_keeps_own_event(autopsy_case, client, database):
    job, _ = upload(client, autopsy_case, [observation(), observation()])
    assert (job["accepted"], job["skipped"]) == (1, 1)
    assert database.execute("SELECT COUNT(*) FROM autopsy_event_occurrences WHERE job_id=?", (job["id"],)).fetchone()[0] == 2
    other = client.post("/api/cases", json={"title": "Independent incident"}).json["id"]
    other_job, _ = upload(client, other, [observation()])
    assert other_job["accepted"] == 1
    assert logs(client, other)["items"][0]["id"] != logs(client, autopsy_case)["items"][0]["id"]


def test_occurrence_visibility_does_not_leak_restricted_original_or_metadata(autopsy_case, client, login_as, user_ids):
    base = f"/api/cases/{autopsy_case}"
    login_as("soc_manager")
    hidden, hidden_bytes = upload(client, autopsy_case, [observation()])
    policy = {"restricted": True, "members": [], "reason": "Confidential retained origin"}
    assert client.put(base + f"/imports/{hidden['id']}/access", json=policy).status_code == 200
    login_as("analyst")
    assert logs(client, autopsy_case)["total"] == 0
    visible, visible_bytes = upload(client, autopsy_case, [observation()], pretty=True)
    assert (visible["accepted"], visible["skipped"]) == (0, 1)
    assert logs(client, autopsy_case)["total"] == 1
    event = logs(client, autopsy_case)["items"][0]
    for endpoint in ("/logs", f"/logs/{event['id']}", "/logs/export?format=json&redacted=0"):
        response = client.get(base + endpoint)
        assert response.status_code == 200, response.json
        assert hashlib.sha256(hidden_bytes).hexdigest() not in response.text
        assert hashlib.sha256(visible_bytes).hexdigest() in response.text
    assert event["import_job_id"] == visible["id"] and event["created_by"] == user_ids["analyst"]
    timeline = client.get(base + "/timeline")
    assert timeline.status_code == 200 and timeline.json["total"] == 1
    assert timeline.json["items"][0]["ingested_at"] == event["ingested_at"]
    # A guessed batch selector cannot force fallback to the hidden primary origin.
    guessed = client.get(base + f"/logs/{event['id']}?job_id={hidden['id']}")
    assert guessed.status_code == 200 and hashlib.sha256(hidden_bytes).hexdigest() not in guessed.text
    oversized = client.get(base + f"/logs/{event['id']}?job_id=" + "9" * 5000)
    assert oversized.status_code == 200 and hashlib.sha256(hidden_bytes).hexdigest() not in oversized.text
    assert client.get(base + f"/imports/{hidden['id']}/original").status_code == 404
    assert client.get(base + f"/logs?job_id={hidden['id']}").status_code == 422
    assert client.get(base).json["full_case_access"] is False
    assert client.post(base + f"/logs/{event['id']}/exhibit").status_code in {200, 201}
    assert client.post(base + "/reports", json={"version": client.get(base).json["version"]}).status_code == 403
    # An exact upload of inaccessible bytes must not return that hidden receipt.
    retried, _ = upload(client, autopsy_case, [observation()])
    assert retried["id"] != hidden["id"]


def test_concurrent_reexports_share_one_event_and_retain_both_jobs(autopsy_case, app, database, user_ids):
    def worker(pretty):
        with app.test_client() as concurrent_client:
            with concurrent_client.session_transaction() as session:
                session["user_id"], session["workspace_id"], session["user_role"] = user_ids["analyst"], 1, "analyst"
            return upload(concurrent_client, autopsy_case, [observation()], pretty=pretty)[0]

    with ThreadPoolExecutor(max_workers=2) as pool:
        receipts = list(pool.map(worker, [False, True]))
    assert sorted((row["accepted"], row["skipped"]) for row in receipts) == [(0, 1), (1, 0)]
    assert database.execute("SELECT COUNT(*) FROM security_events WHERE owner_case_id=?", (autopsy_case,)).fetchone()[0] == 1
    assert database.execute("SELECT COUNT(*) FROM autopsy_event_occurrences WHERE case_id=?", (autopsy_case,)).fetchone()[0] == 2


@pytest.mark.parametrize("same_bytes", [False, True])
def test_simultaneous_connector_and_file_keep_one_event_and_one_rule_proof(autopsy_case, app, client, database, user_ids, same_bytes):
    base = f"/api/cases/{autopsy_case}"
    source = client.post(
        base + "/siem-connectors", json={"name": "Registered evidence source", "type": "http", "endpoint": "https://siem.corp.example/events"}
    ).json
    row = observation(process_name="powershell.exe", command_line="powershell.exe -enc AAAA")
    payload = json.dumps([row])

    def worker(channel):
        with app.test_client() as concurrent_client:
            with concurrent_client.session_transaction() as session:
                session["user_id"], session["workspace_id"], session["user_role"] = user_ids["analyst"], 1, "analyst"
            if channel == "file":
                result = concurrent_client.post(base + "/imports", json={"filename": "events.json", "content": payload, "source_id": source["id"]})
            else:
                result = concurrent_client.post(
                    f"/api/sources/{source['id']}/ingest",
                    data=payload if same_bytes else json.dumps([row], indent=2),
                    content_type="application/json",
                    headers={"X-SOCify-Source-Key": source["ingest_key"]},
                )
            assert result.status_code in {200, 201}, result.json
            return result.json

    with ThreadPoolExecutor(max_workers=2) as pool:
        receipts = list(pool.map(worker, ["file", "connector"]))
    assert sum(row["accepted"] for row in receipts) == 1
    assert sum(row["skipped"] for row in receipts) == 1
    assert logs(client, autopsy_case)["total"] == 1
    alerts = database.execute("SELECT id,evidence FROM alerts WHERE owner_case_id=?", (autopsy_case,)).fetchall()
    assert len(alerts) == 1
    retained = tuple(alerts[0])
    queued = client.post(base + "/detection", json={"version": client.get(base).json["version"], "mode": "rules"})
    assert queued.status_code == 202, queued.json
    from socify.autopsy_worker import run_autopsy_worker_once

    with app.app_context():
        assert run_autopsy_worker_once() == queued.json["id"]
    assert [tuple(row) for row in database.execute("SELECT id,evidence FROM alerts WHERE owner_case_id=?", (autopsy_case,))] == [retained]


def test_activation_uses_all_occurrences_but_reader_needs_an_active_visible_one(autopsy_case, client, login_as):
    base = f"/api/cases/{autopsy_case}"
    login_as("soc_manager")
    first, _ = upload(client, autopsy_case, [observation()])
    retained_id = logs(client, autopsy_case)["items"][0]["id"]
    repeated, _ = upload(client, autopsy_case, [observation()], pretty=True)
    changed, _ = upload(client, autopsy_case, [observation()], source_timezone="Asia/Riyadh")
    assert changed["accepted"] == 1
    assert logs(client, autopsy_case)["total"] == 2  # The second original still supports retained_id.
    policy = {"restricted": True, "members": [], "reason": "Isolate current supporting origin"}
    assert client.put(base + f"/imports/{repeated['id']}/access", json=policy).status_code == 200
    login_as("analyst")
    assert logs(client, autopsy_case)["total"] == 1
    historical_detail = client.get(base + f"/logs/{retained_id}")
    assert historical_detail.status_code == 200  # Existing detail route deliberately permits authorized history.
    assert historical_detail.json["import_job_id"] == first["id"]
    assert historical_detail.json["autopsy_active"] == 0
    assert client.post(base + f"/logs/{retained_id}/exhibit").status_code == 404
    historical = logs(client, autopsy_case, f"?job_id={first['id']}")
    assert historical["total"] == 1 and historical["items"][0]["id"] == retained_id
    login_as("soc_manager")
    for job in (first, repeated):
        result = client.post(
            base + f"/imports/{job['id']}/activate", json={"version": client.get(base).json["version"], "reason": "Restore reviewed derivation"}
        )
        assert result.status_code == 200, result.json
    login_as("analyst")
    assert logs(client, autopsy_case)["total"] == 1
    assert logs(client, autopsy_case)["items"][0]["id"] == retained_id


def test_connector_identity_keeps_changed_id_facts_and_registered_source_partition(autopsy_case, client, database):
    base = f"/api/cases/{autopsy_case}"
    sources = []
    for name in ("Original gateway", "Independent gateway"):
        result = client.post(base + "/siem-connectors", json={"name": name, "type": "http", "endpoint": "https://siem.corp.example/api/events"})
        assert result.status_code == 201, result.json
        sources.append(result.json)

    def push(source, rows, pretty=False):
        payload = json.dumps({"events": rows}, sort_keys=pretty, indent=2 if pretty else None).encode()
        response = client.post(
            f"/api/sources/{source['id']}/ingest", data=payload, content_type="application/json", headers={"X-SOCify-Source-Key": source["ingest_key"]}
        )
        assert response.status_code == 201, response.json
        return response.json

    first = observation(process_name="powershell.exe", command_line="powershell.exe -enc AAAA")
    assert push(sources[0], [first])["accepted"] == 1
    retry = push(sources[0], [first], True)
    assert (retry["accepted"], retry["skipped"], retry["alerts_triggered"]) == (0, 1, 0)
    assert push(sources[0], [first], True)["skipped"] == 1
    assert push(sources[0], [{**first, "command_line": "powershell.exe -enc BBBB"}])["accepted"] == 1
    assert push(sources[1], [first])["accepted"] == 1
    assert logs(client, autopsy_case)["total"] == 3
    assert database.execute("SELECT COUNT(*) FROM autopsy_event_occurrences WHERE case_id=?", (autopsy_case,)).fetchone()[0] == 4
    # Identical file bytes sent under different authenticated sources remain active.
    for source in sources:
        job, _ = upload(client, autopsy_case, [observation("upload-1")], source_id=source["id"])
        assert job["accepted"] == 1
    assert logs(client, autopsy_case)["total"] == 5


def test_reports_and_capsule_restore_keep_immutable_history_and_all_original_links(autopsy_case, client, database, login_as):
    from socify.autopsy_capsules import inspect_capsule

    base = f"/api/cases/{autopsy_case}"
    upload(client, autopsy_case, [observation()])
    report = client.post(base + "/reports", json={"version": client.get(base).json["version"]})
    assert report.status_code == 202, report.json
    snapshot = database.execute("SELECT id,payload,sha256 FROM autopsy_reports WHERE id=?", (report.json["id"],)).fetchone()
    upload(client, autopsy_case, [observation()], pretty=True)
    assert tuple(database.execute("SELECT id,payload,sha256 FROM autopsy_reports WHERE id=?", (report.json["id"],)).fetchone()) == tuple(snapshot)
    fresh = client.post(base + "/reports", json={"version": client.get(base).json["version"]})
    assert fresh.status_code == 202
    fresh_snapshot = client.get(base + f"/reports/{fresh.json['id']}").json["payload"]
    assert fresh_snapshot["summary"]["counts"]["normalized_logs"] == 1
    assert [(item["accepted"], item["skipped"], item["total"]) for item in fresh_snapshot["imports"]] == [(1, 0, 1), (0, 1, 1)]
    login_as("soc_manager")
    capsule = client.get(base + "/capsule?profile=team")
    assert capsule.status_code == 200
    _, data, files = inspect_capsule(capsule.data)
    assert len(data["tables"]["autopsy_event_occurrences"]) == 2
    assert len([key for key in files if key.startswith("originals/")]) == 2
    import io

    restored = client.post("/api/cases/import-capsule", data={"file": (io.BytesIO(capsule.data), "case.zip")})
    assert restored.status_code == 201, restored.json
    restored_id = restored.json["case_id"]
    assert logs(client, restored_id)["total"] == 1
    jobs = client.get(f"/api/cases/{restored_id}/imports").json["items"]
    assert len(jobs) == 2
    assert all(logs(client, restored_id, f"?job_id={job['id']}")["total"] == 1 for job in jobs)


def test_migration_does_not_merge_historical_event_ids_and_is_repeatable(autopsy_case, client, database):
    from socify.event_identity import migrate

    upload(client, autopsy_case, [observation()])
    database.execute("DELETE FROM autopsy_event_identities")  # Model separate historical rows.
    upload(client, autopsy_case, [observation()], pretty=True)
    original_events = [tuple(row) for row in database.execute("SELECT id,event_id,provenance FROM security_events WHERE owner_case_id=?", (autopsy_case,))]
    assert len(original_events) == 2
    # Recreate a pre-migration database using its historical primary job links.
    database.execute("DELETE FROM schema_meta WHERE key='event_occurrences'")
    database.execute("DELETE FROM autopsy_event_identities")
    database.execute("DELETE FROM autopsy_event_occurrences")
    migrate(database)
    migrate(database)
    assert [
        tuple(row) for row in database.execute("SELECT id,event_id,provenance FROM security_events WHERE owner_case_id=?", (autopsy_case,))
    ] == original_events
    third, _ = upload(client, autopsy_case, [observation()], encoding="utf-8")
    assert (third["accepted"], third["skipped"]) == (0, 1)


def test_repeated_authentication_occurrences_cannot_inflate_correlation_threshold(autopsy_case, client, database):
    row = observation(event_type="failed_login", source_ip="192.0.2.57", username="reviewed-account", action="login", outcome="failed")
    first, _ = upload(client, autopsy_case, [row] * 5)
    assert (first["accepted"], first["skipped"]) == (1, 4)
    query = "SELECT a.id,a.evidence FROM alerts a JOIN rules r ON r.id=a.rule_id WHERE a.owner_case_id=? AND r.name='[SOCify] Brute Force Authentication Burst'"
    assert database.execute(query, (autopsy_case,)).fetchall() == []
    next_rows = [{**row, "external_id": f"authentication-{number}", "timestamp": f"2026-11-02T08:0{number}:00Z"} for number in range(1, 5)]
    second, _ = upload(client, autopsy_case, [*reversed(next_rows), row], pretty=True)
    assert (second["accepted"], second["skipped"]) == (4, 1)
    proofs = [tuple(result) for result in database.execute(query, (autopsy_case,))]
    assert len(proofs) == 1 and len(json.loads(proofs[0][1])["event_ids"]) == 5
    upload(client, autopsy_case, [row, *next_rows])
    assert [tuple(result) for result in database.execute(query, (autopsy_case,))] == proofs


def test_explicit_zero_identifier_is_retained_and_deduplicated_without_row_fallback(autopsy_case, client):
    upload(client, autopsy_case, [observation(0)])
    second, _ = upload(client, autopsy_case, [observation(0)], pretty=True)
    assert (second["accepted"], second["skipped"]) == (0, 1)
    assert logs(client, autopsy_case)["items"][0]["external_id"] == "0"


@pytest.mark.parametrize("restore_count", [1, 2])
def test_restored_declared_source_accepts_overlapping_export_without_losing_ids(autopsy_case, client, login_as, database, restore_count):
    import io

    first, second, third = observation(), observation("gateway-002"), observation("gateway-003")
    upload(client, autopsy_case, [first, second])
    login_as("soc_manager")
    case_id = autopsy_case
    for _ in range(restore_count):
        exported = client.get(f"/api/cases/{case_id}/capsule?profile=team")
        restored = client.post("/api/cases/import-capsule", data={"file": (io.BytesIO(exported.data), "case.zip")})
        assert restored.status_code == 201, restored.json
        case_id = restored.json["case_id"]
    before = logs(client, case_id)["items"]
    receipt, _ = upload(client, case_id, [second, first, third], pretty=True)
    assert (receipt["accepted"], receipt["skipped"]) == (1, 2)
    after = logs(client, case_id)["items"]
    assert len(after) == 3
    assert {row["id"] for row in before}.issubset({row["id"] for row in after})
    assert database.execute("SELECT COUNT(*) FROM autopsy_event_occurrences WHERE case_id=?", (case_id,)).fetchone()[0] == 5


def test_capsule_restore_does_not_reconnect_or_adopt_an_old_registered_source(autopsy_case, client, login_as, database):
    import io

    source = client.post(
        f"/api/cases/{autopsy_case}/siem-connectors", json={"name": "Private origin", "type": "http", "endpoint": "https://siem.corp.example/events"}
    ).json
    upload(client, autopsy_case, [observation()], source_id=source["id"])
    login_as("soc_manager")
    case_id = autopsy_case
    for _ in range(2):
        exported = client.get(f"/api/cases/{case_id}/capsule?profile=team")
        restored = client.post("/api/cases/import-capsule", data={"file": (io.BytesIO(exported.data), "case.zip")})
        assert restored.status_code == 201, restored.json
        case_id = restored.json["case_id"]
        jobs = database.execute("SELECT source_id,autopsy_options FROM ingestion_jobs WHERE case_id=?", (case_id,)).fetchall()
        assert all(row["source_id"] is None and json.loads(row["autopsy_options"])["capsule_source_kind"] == "disconnected" for row in jobs)
        assert (
            database.execute(
                "SELECT COUNT(*) FROM autopsy_event_identities i JOIN security_events e ON e.id=i.event_id WHERE e.owner_case_id=?", (case_id,)
            ).fetchone()[0]
            == 0
        )
        assert client.get(f"/api/cases/{case_id}/siem-connectors").json["items"] == []


@pytest.mark.parametrize("state", ["allowed", "disabled", "restricted"])
def test_registered_source_worker_rechecks_authority_without_request_session(autopsy_case, app, client, login_as, database, state):
    from socify.db import get_db
    from socify.import_worker import run_import_worker_once

    base = f"/api/cases/{autopsy_case}"
    source = client.post(
        base + "/siem-connectors", json={"name": "Queued registered source", "type": "http", "endpoint": "https://siem.corp.example/events"}
    ).json
    app.config["IMPORT_INLINE_EXECUTION"] = False
    content = json.dumps([observation()])
    queued = client.post(base + "/imports", json={"filename": "queued.json", "content": content, "source_id": source["id"]})
    assert queued.status_code == 202, queued.json
    if state == "disabled":
        database.execute("UPDATE event_sources SET is_active=0 WHERE id=?", (source["id"],))
    elif state == "restricted":
        app.config["IMPORT_INLINE_EXECUTION"] = True
        login_as("soc_manager")
        hidden, _ = upload(client, autopsy_case, [observation("restricted-evidence")])
        assert (
            client.put(base + f"/imports/{hidden['id']}/access", json={"restricted": True, "members": [], "reason": "Revoke full source context"}).status_code
            == 200
        )
        login_as("analyst")
    with app.app_context():
        assert run_import_worker_once(get_db(), "source-authority-review") is not None
    result = client.get(base + f"/imports/{queued.json['id']}").json
    assert result["status"] == ("completed" if state == "allowed" else "failed"), result
    assert result["accepted"] == (1 if state == "allowed" else 0)
    assert client.get(base + f"/imports/{queued.json['id']}/original").data == content.encode()
