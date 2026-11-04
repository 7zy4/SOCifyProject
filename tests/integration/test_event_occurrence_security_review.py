"""Independent access-boundary checks for shared imported observations."""

import csv
import hashlib
import io
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tests.conftest import DEMO_LOGIN_VALUE

ARTIFACTS = Path("artifacts/security-review/event-occurrence-independent")


def record(name, value):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, ensure_ascii=False, indent=2)
    (ARTIFACTS / f"{name}.json").write_text(encoded, encoding="utf-8")
    (ARTIFACTS / f"{name}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}.json").write_text(encoded, encoding="utf-8")


def observation(**changes):
    return {
        "source": "independent-gateway",
        "external_id": "original-001",
        "timestamp": "2026-11-02T09:00:00Z",
        "hostname": "REVIEW-HOST",
        "title": "Retained evidence for independent access review",
        **changes,
    }


def upload(client, case_id, row, *, pretty=False, **options):
    payload = json.dumps([row], sort_keys=pretty, indent=2 if pretty else None)
    response = client.post(f"/api/cases/{case_id}/imports", json={"filename": "review.json", "content": payload, **options})
    assert response.status_code in {200, 201}, response.json
    return response.json, hashlib.sha256(payload.encode()).hexdigest()


def test_shared_event_never_opens_hidden_exhibit_and_revocation_reselects_origin(autopsy_case, client, login_as, user_ids):
    base = f"/api/cases/{autopsy_case}"
    login_as("soc_manager")
    original, hidden_hash = upload(client, autopsy_case, observation())
    event_id = client.get(base + "/logs").json["items"][0]["id"]
    exhibit = client.post(base + f"/logs/{event_id}/exhibit").json["id"]
    visible, visible_hash = upload(client, autopsy_case, observation(), pretty=True)
    report_id = client.post(base + "/reports", json={"version": client.get(base).json["version"]}).json["id"]

    def access(job, members):
        response = client.put(base + f"/imports/{job['id']}/access", json={"restricted": True, "members": members, "reason": "Independent access boundary"})
        assert response.status_code == 200, response.json

    access(original, [])
    access(visible, [user_ids["analyst"]])
    login_as("analyst")
    checked = {}
    for path in (
        f"/api/incidents/{autopsy_case}/evidence/{exhibit}",
        f"/api/incidents/{autopsy_case}/evidence/{exhibit}/content",
        base + f"/reports/{report_id}",
        base + "/alerts",
        base + "/chronology",
    ):
        result = client.get(path)
        checked[path] = result.status_code
        assert result.status_code == 403, (path, result.json)
        assert hidden_hash not in result.text
    summary = client.get(base).json
    assert summary["evidence"] == [] and summary["counts"]["events"] == 1
    detail = client.get(base + f"/logs/{event_id}")
    assert detail.status_code == 200 and hidden_hash not in detail.text and visible_hash in detail.text
    assert client.post(base + f"/logs/{event_id}/exhibit").json["id"] == exhibit

    login_as("soc_manager")
    access(visible, [])
    login_as("analyst")
    assert client.get(base + "/logs").json["total"] == 0
    assert client.get(base + f"/logs/{event_id}").status_code == 404
    assert client.get(base + "/timeline").json["total"] == 0
    login_as("soc_manager")
    access(original, [user_ids["analyst"]])
    login_as("analyst")
    detail = client.get(base + f"/logs/{event_id}")
    assert detail.status_code == 200 and hidden_hash in detail.text and visible_hash not in detail.text
    assert client.get(base + "/logs").json["total"] == 1
    record(
        "restricted-exhibit-boundaries",
        {"status": "passed", "endpoints": checked, "revocation": "immediate", "regrant": "selected only the newly authorized origin"},
    )


def test_guessed_connector_of_inaccessible_case_cannot_label_an_import(autopsy_case, client, login_as, database):
    login_as("soc_manager")
    confidential = client.post("/api/cases", json={"title": "Confidential separate incident"}).json["id"]
    source = client.post(
        f"/api/cases/{confidential}/siem-connectors",
        json={"name": "PRIVATE-CONNECTOR-NAME", "type": "http", "endpoint": "https://private-source.example/events"},
    ).json
    login_as("analyst")
    assert client.get(f"/api/cases/{confidential}").status_code == 404
    payload = {"filename": "my-events.json", "content": json.dumps([observation()]), "source_id": source["id"]}
    preview = client.post(f"/api/cases/{autopsy_case}/imports/preview", json=payload)
    imported = client.post(f"/api/cases/{autopsy_case}/imports", json=payload)
    linked = database.execute("SELECT id,source_id,source_name FROM ingestion_jobs WHERE case_id=?", (autopsy_case,)).fetchall()
    evidence = {
        "preview_status": preview.status_code,
        "preview": preview.json,
        "import_status": imported.status_code,
        "import": imported.json,
        "linked_jobs": [dict(row) for row in linked],
    }
    record("foreign-source-label", evidence)
    assert preview.status_code in {403, 404}, evidence
    assert imported.status_code in {403, 404}, evidence
    assert not linked


def test_global_source_list_respects_private_case_boundary(autopsy_case, client, login_as):
    own = client.post(
        f"/api/cases/{autopsy_case}/siem-connectors", json={"name": "MY-AUTHORIZED-SOURCE", "type": "http", "endpoint": "https://my-source.example/events"}
    ).json
    login_as("soc_manager")
    confidential = client.post("/api/cases", json={"title": "Private source investigation"}).json["id"]
    hidden = client.post(
        f"/api/cases/{confidential}/siem-connectors",
        json={"name": "RESTRICTED-SOURCE-NAME", "type": "http", "endpoint": "https://restricted-endpoint.example/events"},
    ).json
    login_as("analyst")
    assert client.get(f"/api/cases/{confidential}").status_code == 404
    listed = client.get("/api/sources")
    record("global-source-list", {"status": listed.status_code, "payload": listed.json, "hidden_id": hidden["id"], "allowed_id": own["id"]})
    assert listed.status_code == 200
    assert own["id"] in {row["id"] for row in listed.json}
    assert hidden["id"] not in {row["id"] for row in listed.json}
    assert "restricted-endpoint.example" not in listed.text


def test_partial_case_reader_cannot_borrow_hidden_connector_metadata(autopsy_case, client, login_as):
    base = f"/api/cases/{autopsy_case}"
    login_as("soc_manager")
    hidden, _ = upload(client, autopsy_case, observation())
    source = client.post(
        base + "/siem-connectors", json={"name": "HIDDEN-IN-PARTIAL-CASE", "type": "http", "endpoint": "https://partial-private.example/events"}
    ).json
    assert (
        client.put(
            base + f"/imports/{hidden['id']}/access", json={"restricted": True, "members": [], "reason": "Restricted investigation material"}
        ).status_code
        == 200
    )
    login_as("analyst")
    assert client.get(base).json["full_case_access"] is False
    assert client.get(base + "/siem-connectors").status_code == 403
    body = {"filename": "mine.json", "content": json.dumps([observation(external_id="my-new-observation")]), "source_id": source["id"]}
    preview = client.post(base + "/imports/preview", json=body)
    imported = client.post(base + "/imports", json=body)
    record(
        "partial-case-source", {"preview_status": preview.status_code, "preview": preview.json, "import_status": imported.status_code, "import": imported.json}
    )
    assert preview.status_code in {403, 404}
    assert imported.status_code in {403, 404}
    assert "HIDDEN-IN-PARTIAL-CASE" not in preview.text + imported.text


def test_shared_event_does_not_reveal_global_monitoring_for_restricted_case(autopsy_case, client, login_as, user_ids):
    base = f"/api/cases/{autopsy_case}"
    login_as("soc_manager")
    row = observation(process_name="powershell.exe", command_line="powershell.exe -enc AAAA")
    hidden, _ = upload(client, autopsy_case, row)
    visible, _ = upload(client, autopsy_case, row, pretty=True)
    assert client.get("/api/soc/monitoring", query_string={"case_id": autopsy_case}).json["total"] > 0
    for job, members in ((hidden, []), (visible, [user_ids["analyst"]])):
        assert (
            client.put(base + f"/imports/{job['id']}/access", json={"restricted": True, "members": members, "reason": "Review scoped alert access"}).status_code
            == 200
        )
    login_as("analyst")
    assert client.get(base + "/logs").json["total"] == 1
    for channel in ("main", "investigation", "closed"):
        result = client.get("/api/soc/monitoring", query_string={"case_id": autopsy_case, "channel": channel}).json
        assert result["total"] == 0 and result["items"] == [] and not any(result["counts"].values())


@pytest.mark.parametrize("replacement", [True, 1.0, "1", [1, 2]])
def test_source_json_type_changes_do_not_merge_observations(autopsy_case, client, replacement):
    initial = observation(extra={"value": 1, "ordered": [1, 2]})
    upload(client, autopsy_case, initial)
    duplicate, _ = upload(client, autopsy_case, initial, pretty=True)
    assert (duplicate["accepted"], duplicate["skipped"]) == (0, 1)
    different = observation(extra={"value": replacement, "ordered": [1, 2]})
    result, _ = upload(client, autopsy_case, different, pretty=True)
    assert (result["accepted"], result["skipped"]) == (1, 0)
    assert client.get(f"/api/cases/{autopsy_case}/logs").json["total"] == 2


def test_array_order_remains_source_evidence(autopsy_case, client):
    upload(client, autopsy_case, observation(extra={"ordered": [1, 2]}))
    result, _ = upload(client, autopsy_case, observation(extra={"ordered": [2, 1]}), pretty=True)
    assert (result["accepted"], result["skipped"]) == (1, 0)
    assert client.get(f"/api/cases/{autopsy_case}/logs").json["total"] == 2


def test_same_source_facts_are_independent_between_workspaces(autopsy_case, client, app, database, user_ids):
    first, _ = upload(client, autopsy_case, observation())
    first_event = client.get(f"/api/cases/{autopsy_case}/logs").json["items"][0]["id"]
    source = client.post(
        f"/api/cases/{autopsy_case}/siem-connectors",
        json={"name": "Original workspace source", "type": "http", "endpoint": "https://tenant-one.example/events"},
    ).json
    other_workspace = database.execute(
        "INSERT INTO training_workspaces(public_id,name,created_at) VALUES ('occurrence-security-tenant','Independent workspace','2026-11-02T00:00:00Z')"
    ).lastrowid
    other_user = database.execute(
        "INSERT INTO users(email,password_hash,name,role,workspace_id,created_at) SELECT 'independent-review@example.test',password_hash,'Independent reviewer','analyst',?,'2026-11-02T00:00:00Z' FROM users WHERE id=?",
        (other_workspace, user_ids["analyst"]),
    ).lastrowid
    with app.test_client() as other:
        with other.session_transaction() as session:
            session["user_id"], session["workspace_id"], session["user_role"] = other_user, other_workspace, "analyst"
        created = other.post("/api/cases", json={"title": "Separate workspace investigation"})
        assert created.status_code == 201, created.json
        case_id = created.json["id"]
        second, _ = upload(other, case_id, observation())
        assert first["accepted"] == second["accepted"] == 1
        other_event = other.get(f"/api/cases/{case_id}/logs").json["items"][0]["id"]
        assert other_event != first_event
        repeated, _ = upload(other, case_id, observation(), pretty=True)
        assert (repeated["accepted"], repeated["skipped"]) == (0, 1)
        assert other.get(f"/api/cases/{autopsy_case}/logs/{first_event}").status_code == 404
        assert other.get(f"/api/cases/{case_id}/logs/{first_event}").status_code == 404
        attempt = other.post(
            f"/api/cases/{case_id}/imports/preview",
            json={"filename": "tenant.json", "content": json.dumps([observation()]), "source_id": source["id"]},
        )
        assert attempt.status_code == 404
        assert "tenant-one.example" not in attempt.text
    assert client.get(f"/api/cases/{autopsy_case}/logs").json["total"] == 1


@pytest.mark.parametrize(
    "format_name,selected_job,already_sent",
    [("json", False, 0), ("json", True, 1), ("jsonl", False, 1), ("csv", True, 0), ("csv", False, 1)],
)
def test_export_revocation_never_falls_back_to_a_restricted_original(autopsy_case, client, app, login_as, user_ids, format_name, selected_job, already_sent):
    base = f"/api/cases/{autopsy_case}"
    records = [observation(external_id=f"retained-{number}", timestamp=f"2026-11-02T09:0{number}:00Z") for number in range(3)]
    hidden_bytes = json.dumps(records)
    visible_bytes = json.dumps(records, indent=2, sort_keys=True)
    hidden_hash, visible_hash = hashlib.sha256(hidden_bytes.encode()).hexdigest(), hashlib.sha256(visible_bytes.encode()).hexdigest()
    login_as("admin")
    original = client.post(base + "/imports", json={"filename": "hidden.json", "content": hidden_bytes}).json
    login_as("soc_manager")
    visible = client.post(base + "/imports", json={"filename": "visible.json", "content": visible_bytes}).json
    for job, members in ((original, []), (visible, [user_ids["analyst"]])):
        assert (
            client.put(
                base + f"/imports/{job['id']}/access", json={"restricted": True, "members": members, "reason": "Review stream authorization"}
            ).status_code
            == 200
        )
    login_as("analyst")
    url = base + f"/logs/export?format={format_name}&redacted=0" + (f"&job_id={visible['id']}" if selected_job else "")
    response = client.get(url, buffered=False)
    assert response.status_code == 200

    def revoke():
        with app.test_client() as manager:
            with manager.session_transaction() as session:
                session["user_id"], session["workspace_id"], session["user_role"] = user_ids["soc_manager"], 1, "soc_manager"
            revoked = manager.put(
                base + f"/imports/{visible['id']}/access", json={"restricted": True, "members": [], "reason": "Revoke before first streamed row"}
            )
            return revoked.status_code, revoked.json

    try:
        iterator = iter(response.response)
        sent = [next(iterator)]  # JSON bracket, CSV header, or the first JSONL row.
        if already_sent and format_name != "jsonl":
            sent.append(next(iterator))
        with ThreadPoolExecutor(max_workers=1) as pool:
            status, payload = pool.submit(revoke).result()
        assert status == 200, payload
        body = b"".join([*sent, *iterator]).decode("utf-8")
    finally:
        response.close()
    rows = (
        json.loads(body)
        if format_name == "json"
        else [json.loads(line) for line in body.splitlines()]
        if format_name == "jsonl"
        else list(csv.DictReader(io.StringIO(body.lstrip("\ufeff"))))
    )
    record(
        f"export-revocation-{format_name}-{selected_job}-{already_sent}",
        {"status": 200, "rows": rows, "never_authorized_hash": hidden_hash, "initially_authorized_hash": visible_hash},
    )
    assert hidden_hash not in body
    assert "idempotency_key" not in body
    assert len(rows) == already_sent
    if format_name != "csv":
        assert all(row["import_job_id"] == visible["id"] and row["created_by"] == user_ids["soc_manager"] for row in rows)
        assert all(row["provenance"]["file_sha256"] == visible_hash for row in rows)


@pytest.mark.parametrize("revocation", ["case_membership", "account_deactivation", "session_revocation", "export_permission", "download_permission"])
def test_export_rechecks_case_membership_and_account_state(autopsy_case, client, app, login_as, user_ids, revocation):
    base = f"/api/cases/{autopsy_case}"
    upload(client, autopsy_case, observation())
    login_as("soc_manager")
    handed_off = client.post(
        base + "/handoff",
        json={
            "from_user": user_ids["analyst"],
            "to_user": user_ids["soc_manager"],
            "version": client.get(base).json["version"],
            "reason": "Independent export authorization review",
        },
    )
    assert handed_off.status_code == 200, handed_off.json
    login_as("analyst")
    other_session = None
    session_id = None
    if revocation == "session_revocation":
        credentials = {"email": "analyst@socify.local", "password": DEMO_LOGIN_VALUE}
        assert client.post("/api/auth/login", json=credentials).status_code == 200
        session_id = next(item["id"] for item in client.get("/api/auth/sessions").json["items"] if item["is_current"])
        other_session = app.test_client()
        assert other_session.post("/api/auth/login", json=credentials).status_code == 200
    response = client.get(base + "/logs/export?format=json&redacted=0", buffered=False)
    assert response.status_code == 200

    def revoke():
        if revocation == "session_revocation":
            result = other_session.delete(f"/api/auth/sessions/{session_id}")
            return result.status_code, {"revoked_session_id": session_id}
        with app.test_client() as manager:
            with manager.session_transaction() as session:
                session["user_id"], session["workspace_id"], session["user_role"] = user_ids["soc_manager"], 1, "soc_manager"
            if revocation == "case_membership":
                result = manager.delete(
                    base + f"/members/{user_ids['analyst']}",
                    json={"version": manager.get(base).json["version"], "reason": "End investigation access before streaming"},
                )
            elif revocation == "account_deactivation":
                result = manager.post(
                    f"/api/team/members/{user_ids['analyst']}/deactivate",
                    json={"reason": "Disable account before streaming", "handoff_to": user_ids["soc_manager"]},
                )
            else:
                kept_permission = "cases.export" if revocation == "download_permission" else "evidence.download"
                result = manager.put("/api/team/roles/analyst", json={"permissions": ["cases.read", kept_permission]})
            return result.status_code, result.json

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            status, result = pool.submit(revoke).result()
        assert status == (204 if revocation == "session_revocation" else 200), result
        body = response.get_data(as_text=True)
    finally:
        response.close()
    rows = json.loads(body)
    record(f"export-{revocation}", {"revocation_status": status, "result": result, "exported_rows": rows})
    assert rows == []
