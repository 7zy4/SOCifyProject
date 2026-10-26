import json

import pytest


@pytest.fixture
def shared_source(autopsy_case, client, database, login_as, user_ids):
    source = f"/api/cases/{autopsy_case}"
    login_as("soc_manager")
    imported = client.post(source + "/imports", json={"filename": "shared.json", "content": json.dumps([{"title": "Restricted cross-case evidence"}])})
    assert imported.status_code == 201, imported.json
    event = client.get(source + "/logs").json["items"][0]["id"]
    rule = database.execute("SELECT id FROM rules LIMIT 1").fetchone()[0]
    alert = database.execute(
        "INSERT INTO alerts(alert_id,workspace_id,rule_id,rule_version,reason,evidence,severity,confidence,detected_at,dedup_key,trace,owner_case_id) VALUES ('cross-case-private',1,?,1,'Private source alert','[]','high',.9,'2026-10-26T10:00:00Z','cross-case-private','{}',?) RETURNING id",
        (rule, autopsy_case),
    ).fetchone()[0]
    database.execute("INSERT INTO alert_events(alert_id,event_id) VALUES (?,?)", (alert, event))
    login_as("analyst")
    target = client.post("/api/cases", json={"title": "Recipient investigation", "reason": "alert_review", "objective": "Review shared synthetic evidence"})
    assert target.status_code == 201, target.json
    return source, target.json["id"], imported.json["id"], event, alert


def restrict_source(client, login_as, source, job, members=()):
    login_as("soc_manager")
    result = client.put(source + f"/imports/{job}/access", json={"restricted": True, "members": list(members), "reason": "Cross-case disclosure boundary"})
    assert result.status_code == 200, result.json
    login_as("analyst")


@pytest.mark.parametrize("kind", ["events", "alerts"])
def test_private_source_cannot_be_attached_through_legacy_case_routes(shared_source, client, database, login_as, kind):
    source, target, job, event, alert = shared_source
    restrict_source(client, login_as, source, job)
    response = client.post(f"/api/incidents/{target}/{kind}", json={"event_id" if kind == "events" else "alert_id": event if kind == "events" else alert})
    assert response.status_code == 404, response.json
    for table in ("case_events", "case_alerts", "case_evidence"):
        assert database.execute(f"SELECT COUNT(*) FROM {table} WHERE case_id=?", (target,)).fetchone()[0] == 0


@pytest.mark.parametrize("kind", ["events", "alerts"])
def test_source_revocation_blocks_existing_cross_case_context_and_warm_counts(shared_source, client, login_as, user_ids, kind):
    source, target, job, event, alert = shared_source
    response = client.post(f"/api/incidents/{target}/{kind}", json={"event_id" if kind == "events" else "alert_id": event if kind == "events" else alert})
    assert response.status_code == 201, response.json
    base = f"/api/cases/{target}"
    summary = client.get(base).json
    assert summary["counts"]["events"] == 1
    assert client.get(base + "/chronology").status_code == 200
    restrict_source(client, login_as, source, job)
    summary_after = client.get(base).json
    assert summary_after["version"] == summary["version"]
    assert summary_after["counts"]["events"] == 0
    assert client.get(base + "/logs").json["total"] == 0
    for suffix in ("/chronology", "/evidence"):
        response = client.get(base + suffix) if suffix != "/evidence" else client.get(f"/api/incidents/{target}/evidence/1")
        assert response.status_code == 403, (suffix, response.json)
    assert client.post(base + "/reports", json={}).status_code == 403
    restrict_source(client, login_as, source, job, [user_ids["analyst"]])
    assert client.get(base).json["counts"]["events"] == 1
    assert client.get(base + "/chronology").status_code == 200


@pytest.mark.parametrize("retained", ["event_evidence", "alert_link", "alert_evidence"])
def test_revocation_covers_historical_evidence_and_alert_links_without_case_events(shared_source, client, database, login_as, user_ids, retained):
    source, target, job, event, alert = shared_source
    if retained == "alert_link":
        database.execute(
            "INSERT INTO case_alerts(case_id,alert_id,attached_by,attached_at) VALUES (?,?,?,'2026-10-26T10:00:00Z')", (target, alert, user_ids["analyst"])
        )
    else:
        kind = "event" if retained == "event_evidence" else "alert"
        database.execute(
            "INSERT INTO case_evidence(case_id,evidence_type,reference_id,title,sha256,provenance,added_by,added_at) VALUES (?,?,?,'Historical reference',?,'{}',?,'2026-10-26T10:00:00Z')",
            (target, kind, str(event if kind == "event" else alert), "0" * 64, user_ids["analyst"]),
        )
    assert client.get(f"/api/cases/{target}/chronology").status_code == 200
    restrict_source(client, login_as, source, job)
    assert client.get(f"/api/cases/{target}/chronology").status_code == 403
    assert client.post(f"/api/cases/{target}/reports", json={}).status_code == 403
