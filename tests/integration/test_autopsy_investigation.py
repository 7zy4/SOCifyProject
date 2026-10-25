import json

import pytest

from socify.timeutils import iso_now


def import_logs(client, case_id):
    result = client.post(
        f"/api/cases/{case_id}/imports",
        json={
            "filename": "timeline.jsonl",
            "content": "\n".join(
                [
                    json.dumps({"title": "Observed first event", "event_time": "2026-10-24T10:00:00Z", "source_ip": "192.0.2.5", "hostname": "defender-01"}),
                    json.dumps({"title": "Unknown source time", "source_ip": "192.0.2.9"}),
                ]
            ),
        },
    )
    assert result.status_code == 201
    return client.get(f"/api/cases/{case_id}/logs").json["items"]


def test_timeline_preserves_uncertainty_and_shared_or_private_annotations(autopsy_case, client, login_as, user_ids):
    events = import_logs(client, autopsy_case)
    base = f"/api/cases/{autopsy_case}"
    timeline = client.get(base + "/timeline?limit=1").json
    assert timeline["total"] == 2 and len(timeline["items"]) == 1
    assert timeline["items"][0]["observed_time_known"] is True
    second = client.get(base + "/timeline?limit=1&page=2").json["items"][0]
    assert second["event_time"] is None and second["observed_time_known"] is False
    assert second["ingested_at"]
    assert len(client.get(base + "/timeline?q=Observed").json["items"]) == 1
    for visibility in ("team", "private"):
        assert (
            client.post(
                base + "/records/bookmark",
                json={"event_id": events[0]["id"], "title": visibility + " important event", "color": "gold", "tags": ["pivot"], "visibility": visibility},
            ).status_code
            == 201
        )
        assert (
            client.post(
                base + "/records/timeline_view",
                json={
                    "title": visibility + " saved range",
                    "query": "Observed",
                    "visibility": visibility,
                    "start": "2026-10-24T09:00:00Z",
                    "end": "2026-10-24T11:00:00Z",
                },
            ).status_code
            == 201
        )
    assert len(client.get(base + "/timeline").json["bookmarks"]) == 2
    login_as("soc_manager")
    assert client.post(base + "/members", json={"user_id": user_ids["auditor"], "responsibility": "reviewer"}).status_code == 200
    login_as("auditor")
    listed = client.get(base + "/timeline").json
    assert [item["payload"]["visibility"] for item in listed["bookmarks"]] == ["team"]
    assert [item["payload"]["visibility"] for item in listed["views"]] == ["team"]
    assert client.get("/api/this-route-does-not-exist").status_code == 404


def test_graph_never_expands_into_another_private_case_or_unattached_alert(autopsy_case, client, database, login_as, user_ids):
    event = import_logs(client, autopsy_case)[0]
    login_as("soc_manager")
    other = client.post(
        "/api/cases",
        json={"title": "Private parallel investigation", "reason": "forensic_review", "objective": "Different private scope", "event_ids": [event["id"]]},
    ).json["id"]
    rule = database.execute("SELECT id FROM rules LIMIT 1").fetchone()[0]
    alert = database.execute(
        "INSERT INTO alerts(alert_id, workspace_id, rule_id, rule_version, reason, evidence, severity, confidence, detected_at, dedup_key, trace, owner_case_id) VALUES ('private-graph-alert', 1, ?, 1, 'Private alert relation', '[]', 'high', .9, ?, 'private-graph-alert', '{}', ?) RETURNING id",
        (rule, iso_now(), other),
    ).fetchone()[0]
    database.execute("INSERT INTO alert_events(alert_id, event_id) VALUES (?, ?)", (alert, event["id"]))
    database.execute(
        "INSERT INTO case_alerts(case_id, alert_id, attached_by, attached_at) VALUES (?, ?, ?, ?)", (other, alert, user_ids["soc_manager"], iso_now())
    )
    login_as("analyst")
    graph = client.get(f"/api/cases/{autopsy_case}/graph").json
    assert graph["case_id"] == autopsy_case
    assert any(item["type"] == "IP" and item["label"] == "192.0.2.5" for item in graph["nodes"])
    assert not any(item["id"] in {f"incident:{other}", f"alert:{alert}"} for item in graph["nodes"])
    assert client.get(f"/api/cases/{other}/graph").status_code == 404
    assert client.get(f"/api/cases/{autopsy_case}/graph?case_id={other}").status_code == 422
    assert graph["edges"]


def test_case_mitre_uses_offline_catalog_requires_own_log_and_appears_in_report(autopsy_case, client):
    event = import_logs(client, autopsy_case)[0]
    base = f"/api/cases/{autopsy_case}"
    catalog = client.get(base + "/attack?q=T1059").json
    assert catalog["offline_snapshot"] is True
    technique = next(item for item in catalog["items"] if item["technique_id"] == "T1059")
    body = {"technique_id": "T1059", "assessment": "verified", "reason": "Linked event supports the observed technique"}
    assert client.post(base + "/attack", json=body).status_code == 422
    assert client.post(base + "/attack", json={**body, "event_id": 999999}).status_code == 422
    assert client.post(base + "/attack", json={**body, "event_id": event["id"]}).status_code == 201
    annotation = client.get(base + "/attack").json["annotations"][0]
    assert annotation["attack_version"] == technique["attack_version"]
    assert client.post(base + f"/logs/{event['id']}/exhibit").status_code == 201
    report = client.post(base + "/reports", json={"version": client.get(base).json["version"]})
    snapshot = client.get(base + f"/reports/{report.json['id']}").json["payload"]
    assert snapshot["techniques"][0]["technique_id"] == "T1059"
    assert snapshot["evidenced_timeline"][0]["id"] == event["id"]


@pytest.mark.parametrize(
    "suffix",
    [
        "timeline?limit=101",
        "timeline?page=0",
        "timeline?training_run_id=1",
        "timeline?severity=invalid",
        "graph?limit=101",
        "graph?limit=bad",
        "attack?q=" + "a" * 101,
    ],
)
def test_investigation_rejects_invalid_filters(autopsy_case, client, suffix):
    assert client.get(f"/api/cases/{autopsy_case}/{suffix}").status_code == 422
