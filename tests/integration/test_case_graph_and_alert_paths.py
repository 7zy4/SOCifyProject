"""Case graph, alert and import-attachment paths that the product serves, exercised on a real case."""

import json


def _failed_logins(client, case_id, count=5):
    rows = [
        {
            "event_type": "failed_login",
            "category": "authentication",
            "severity": "high" if index == 0 else "medium",
            "title": f"Failed login {index}",
            "event_time": f"2026-10-19T10:0{index}:00Z",
            "source_ip": "198.51.100.20",
            "username": "amina",
            "action": "login",
            "outcome": "failed",
            "mitre_ids": ["T1110"],
        }
        for index in range(count)
    ]
    imported = client.post(
        f"/api/cases/{case_id}/imports", json={"filename": "logins.jsonl", "format": "jsonl", "content": "\n".join(json.dumps(row) for row in rows)}
    )
    assert imported.status_code == 201 and imported.json["accepted"] == count, imported.json
    return imported.json["id"]


def test_graph_links_events_to_their_technique_alert_and_case(autopsy_case, client, database):
    _failed_logins(client, autopsy_case)
    alert = database.execute("SELECT id FROM alerts WHERE owner_case_id = ?", (autopsy_case,)).fetchone()
    assert alert is not None, "five failed logins from one address raise the threshold alert"
    graph = client.get(f"/api/cases/{autopsy_case}/graph")
    assert graph.status_code == 200
    kinds = {node["type"] for node in graph.json["nodes"]}
    assert {"Event", "Incident"} <= kinds
    assert any(node["id"] == "technique:T1110" for node in graph.json["nodes"])
    assert any(edge["source"].startswith("event:") and edge["target"] == "technique:T1110" for edge in graph.json["edges"])
    assert database.execute("SELECT 1 FROM case_alerts WHERE case_id = ? AND alert_id = ?", (autopsy_case, alert["id"])).fetchone()
    assert any(node["id"] == f"alert:{alert['id']}" for node in graph.json["nodes"])
    assert any(edge["target"] == f"alert:{alert['id']}" and edge["type"] == "triggered_rule" for edge in graph.json["edges"])


def test_graph_filters_narrow_events_and_reject_unknown_values(autopsy_case, client):
    _failed_logins(client, autopsy_case)
    base = f"/api/cases/{autopsy_case}/graph"
    assert client.get(base).json["event_count"] == 5
    assert client.get(base + "?severity=high").json["event_count"] == 1
    assert client.get(base + "?start=2026-10-19T10:02:00Z").json["event_count"] == 3
    assert client.get(base + "?start=2026-10-19T10:01:00Z&end=2026-10-19T10:02:00Z").json["event_count"] == 2
    assert client.get(base + "?severity=urgent").status_code == 422
    assert client.get(base + "?unknown=1").status_code == 422


def test_case_opened_from_an_alert_carries_the_alert_and_its_technique(autopsy_case, client, database):
    _failed_logins(client, autopsy_case)
    alert = database.execute("SELECT id, reason, severity FROM alerts WHERE owner_case_id = ? ORDER BY id LIMIT 1", (autopsy_case,)).fetchone()
    created = client.post(f"/api/alerts/{alert['id']}/case", json={})
    assert created.status_code == 201, created.json
    assert created.json["id"] != autopsy_case
    assert created.json["title"] == f"Investigation: {alert['reason'][:180]}"
    assert created.json["severity"] == alert["severity"]
    assert database.execute("SELECT 1 FROM case_alerts WHERE case_id = ? AND alert_id = ?", (created.json["id"], alert["id"])).fetchone()
    assert client.post("/api/alerts/999999/case", json={}).status_code == 404


def test_attaching_a_case_import_lists_its_events_once(autopsy_case, client, database):
    job = _failed_logins(client, autopsy_case)
    url = f"/api/incidents/{autopsy_case}/imports"
    attached = client.post(url, json={"job_id": job})
    assert attached.status_code == 200, attached.json
    # The import already belongs to the case, so every event is attached and nothing is added twice.
    assert attached.json == {"added": 0, "has_more": False, "next_after_id": attached.json["next_after_id"]}
    assert database.execute("SELECT COUNT(*) FROM case_events WHERE case_id = ?", (autopsy_case,)).fetchone()[0] == 5
    assert client.post(url, json={"job_id": 999999}).status_code == 404
    assert client.post("/api/incidents/999999/imports", json={"job_id": job}).status_code == 404
    assert client.get(f"/api/incidents/{autopsy_case}/report?revision=invalid").status_code == 422
