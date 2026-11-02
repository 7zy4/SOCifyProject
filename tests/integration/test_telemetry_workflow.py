import json

import pytest

from socify.autopsy_report_render import render_html
from socify.autopsy_reports import build_snapshot
from socify.cases import _case_row
from socify.network_insights import network_snapshot, telemetry_report
from tests.unit.test_telemetry import zeek


def upload(client, case_id, rows, name="telemetry.json"):
    result = client.post(f"/api/cases/{case_id}/imports", json={"filename": name, "content": json.dumps(rows)})
    assert result.status_code == 201, result.json
    return result.json


def eve():
    return {
        "timestamp": "2026-01-01T00:00:00Z",
        "flow_id": 9,
        "src_ip": "10.0.0.2",
        "dest_ip": "203.0.113.9",
        "dest_port": 443,
        "event_type": "alert",
        "proto": "TCP",
        "alert": {"signature_id": 1234, "signature": "Retained IDS signature", "severity": 1},
    }


def osquery():
    return {
        "hostIdentifier": "station-9",
        "name": "processes",
        "unixTime": 1790000000,
        "diffResults": {"added": [{"pid": "12", "name": "agent", "cmdline": "agent --run"}], "removed": [{"pid": "11", "name": "agent"}]},
    }


def test_native_logs_flow_through_rules_network_and_endpoint_views(autopsy_case, client, database):
    base = f"/api/cases/{autopsy_case}"
    upload(client, autopsy_case, [*[zeek(i) for i in range(10)], eve(), osquery()])
    network = client.get(base + "/network-insights").json
    assert network["connection_count"] == 10 and network["periodic_count"] == 1
    assert network["event_count"] == 11 and network["pair_count"] == 2
    pair = network["items"][0]
    assert pair["median_interval_seconds"] == 60 and pair["bytes_sent"] == 1200
    assert client.get(base + "/network-insights?pair=" + pair["key"]).json["selected"]["key"] == pair["key"]
    assert client.get(base + "/network-insights?q=unrelated").json["items"] == []
    assert client.get(base + "/network-insights?pair=unavailable").status_code == 404
    endpoint = client.get(base + "/endpoint-queries").json
    assert endpoint["total"] == 2
    assert {item["action"] for item in endpoint["items"]} == {"added", "removed"}
    assert all(item["event_time_known"] for item in endpoint["items"])
    assert client.get(base + "/endpoint-queries?host=station-9&action=added").json["items"][0]["columns"]["pid"] == "12"
    assert client.get(base + "/endpoint-queries?host=absent").json["total"] == 0
    alerts = client.get(base + "/alerts").json["items"]
    assert len(alerts) == 1
    dossier = client.get(base + f"/alerts/{alerts[0]['id']}/dossier").json
    assert dossier["events"][0]["normalized_fields"]["ids_signature"] == "Retained IDS signature"
    assert database.execute("SELECT COUNT(*) FROM security_events WHERE owner_case_id=? AND import_job_id IS NOT NULL", (autopsy_case,)).fetchone()[0] == 13


def test_network_and_endpoints_do_not_leak_inactive_other_cases_or_unassigned_cases(autopsy_case, client, database, login_as):
    upload(client, autopsy_case, [zeek(), osquery()])
    other = client.post("/api/cases", json={"title": "Other case"}).json["id"]
    for endpoint in ("network-insights", "endpoint-queries"):
        assert client.get(f"/api/cases/{other}/{endpoint}").json["items"] == []
    database.execute("UPDATE security_events SET autopsy_active=0 WHERE owner_case_id=?", (autopsy_case,))
    assert client.get(f"/api/cases/{autopsy_case}/network-insights").json["event_count"] == 0
    assert client.get(f"/api/cases/{autopsy_case}/endpoint-queries").json["total"] == 0
    database.execute("DELETE FROM autopsy_case_members WHERE case_id=?", (autopsy_case,))
    for endpoint in ("network-insights", "endpoint-queries"):
        assert client.get(f"/api/cases/{autopsy_case}/{endpoint}").status_code == 404


@pytest.mark.parametrize(
    "endpoint,query",
    [
        ("network-insights", "page=0"),
        ("network-insights", "page=x"),
        ("network-insights", "page=1&page=2"),
        ("network-insights", "extra=1"),
        ("network-insights", "q=" + "x" * 201),
        ("network-insights", "pair=" + "x" * 25),
        ("endpoint-queries", "page=-1"),
        ("endpoint-queries", "action=unknown"),
        ("endpoint-queries", "host=" + "x" * 513),
        ("endpoint-queries", "action=added&action=removed"),
        ("endpoint-queries", "extra=1"),
    ],
)
def test_invalid_filters_rejected(autopsy_case, client, endpoint, query):
    assert client.get(f"/api/cases/{autopsy_case}/{endpoint}?{query}").status_code == 422


def test_pagination_has_no_duplicates(autopsy_case, client):
    upload(
        client,
        autopsy_case,
        [*[zeek(i, **{"id.resp_h": f"192.0.2.{i + 1}"}) for i in range(28)], {**osquery(), "diffResults": {"added": [{"pid": str(i)} for i in range(28)]}}],
    )
    for endpoint, key in (("network-insights", "key"), ("endpoint-queries", "id")):
        base = f"/api/cases/{autopsy_case}/{endpoint}"
        first, second = client.get(base).json, client.get(base + "?page=2").json
        assert first["total"] == 28 and len(first["items"]) == 25 and len(second["items"]) == 3
        assert not {item[key] for item in first["items"]} & {item[key] for item in second["items"]}


def test_reports_include_real_telemetry_and_remain_immutable(autopsy_case, client, app, login_as):
    upload(client, autopsy_case, [*[zeek(i) for i in range(6)], osquery()])
    login_as("soc_manager")
    with app.test_request_context():
        from flask import session

        with client.session_transaction() as saved:
            session.update(dict(saved))
        full = build_snapshot(_case_row(autopsy_case), 1, "full")
        redacted = build_snapshot(_case_row(autopsy_case), 1, "metadata_only_v1")
    assert full["network_analysis"]["periodic_count"] == 1 and len(full["endpoint_results"]) == 2
    assert "network_analysis" not in redacted and "endpoint_results" not in redacted
    assert "تحليل الشبكة" in render_html(full) and "نتائج الأجهزة" in render_html(full)
    assert full["network_analysis"]["items"][0]["key"] not in render_html(full)
    assert "socify-connections-1" not in render_html(full)
    base = f"/api/cases/{autopsy_case}"
    guide = client.get(base + "/quick-report").json
    answers = {question["id"]: question["options"][0]["value"] for question in guide["questions"]}
    assert client.put(base + "/quick-report", json={"answers": answers}).status_code == 200
    printed = client.get(f"/cases/{autopsy_case}/quick-report/print")
    assert printed.status_code == 200 and "تحليل الشبكة" in printed.text and "station-9" in printed.text
    assert "socify-connections-1" not in printed.text and "انتظام الفواصل" in printed.text
    upload(client, autopsy_case, [zeek(8)], "later.json")
    assert full["network_analysis"]["connection_count"] == 6


def test_network_bounds_fail_explicitly(autopsy_case, client, database, monkeypatch):
    upload(client, autopsy_case, [zeek(i) for i in range(3)])
    monkeypatch.setattr("socify.network_insights.MAX_NETWORK_EVENTS", 2)
    assert client.get(f"/api/cases/{autopsy_case}/network-insights").status_code == 422
    with pytest.raises(ValueError, match="٢٠٠٠٠"):
        network_snapshot(database, autopsy_case, 1)


def test_full_report_limits_endpoint_results(autopsy_case, client, database, monkeypatch):
    upload(client, autopsy_case, [osquery()])
    monkeypatch.setattr("socify.network_insights.network_snapshot", lambda *args: {"event_count": 1, "items": [{}] * 2001})
    with pytest.raises(ValueError, match="٢٠٠٠"):
        telemetry_report(database, autopsy_case, 1)


def test_unknown_timestamps_stay_unknown(autopsy_case, client):
    sample = zeek()
    sample.pop("ts")
    upload(client, autopsy_case, [sample])
    result = client.get(f"/api/cases/{autopsy_case}/network-insights").json["items"][0]
    assert not result["periodic"] and result["first_seen"] is None


def test_full_batch_selection_approval_and_archive_scopes(autopsy_case, client, login_as, database, app):
    login_as("soc_manager")
    job = upload(client, autopsy_case, [zeek(), osquery()])["id"]
    base = f"/api/cases/{autopsy_case}"
    assert client.put(base + f"/imports/{job}/access", json={"restricted": True, "members": [], "reason": "Scoped evidence"}).status_code == 200
    login_as("analyst")
    for endpoint in ("network-insights", "endpoint-queries"):
        assert client.get(base + "/" + endpoint).status_code in {403, 404}
    login_as("soc_manager")
    assert client.get(base + "/network-insights").status_code == 200
    app.config["REQUIRE_INVESTIGATION_SELECTION"] = True
    for endpoint in ("network-insights", "endpoint-queries"):
        assert client.get(base + "/" + endpoint).status_code in {403, 404, 409}
    app.config["REQUIRE_INVESTIGATION_SELECTION"] = False
    app.config["REQUIRE_CASE_APPROVAL"] = True
    database.execute("UPDATE case_approvals SET state='pending' WHERE case_id=?", (autopsy_case,))
    for endpoint in ("network-insights", "endpoint-queries"):
        assert client.get(base + "/" + endpoint).status_code in {403, 404, 409}
    app.config["REQUIRE_CASE_APPROVAL"] = False
    database.execute("UPDATE incident_cases SET archived_at=created_at WHERE id=?", (autopsy_case,))
    for endpoint in ("network-insights", "endpoint-queries"):
        assert client.get(base + "/" + endpoint).status_code == 404
