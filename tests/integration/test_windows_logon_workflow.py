import json

import pytest

from socify.autopsy_report_render import render_html
from socify.autopsy_reports import build_snapshot
from socify.cases import _case_row
from socify.network_insights import telemetry_report
from socify.windows_logon import RULE_NAME
from tests.unit.test_windows_logon import logon_xml


def upload_logons(client, case_id, rows):
    response = client.post(f"/api/cases/{case_id}/imports", json={"filename": "Security.xml", "content": "<Events>" + "".join(rows) + "</Events>"})
    assert response.status_code in (200, 201), response.json
    return response.json


def correlated(database, case_id):
    return database.execute(
        "SELECT a.* FROM alerts a JOIN rules r ON r.id=a.rule_id WHERE a.owner_case_id=? AND r.name=? ORDER BY a.id", (case_id, RULE_NAME)
    ).fetchall()


@pytest.mark.parametrize("reversed_order", [False, True])
def test_windows_login_alert_dossier_and_report(autopsy_case, client, database, app, login_as, reversed_order):
    rows = [*(logon_xml(i) for i in range(5)), logon_xml(5, 4624)]
    if reversed_order:
        rows.reverse()
    upload_logons(client, autopsy_case, rows)
    alerts = correlated(database, autopsy_case)
    assert len(alerts) == 1
    evidence = json.loads(alerts[0]["evidence"])["event_ids"]
    assert len(evidence) == 6
    assert database.execute("SELECT outcome FROM security_events WHERE id=?", (evidence[-1],)).fetchone()[0] == "success"
    base = f"/api/cases/{autopsy_case}"
    dossier = client.get(base + f"/alerts/{alerts[0]['id']}/dossier").json
    assert len(dossier["events"]) == 6
    assert dossier["events"][-1]["normalized_fields"]["logon_id"] == "0x98c1"
    upload_logons(client, autopsy_case, rows)
    assert len(correlated(database, autopsy_case)) == 1
    login_as("soc_manager")
    with app.test_request_context():
        from flask import session

        with client.session_transaction() as saved:
            session.update(dict(saved))
        full = build_snapshot(_case_row(autopsy_case), 1, "full")
        redacted = build_snapshot(_case_row(autopsy_case), 1, "metadata_only_v1")
    assert len(full["logon_events"]) == 6 and "logon_events" not in redacted
    assert "auth_target" not in json.dumps(full["logon_events"])
    assert "تسجيل الدخول" in render_html(full)
    guide = client.get(base + "/quick-report").json
    assert client.put(base + "/quick-report", json={"answers": {q["id"]: q["options"][0]["value"] for q in guide["questions"]}}).status_code == 200
    report = client.get(f"/cases/{autopsy_case}/quick-report/print").text
    assert "نطاق الحساب" in report and "دخول تفاعلي عن بُعد" in report and "0xc000006a" in report
    assert telemetry_report(database, autopsy_case, 999)["logon_events"] == []
    database.execute("UPDATE security_events SET autopsy_active=0 WHERE owner_case_id=?", (autopsy_case,))
    assert telemetry_report(database, autopsy_case, 1)["logon_events"] == []


@pytest.mark.parametrize(
    "change", [{"host": "OTHER"}, {"domain": "OTHER"}, {"user": "other"}, {"ip": "192.0.2.43"}, {"kind": "3"}, {"domain": "-"}, {"minute": 16}]
)
def test_success_must_match_context_and_time_window(autopsy_case, client, database, change):
    upload_logons(client, autopsy_case, [*(logon_xml(i) for i in range(5)), logon_xml(5, 4624, **change)])
    assert not correlated(database, autopsy_case)


def test_late_failures_complete_existing_success_and_anchor_each_alert(autopsy_case, client, database):
    upload_logons(client, autopsy_case, [logon_xml(6, 4624)])
    upload_logons(client, autopsy_case, [logon_xml(i) for i in range(5)])
    assert len(correlated(database, autopsy_case)) == 1
    upload_logons(client, autopsy_case, [logon_xml(7, 4624)])
    alerts = correlated(database, autopsy_case)
    assert len(alerts) == 2
    finals = [json.loads(row["evidence"])["event_ids"][-1] for row in alerts]
    assert len(set(finals)) == 2


def test_sequence_rejects_wrong_order_unqualified_events_and_cross_case(autopsy_case, client, database):
    upload_logons(client, autopsy_case, [logon_xml(0, 4624), *(logon_xml(i) for i in range(1, 6))])
    assert not correlated(database, autopsy_case)
    # The rule's root condition must also apply to every predecessor.
    database.execute("UPDATE security_events SET source_type='unrelated' WHERE owner_case_id=? AND outcome='failed'", (autopsy_case,))
    upload_logons(client, autopsy_case, [logon_xml(6, 4624)])
    assert not correlated(database, autopsy_case)
    other = client.post("/api/cases", json={"title": "Separate investigation"}).json["id"]
    upload_logons(client, other, [logon_xml(i) for i in range(5)])
    upload_logons(client, autopsy_case, [logon_xml(7, 4624)])
    assert not correlated(database, autopsy_case)


def test_unknown_time_and_retired_evidence_do_not_complete_sequence(autopsy_case, client, database):
    upload_logons(client, autopsy_case, [logon_xml(i) for i in range(5)])
    database.execute(
        "UPDATE security_events SET normalized_fields=json_set(normalized_fields,'$.event_time_known',json('false')) WHERE owner_case_id=?", (autopsy_case,)
    )
    upload_logons(client, autopsy_case, [logon_xml(6, 4624)])
    assert not correlated(database, autopsy_case)

    database.execute(
        "UPDATE security_events SET normalized_fields=json_set(normalized_fields,'$.event_time_known',json('true')),autopsy_active=0 WHERE owner_case_id=? AND outcome='failed'",
        (autopsy_case,),
    )
    upload_logons(client, autopsy_case, [logon_xml(7, 4624)])
    assert not correlated(database, autopsy_case)


def test_missing_target_never_inherits_the_reporting_account(autopsy_case, client, database):
    upload_logons(client, autopsy_case, [logon_xml(user="-", ip="-")])
    event = database.execute("SELECT * FROM security_events WHERE owner_case_id=? AND source_type='windows'", (autopsy_case,)).fetchone()
    assert event["username"] is None and event["source_ip"] is None
    raw = json.loads(event["raw_data"])
    assert raw["raw_payload"]["SubjectUserName"] == "SYSTEM"
    assert "auth_target" not in event["raw_data"]


def test_timestamp_upper_boundary_does_not_abort_import(autopsy_case, client, database):
    rows = [*(logon_xml(i, minute=54 + i) for i in range(5)), logon_xml(5, 4624, minute=59)]
    upload_logons(client, autopsy_case, [row.replace("2026-11-02T02:", "9999-12-31T23:") for row in rows])
    assert len(correlated(database, autopsy_case)) == 1
