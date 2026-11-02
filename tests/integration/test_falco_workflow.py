import json

from socify.autopsy_report_render import render_html
from socify.autopsy_reports import build_snapshot
from socify.cases import _case_row
from socify.network_insights import telemetry_report
from tests.integration.test_telemetry_workflow import upload
from tests.unit.test_falco import falco


def test_runtime_upload_alert_dossier_and_report(autopsy_case, client, database, app, login_as):
    base = f"/api/cases/{autopsy_case}"
    upload(client, autopsy_case, [falco()])
    events = database.execute(
        "SELECT id,normalized_fields,raw_data FROM security_events WHERE owner_case_id=? AND source_type='falco'", (autopsy_case,)
    ).fetchall()
    assert len(events) == 1
    assert json.loads(events[0]["raw_data"])["output_fields"]["container.name"] == "checkout"
    alerts = client.get(base + "/alerts").json["items"]
    rule_id = database.execute("SELECT id FROM rules WHERE workspace_id=1 AND name=?", ("[SOCify] Critical Runtime Security Alert",)).fetchone()[0]
    runtime = next(item for item in alerts if item["rule_id"] == rule_id)
    assert runtime["severity"] == "critical"
    dossier = client.get(base + f"/alerts/{runtime['id']}/dossier").json
    fields = dossier["events"][0]["normalized_fields"]
    assert fields["container_id"] == "a12bc45" and fields["command_line"] == "sh"
    assert fields["sensor_hostname"] == "collector-pod-7"
    hosts = client.get(base + "/observed-hosts").json
    assert "worker-04" in json.dumps(hosts) and "collector-pod-7" not in json.dumps(hosts)
    # Re-uploading an identical file does not create another event or alert.
    duplicate = client.post(base + "/imports", json={"filename": "telemetry.json", "content": json.dumps([falco()])})
    assert duplicate.status_code == 200
    assert database.execute("SELECT COUNT(*) FROM security_events WHERE owner_case_id=? AND source_type='falco'", (autopsy_case,)).fetchone()[0] == 1
    assert len(client.get(base + "/alerts").json["items"]) == len(alerts)
    login_as("soc_manager")
    with app.test_request_context():
        from flask import session

        with client.session_transaction() as saved:
            session.update(dict(saved))
        full = build_snapshot(_case_row(autopsy_case), 1, "full")
        redacted = build_snapshot(_case_row(autopsy_case), 1, "metadata_only_v1")
    assert full["runtime_events"][0]["event_id"] == events[0]["id"]
    assert full["runtime_events"][0]["event_time"].startswith("2026-11-02T10:20:30")
    assert "runtime_events" not in redacted
    rendered = render_html(full)
    assert "checkout-7" in rendered and "أمن الأنظمة والحاويات" in rendered
    guide = client.get(base + "/quick-report").json
    answers = {question["id"]: question["options"][0]["value"] for question in guide["questions"]}
    assert client.put(base + "/quick-report", json={"answers": answers}).status_code == 200
    printed = client.get(f"/cases/{autopsy_case}/quick-report/print")
    assert printed.status_code == 200 and "checkout-7" in printed.text and "حساس الجمع" in printed.text
    database.execute("UPDATE security_events SET autopsy_active=0 WHERE owner_case_id=?", (autopsy_case,))
    assert full["runtime_events"][0]["container_name"] == "checkout"
    assert telemetry_report(database, autopsy_case, 1)["runtime_events"] == []


def test_runtime_scope_and_missing_subject_host(autopsy_case, client, database, login_as):
    base = f"/api/cases/{autopsy_case}"
    upload(client, autopsy_case, [falco(priority="Warning", output_fields={"container.id": "only-container"})])
    assert client.get(base + "/observed-hosts").json["total"] == 0
    other = client.post("/api/cases", json={"title": "Unrelated investigation"}).json["id"]
    assert telemetry_report(database, other, 1)["runtime_events"] == []
    assert telemetry_report(database, autopsy_case, 999)["runtime_events"] == []
    alerts = client.get(base + "/alerts").json["items"]
    assert alerts and alerts[0]["severity"] == "medium"
    database.execute("DELETE FROM autopsy_case_members WHERE case_id=?", (autopsy_case,))
    assert client.get(base + f"/alerts/{alerts[0]['id']}/dossier").status_code == 404
