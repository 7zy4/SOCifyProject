import json
import re

from socify.autopsy_report_render import lines, render_html, report_table
from socify.autopsy_reports import build_snapshot
from socify.cases import _case_row
from socify.network_insights import telemetry_report
from tests.integration.test_telemetry_workflow import upload
from tests.unit.test_snort import snort


def test_snort_import_investigation_reports_and_scope(autopsy_case, client, database, app, login_as):
    base = f"/api/cases/{autopsy_case}"
    upload(client, autopsy_case, [snort()])
    rule = database.execute("SELECT id FROM rules WHERE workspace_id=1 AND name='[SOCify] Snort High Alert'").fetchone()[0]
    alerts = client.get(base + "/alerts").json["items"]
    alert = next(item for item in alerts if item["rule_id"] == rule)
    dossier = client.get(base + f"/alerts/{alert['id']}/dossier").json
    assert dossier["events"][0]["normalized_fields"]["ids_rule"] == "1:1000000:2"
    assert client.get(base + "/observed-hosts").json["total"] == 0
    assert client.post(base + "/imports", json={"filename": "telemetry.json", "content": json.dumps([snort()])}).status_code == 200
    assert len(client.get(base + "/alerts").json["items"]) == len(alerts)
    login_as("soc_manager")
    with app.test_request_context():
        from flask import session

        with client.session_transaction() as saved:
            session.update(dict(saved))
        full = build_snapshot(_case_row(autopsy_case), 1, "full")
        redacted = build_snapshot(_case_row(autopsy_case), 1, "metadata_only_v1")
    assert full["network_alerts"][0]["source_port"] == 50284
    assert "network_alerts" not in redacted
    assert "تنبيهات الشبكة" in render_html(full)
    guide = client.get(base + "/quick-report").json
    assert client.put(base + "/quick-report", json={"answers": {q["id"]: q["options"][0]["value"] for q in guide["questions"]}}).status_code == 200
    printed = client.get(f"/cases/{autopsy_case}/quick-report/print").text
    assert 'class="qa-table report-facts"' in printed and "معرف قاعدة الرصد" in printed
    assert "would_drop" in printed and "50284" in printed
    assert not re.search(r">— \d+ —<", printed)
    assert telemetry_report(database, autopsy_case, 999)["network_alerts"] == []
    database.execute("UPDATE security_events SET autopsy_active=0 WHERE owner_case_id=?", (autopsy_case,))
    assert telemetry_report(database, autopsy_case, 1)["network_alerts"] == []


def test_report_numbers_have_labels_and_untrusted_text_is_escaped():
    content = {"event_ids": [7, 8], "findings": [{"event_id": 7, "title": "<script>alert(1)</script>"}]}
    rendered = report_table(content)
    assert '<th scope="row">معرفات السجلات المرتبطة</th>' in rendered
    assert "7، 8" in rendered and "&lt;script&gt;" in rendered
    assert "<script>" not in rendered
    assert all(not re.fullmatch(r"[—\s\d]+", text) for _, text in lines(content))
