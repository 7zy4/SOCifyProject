import base64
import json

import pytest

from socify.autopsy_report_render import render_html
from socify.autopsy_reports import build_snapshot
from socify.autopsy_worker import run_autopsy_worker_once
from socify.cases import _case_row
from socify.content_inspection import RESERVED_FIELDS


def upload(client, case_id, content, filename="content.json"):
    response = client.post(f"/api/cases/{case_id}/imports", json={"filename": filename, "content": json.dumps(content)})
    assert response.status_code == 201, response.json
    return response


def suspicious_records():
    return [
        {"title": "Configuration exposure", "message": "api_key=" + "Ab3!Cd4@Ef5#Gh6"},
        {"title": "Financial export", "message": "4111111111111111", "iban": "GB82WEST12345698765432"},
        {
            "title": "Encoded command",
            "command_line": "powershell -EncodedCommand " + base64.b64encode("Invoke-Expression ('text')".encode("utf-16-le")).decode(),
        },
    ]


def test_uploaded_content_produces_evidenced_alerts_and_masked_case_results(autopsy_case, client, database):
    base = f"/api/cases/{autopsy_case}"
    assert client.get(base + "/content-inspection").json["total"] == 0
    upload(client, autopsy_case, suspicious_records())
    response = client.get(base + "/content-inspection")
    assert response.status_code == 200, response.json
    assert response.json["total"] == 3
    assert "Ab3!Cd4@Ef5#Gh6" not in response.text
    assert "4111111111111111" not in response.text
    assert "GB82WEST12345698765432" not in response.text
    findings = [finding for item in response.json["items"] for finding in item["inspection"]["findings"]]
    assert {finding["kind"] for finding in findings} == {"credential_assignment", "payment_card", "iban"}
    alerts = client.get(base + "/alerts").json["items"]
    expected = {"[SOCify] Exposed Credential Material", "[SOCify] Sensitive Financial Data Exposure", "[SOCify] Suspicious Decoded Content"}
    rules = {row["id"]: row["name"] for row in database.execute("SELECT id,name FROM rules")}
    assert expected <= {rules[alert["rule_id"]] for alert in alerts}
    for alert in alerts:
        dossier = client.get(base + f"/alerts/{alert['id']}/dossier")
        assert dossier.status_code == 200
        assert dossier.json["events"]
        assert all(event["normalized_fields"].get("content_inspection") for event in dossier.json["events"])
    raw = database.execute("SELECT raw_data,raw_hash FROM security_events WHERE owner_case_id=? ORDER BY id", (autopsy_case,)).fetchall()
    assert "Ab3!Cd4@Ef5#Gh6" in raw[0]["raw_data"]
    assert all(row["raw_hash"] for row in raw)
    second = client.post("/api/cases", json={"title": "Separate investigation"}).json["id"]
    assert client.get(f"/api/cases/{second}/content-inspection").json["total"] == 0


def test_content_cannot_forge_findings_or_financial_alerts(autopsy_case, client):
    base = f"/api/cases/{autopsy_case}"
    upload(
        client,
        autopsy_case,
        [
            {
                "title": "Routine activity",
                "message": "4111111111111112",
                "iban": "GB00WEST12345698765432",
                "normalized_fields": {"exposed_secret_count": 99, "content_inspection": {"engine": "socify-content-1", "findings": ["forged"]}},
            }
        ],
    )
    assert client.get(base + "/content-inspection").json["total"] == 0
    assert client.get(base + "/alerts").json["items"] == []


def test_rules_rescan_inspects_old_evidence_and_is_idempotent(autopsy_case, app, client, database):
    base = f"/api/cases/{autopsy_case}"
    upload(client, autopsy_case, suspicious_records())
    retained = database.execute("SELECT id,raw_data,raw_hash,normalized_fields FROM security_events WHERE owner_case_id=?", (autopsy_case,)).fetchall()
    before_alerts = {item["id"] for item in client.get(base + "/alerts").json["items"]}
    for event in retained:
        fields = {key: value for key, value in json.loads(event["normalized_fields"]).items() if key not in RESERVED_FIELDS}
        database.execute("UPDATE security_events SET normalized_fields=? WHERE id=?", (json.dumps(fields), event["id"]))
    assert client.get(base + "/content-inspection").json["total"] == 0
    queued = client.post(base + "/detection", json={"version": client.get(base).json["version"], "mode": "rules"})
    assert queued.status_code == 202, queued.json
    with app.app_context():
        assert run_autopsy_worker_once() == queued.json["id"]
    assert client.get(base + f"/jobs/{queued.json['id']}").json["state"] == "completed"
    assert client.get(base + "/content-inspection").json["total"] == 3
    assert before_alerts == {item["id"] for item in client.get(base + "/alerts").json["items"]}
    for event in retained:
        after = database.execute("SELECT raw_data,raw_hash FROM security_events WHERE id=?", (event["id"],)).fetchone()
        assert tuple(after) == (event["raw_data"], event["raw_hash"])


def test_content_snapshot_preserves_inspection_and_respects_redaction(autopsy_case, app, client, login_as):
    upload(client, autopsy_case, suspicious_records())
    login_as("soc_manager")
    with app.test_request_context():
        from flask import session

        with client.session_transaction() as saved:
            session.update(dict(saved))
        full = build_snapshot(_case_row(autopsy_case), 1, "full")
        redacted = build_snapshot(_case_row(autopsy_case), 1, "metadata_only_v1")
    assert len(full["content_inspection"]) == 3
    inspection = json.dumps(full["content_inspection"])
    assert "Ab3!Cd4@Ef5#Gh6" not in inspection and "4111111111111111" not in inspection
    assert "content_inspection" not in redacted
    assert "فحص المحتوى والترميزات" in render_html(full)
    base = f"/api/cases/{autopsy_case}"
    guide = client.get(base + "/quick-report").json
    answers = {question["id"]: question["options"][0]["value"] for question in guide["questions"]}
    assert client.put(base + "/quick-report", json={"answers": answers}).status_code == 200
    printed = client.get(f"/cases/{autopsy_case}/quick-report/print")
    assert printed.status_code == 200 and "فحص المحتوى والترميزات" in printed.text
    assert "Ab3!Cd4@Ef5#Gh6" not in printed.text and "4111111111111111" not in printed.text
    upload(client, autopsy_case, [{"title": "Later event", "api_key": "Later4!Credential5#"}], "later.json")  # pragma: allowlist secret
    assert len(full["content_inspection"]) == 3


@pytest.mark.parametrize("query", ["page=0", "page=-1", "page=a", "page=1000001", "page=1&page=2", "extra=x"])
def test_inspection_rejects_bad_pagination(autopsy_case, client, query):
    assert client.get(f"/api/cases/{autopsy_case}/content-inspection?{query}").status_code == 422


def test_content_pagination_active_import_and_access(autopsy_case, app, client, database, login_as):
    base = f"/api/cases/{autopsy_case}/content-inspection"
    upload(client, autopsy_case, [{"title": f"Entry {i}", "iban": "GB82WEST12345698765432"} for i in range(28)])
    first, second = client.get(base).json, client.get(base + "?page=2").json
    assert first["total"] == 28 and len(first["items"]) == 25 and len(second["items"]) == 3
    assert not {item["event_id"] for item in first["items"]} & {item["event_id"] for item in second["items"]}
    database.execute("UPDATE security_events SET autopsy_active=0 WHERE id=?", (first["items"][0]["event_id"],))
    assert client.get(base).json["total"] == 27
    database.execute("DELETE FROM autopsy_case_members WHERE case_id=?", (autopsy_case,))
    assert client.get(base).status_code in {403, 404}
    login_as("soc_manager")
    app.config["REQUIRE_INVESTIGATION_SELECTION"] = True
    assert client.get(base).status_code in {403, 404, 409}
    app.config["REQUIRE_INVESTIGATION_SELECTION"] = False
    app.config["REQUIRE_CASE_APPROVAL"] = True
    database.execute("UPDATE case_approvals SET state='pending' WHERE case_id=?", (autopsy_case,))
    assert client.get(base).status_code in {403, 404, 409}


def test_restricted_import_and_archived_case_do_not_expose_content(autopsy_case, client, login_as, database):
    login_as("soc_manager")
    job = upload(client, autopsy_case, suspicious_records()).json["id"]
    base = f"/api/cases/{autopsy_case}"
    assert client.put(base + f"/imports/{job}/access", json={"restricted": True, "members": [], "reason": "Restricted investigation subset"}).status_code == 200
    login_as("analyst")
    assert client.get(base + "/content-inspection").status_code in {403, 404}
    login_as("soc_manager")
    assert client.get(base + "/content-inspection").json["total"] == 3
    database.execute("UPDATE incident_cases SET archived_at=created_at WHERE id=?", (autopsy_case,))
    assert client.get(base + "/content-inspection").status_code == 404
