import json

from socify.schema import ensure_schema


def test_builtin_rules_auto_seeded_into_every_workspace(app, client, database, login_as):
    app.config.update(LEGACY_TRAINING_TESTS=False, REQUIRE_CASE_APPROVAL=False, REQUIRE_INVESTIGATION_SELECTION=False)
    new_ws = database.execute(
        "INSERT INTO training_workspaces(public_id, name, created_at) VALUES ('v6-fresh-ws', 'Fresh SOC Workspace', '2026-11-01T00:00:00Z')"
    ).lastrowid
    ensure_schema(database)

    for ws_id in (1, new_ws):
        count = database.execute(
            "SELECT COUNT(*) FROM rules WHERE workspace_id = ? AND is_active = 1 AND name LIKE '[SOCify V6]%'",
            (ws_id,),
        ).fetchone()[0]
        assert count >= 16, f"Expected >=16 built-in V6 rules in workspace {ws_id}, got {count}"

    login_as("analyst")
    resp = client.get("/api/autopsy/detection/builtin-rules")
    assert resp.status_code == 200, resp.json
    assert resp.json["total"] >= 16


def test_windows_xml_cef_and_json_logs_trigger_builtin_alerts_on_import(app, client, login_as):
    app.config.update(LEGACY_TRAINING_TESTS=False, REQUIRE_CASE_APPROVAL=False, REQUIRE_INVESTIGATION_SELECTION=False)
    login_as("analyst")
    case_id = client.post("/api/cases", json={"title": "Multi-format SIEM triage"}).json["id"]

    # 1. Windows Security XML (EventID 4688 encoded PowerShell + EventID 1102 audit log cleared)
    win_xml = """<Events>
      <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
          <Channel>Security</Channel>
          <EventID>4688</EventID>
          <TimeCreated SystemTime="2026-11-01T02:00:00Z"/>
          <Computer>FIN-WS01</Computer>
        </System>
        <EventData>
          <Data Name="SubjectUserName">jdoe</Data>
          <Data Name="ParentProcessName">C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE</Data>
          <Data Name="NewProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
          <Data Name="CommandLine">powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA</Data>
        </EventData>
      </Event>
      <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
          <Channel>Security</Channel>
          <EventID>1102</EventID>
          <TimeCreated SystemTime="2026-11-01T02:01:00Z"/>
          <Computer>FIN-WS01</Computer>
        </System>
        <EventData>
          <Data Name="SubjectUserName">jdoe</Data>
        </EventData>
      </Event>
    </Events>"""
    r_xml = client.post(f"/api/cases/{case_id}/imports", json={"filename": "security.xml", "content": win_xml})
    assert r_xml.status_code == 201, r_xml.json
    assert r_xml.json["accepted"] == 2

    # 2. ArcSight CEF log with SQL injection payload
    cef_log = (
        "CEF:0|Imperva|SecureSphere|14.0|SQLI-01|SQL Injection Attempt|9|"
        "src=203.0.113.88 dst=10.10.20.15 suser=guest dvchost=waf01.corp "
        "msg=GET /products?id=1' UNION SELECT username,password FROM users--\n"
    )
    r_cef = client.post(f"/api/cases/{case_id}/imports", json={"filename": "waf.cef", "content": cef_log})
    assert r_cef.status_code == 201, r_cef.json
    assert r_cef.json["format"] == "cef"
    assert r_cef.json["accepted"] == 1

    alerts_resp = client.get(f"/api/cases/{case_id}/alerts")
    assert alerts_resp.status_code == 200, alerts_resp.json
    reasons = " | ".join(item["reason"] for item in alerts_resp.json["items"])
    assert "PowerShell" in reasons
    assert "Office Application Spawning Shell" in reasons
    assert "Audit Log Cleared" in reasons
    assert "SQL Injection" in reasons


def test_direct_siem_webhook_push_and_allowlisted_pull(app, client, login_as, monkeypatch):
    app.config.update(
        LEGACY_TRAINING_TESTS=False,
        REQUIRE_CASE_APPROVAL=False,
        REQUIRE_INVESTIGATION_SELECTION=False,
    )
    login_as("analyst")
    case_id = client.post("/api/cases", json={"title": "Live SIEM connector case"}).json["id"]

    # Analyst creates a case-scoped SIEM connector and gets a one-time ingest key
    created = client.post(
        f"/api/cases/{case_id}/siem-connectors",
        json={"name": "Splunk HEC Stream", "type": "http", "endpoint": "https://siem.corp.example/api/events"},
    )
    assert created.status_code == 201, created.json
    source_id = created.json["id"]
    ingest_key = created.json["ingest_key"]
    assert ingest_key and len(ingest_key) >= 32

    # Subsequent listing never leaks ingest_key or ingest_key_hash
    listed = client.get(f"/api/cases/{case_id}/siem-connectors")
    assert listed.status_code == 200
    assert "ingest_key" not in listed.json["items"][0]
    assert "ingest_key_hash" not in listed.json["items"][0]
    assert ingest_key not in json.dumps(listed.json)
    assert listed.json["items"][0]["ingest_key_configured"] is True

    # Machine-to-machine webhook push works even with CSRF enabled, and fails closed on bad key
    app.config["WTF_CSRF_ENABLED"] = True
    try:
        bad = client.post(
            f"/api/sources/{source_id}/ingest",
            headers={"X-SOCify-Source-Key": "wrong-token"},
            json={"events": [{"title": "Should be rejected"}]},
        )
        assert bad.status_code == 401

        pushed = client.post(
            f"/api/sources/{source_id}/ingest",
            headers={"Authorization": f"Splunk {ingest_key}"},
            json={
                "events": [
                    {
                        "title": "LSASS memory dump attempt",
                        "hostname": "DC-01",
                        "process_name": "rundll32.exe",
                        "description": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\lsass.dmp full",
                        "source_ip": "10.0.5.99",
                    }
                ]
            },
        )
        assert pushed.status_code == 201, pushed.json
        assert pushed.json["accepted"] == 1
        assert pushed.json["alerts_triggered"] >= 1
    finally:
        app.config["WTF_CSRF_ENABLED"] = False

    logs = client.get(f"/api/cases/{case_id}/logs")
    assert logs.json["total"] == 1

    # Direct pull enforces SOCIFY_SOURCE_ALLOWLIST (blocks SSRF when unset, succeeds when allowlisted)
    monkeypatch.delenv("SOCIFY_SOURCE_ALLOWLIST", raising=False)
    blocked_pull = client.post(f"/api/cases/{case_id}/siem-connectors/{source_id}/pull", json={})
    assert blocked_pull.status_code == 422

    monkeypatch.setenv("SOCIFY_SOURCE_ALLOWLIST", "siem.corp.example")
    monkeypatch.setattr("socify.sources.safe_external_endpoint", lambda url, allow: (True, "ok"))
    monkeypatch.setattr(
        "socify.sources._fetch_remote_events_bytes",
        lambda url, headers: (
            b'{"title":"Ransomware shadow deletion","process_name":"vssadmin.exe","description":"vssadmin delete shadows /all /quiet"}\n',
            "application/x-ndjson",
        ),
    )
    pulled = client.post(f"/api/cases/{case_id}/siem-connectors/{source_id}/pull", json={})
    assert pulled.status_code == 200, pulled.json
    assert pulled.json["accepted"] == 1
    assert pulled.json["alerts_triggered"] >= 1
    assert client.get(f"/api/cases/{case_id}/logs").json["total"] == 2
