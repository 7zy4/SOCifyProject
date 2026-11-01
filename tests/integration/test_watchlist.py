import json


def test_watchlist_crud_normalization_and_rbac(app, client, login_as):
    app.config.update(LEGACY_TRAINING_TESTS=False, REQUIRE_CASE_APPROVAL=False, REQUIRE_INVESTIGATION_SELECTION=False)
    login_as("analyst")

    # Add suspicious email, IPv4-mapped IPv6 IP, and CIDR range
    r_email = client.post(
        "/api/watchlist",
        json={"indicator_type": "email", "value": "  Attacker@Evil-Drop.Example ", "severity": "high", "note": "BEC sender"},
    )
    assert r_email.status_code == 201, r_email.json
    assert r_email.json["value"] == "attacker@evil-drop.example"

    r_ip = client.post(
        "/api/watchlist",
        json={"indicator_type": "ip", "value": "::ffff:198.51.100.77", "severity": "critical", "note": "C2 node"},
    )
    assert r_ip.status_code == 201, r_ip.json
    assert r_ip.json["value"] == "198.51.100.77"

    r_cidr = client.post(
        "/api/watchlist",
        json={"indicator_type": "cidr", "value": "203.0.113.45/24", "severity": "high", "note": "Bulletproof subnet"},
    )
    assert r_cidr.status_code == 201, r_cidr.json
    assert r_cidr.json["value"] == "203.0.113.0/24"

    # Reject malformed IP / email
    bad = client.post("/api/watchlist", json={"indicator_type": "ip", "value": "999.999.1.1"})
    assert bad.status_code == 422

    listed = client.get("/api/watchlist")
    assert listed.status_code == 200
    assert listed.json["total"] == 3

    # Auditor can read watchlist but cannot modify it
    entry_id = r_ip.json["id"]
    login_as("auditor")
    assert client.get("/api/watchlist").status_code == 200
    assert client.post("/api/watchlist", json={"indicator_type": "ip", "value": "192.0.2.9"}).status_code == 403
    assert client.delete(f"/api/watchlist/{entry_id}").status_code == 403

    # Analyst can toggle active state and delete
    login_as("analyst")
    toggled = client.patch(f"/api/watchlist/{entry_id}", json={"is_active": False, "note": "Archived C2"})
    assert toggled.status_code == 200
    assert toggled.json["is_active"] is False
    deleted = client.delete(f"/api/watchlist/{entry_id}")
    assert deleted.status_code == 200


def test_watchlist_auto_alerts_on_log_import_and_retroactive_case_scan(app, client, login_as):
    app.config.update(LEGACY_TRAINING_TESTS=False, REQUIRE_CASE_APPROVAL=False, REQUIRE_INVESTIGATION_SELECTION=False)
    login_as("analyst")

    # Watchlist CIDR and suspicious email before importing logs
    w_cidr = client.post(
        "/api/watchlist",
        json={"indicator_type": "cidr", "value": "203.0.113.0/24", "severity": "high", "note": "Known phishing proxy net"},
    ).json
    w_email = client.post(
        "/api/watchlist",
        json={"indicator_type": "email", "value": "lure@malicious-invoice.example", "severity": "critical", "note": "Invoice fraud sender"},
    ).json

    case_id = client.post("/api/cases", json={"title": "Watchlist correlation case"}).json["id"]
    events_payload = json.dumps(
        [
            {
                "title": "VPN login from IPv4-mapped address",
                "source_ip": "::ffff:203.0.113.55",
                "username": "ahmed",
                "description": "Remote VPN session established",
            },
            {
                "title": "Inbound mail relay log",
                "source_ip": "192.0.2.199",
                "username": "lure@malicious-invoice.example",
                "description": "SMTP message delivered from lure@malicious-invoice.example to finance@corp.example",
            },
        ]
    )
    imp = client.post(f"/api/cases/{case_id}/imports", json={"filename": "gateway.json", "content": events_payload})
    assert imp.status_code == 201, imp.json
    assert imp.json["accepted"] == 2

    # Both watchlist indicators automatically produced case alerts & incremented hits_count!
    alerts = client.get(f"/api/cases/{case_id}/alerts").json["items"]
    watchlist_reasons = [a["reason"] for a in alerts if "Watchlist" in a["reason"]]
    assert any("203.0.113.0/24" in r for r in watchlist_reasons), alerts
    assert any("lure@malicious-invoice.example" in r for r in watchlist_reasons), alerts

    wl_items = {item["id"]: item for item in client.get("/api/watchlist").json["items"]}
    assert wl_items[w_cidr["id"]]["hits_count"] >= 1
    assert wl_items[w_email["id"]]["hits_count"] >= 1

    # Now analyst adds 192.0.2.199 AFTER the logs were already imported, and runs retroactive watchlist scan!
    w_late = client.post(
        "/api/watchlist",
        json={"indicator_type": "ip", "value": "192.0.2.199", "severity": "high", "note": "Discovered relay IP"},
    ).json
    retro = client.post(f"/api/cases/{case_id}/watchlist-scan", json={})
    assert retro.status_code == 200, retro.json
    assert retro.json["alerts_created"] >= 1
    assert any(m["watchlist_id"] == w_late["id"] for m in retro.json["matches"])

    # Re-running retroactive scan is idempotent (does not duplicate alerts for the same event+watchlist entry)
    retro_again = client.post(f"/api/cases/{case_id}/watchlist-scan", json={})
    assert retro_again.status_code == 200
    assert retro_again.json["alerts_created"] == 0
