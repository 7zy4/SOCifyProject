from socify.config import build_config


def test_v6_default_config_disables_approval_and_selection_gates(monkeypatch):
    monkeypatch.delenv("SOCIFY_REQUIRE_CASE_APPROVAL", raising=False)
    monkeypatch.delenv("SOCIFY_REQUIRE_INVESTIGATION_SELECTION", raising=False)
    cfg = build_config()
    assert cfg["REQUIRE_CASE_APPROVAL"] is False
    assert cfg["REQUIRE_INVESTIGATION_SELECTION"] is False

    monkeypatch.setenv("SOCIFY_REQUIRE_CASE_APPROVAL", "true")
    monkeypatch.setenv("SOCIFY_REQUIRE_INVESTIGATION_SELECTION", "1")
    strict_cfg = build_config()
    assert strict_cfg["REQUIRE_CASE_APPROVAL"] is True
    assert strict_cfg["REQUIRE_INVESTIGATION_SELECTION"] is True


def test_analyst_creates_case_with_tactical_defaults_and_works_immediately(app, client, login_as, user_ids):
    app.config.update(
        LEGACY_TRAINING_TESTS=False,
        ALLOW_REGISTRATION=False,
        REQUIRE_CASE_APPROVAL=False,
        REQUIRE_INVESTIGATION_SELECTION=False,
    )
    login_as("analyst")
    created = client.post("/api/cases", json={"title": "Urgent off-hours VPN brute force"})
    assert created.status_code == 201, created.json
    body = created.json
    case_id = body["id"]
    assert body["assignee"] == user_ids["analyst"]
    assert body["approval"]["state"] == "approved"
    assert body["approval"]["source"] == "v6_direct"
    assert body["context"]["reason"]
    assert body["context"]["objective"]

    # Immediately import logs and query case logs without manager approval or manual selection
    imported = client.post(
        f"/api/cases/{case_id}/imports",
        json={"filename": "vpn.json", "content": '[{"title":"Failed VPN login","source_ip":"198.51.100.42"}]'},
    )
    assert imported.status_code == 201, imported.json
    logs = client.get(f"/api/cases/{case_id}/logs")
    assert logs.status_code == 200
    assert logs.json["total"] == 1


def test_unassigned_case_queue_and_claim_ownership_workflow(app, client, database, login_as, user_ids):
    app.config.update(
        LEGACY_TRAINING_TESTS=False,
        ALLOW_REGISTRATION=False,
        REQUIRE_CASE_APPROVAL=False,
        REQUIRE_INVESTIGATION_SELECTION=False,
    )
    login_as("soc_manager")
    open_case = client.post(
        "/api/cases",
        json={"title": "Unassigned SIEM alert batch", "assignee": None, "classification": "confidential"},
    )
    assert open_case.status_code == 201, open_case.json
    case_id = open_case.json["id"]
    assert open_case.json["assignee"] is None

    restricted_case = client.post(
        "/api/cases",
        json={"title": "Executive restricted case", "assignee": None, "classification": "restricted"},
    )
    assert restricted_case.status_code == 201

    other_ws = database.execute(
        "INSERT INTO training_workspaces(public_id,name,created_at) VALUES ('v6-other-tenant','Other WS','2026-11-01T00:00:00Z')"
    ).lastrowid
    other_case = client.post("/api/cases", json={"title": "Other tenant unassigned", "assignee": None}).json["id"]
    database.execute("UPDATE incident_cases SET workspace_id = ? WHERE id = ?", (other_ws, other_case))

    # Auditor cannot view claimable queue or claim cases
    login_as("auditor")
    assert client.get("/api/cases/claimable").status_code == 403
    assert client.post(f"/api/cases/{case_id}/claim").status_code == 403

    # Analyst sees only non-restricted unassigned cases in their own workspace
    login_as("analyst")
    queue = client.get("/api/cases/claimable")
    assert queue.status_code == 200, queue.json
    claimable_ids = {item["id"] for item in queue.json["items"]}
    assert case_id in claimable_ids
    assert restricted_case.json["id"] not in claimable_ids
    assert other_case not in claimable_ids

    # Restricted and cross-tenant cases cannot be claimed
    assert client.post(f"/api/cases/{restricted_case.json['id']}/claim").status_code == 404
    assert client.post(f"/api/cases/{other_case}/claim").status_code == 404

    # Analyst claims ownership of open_case
    claimed = client.post(f"/api/cases/{case_id}/claim")
    assert claimed.status_code == 200, claimed.json
    assert claimed.json["assignee"] == user_ids["analyst"]
    assert claimed.json["status"] == "investigating"
    assert any(m["user_id"] == user_ids["analyst"] and m["responsibility"] == "owner" for m in claimed.json["members"])

    # Idempotent re-claim by the same owner succeeds
    reclaimed = client.post(f"/api/cases/{case_id}/claim")
    assert reclaimed.status_code == 200

    # Another user attempting to claim an already-owned case receives 409
    login_as("soc_manager")
    conflict = client.post(f"/api/cases/{case_id}/claim")
    assert conflict.status_code == 409
    assert conflict.json["error"]["code"] == "CASE_ALREADY_CLAIMED"
