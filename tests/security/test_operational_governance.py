from socify.audit import record_audit


def test_operational_governance_preserves_permissions_and_workspace_scope(app, client, database, login_as):
    app.config.update(LEGACY_TRAINING_TESTS=False, REQUIRE_CASE_APPROVAL=True, REQUIRE_INVESTIGATION_SELECTION=True)
    paths = ("/api/audit", "/api/admin/users", "/api/admin/role-matrix")
    for path in paths:
        assert client.get(path).status_code == 401
    login_as("analyst")
    for path in paths:
        assert client.get(path).status_code == 403
    other = database.execute(
        "INSERT INTO training_workspaces(public_id,name,created_at) VALUES ('governance-other','Other workspace','2026-10-29T00:00:00Z')"
    ).lastrowid
    record_audit(database, "local-governance-marker", "workspace", 1, workspace=1)
    record_audit(database, "other-governance-marker", "workspace", other, workspace=other)
    login_as("admin")
    for path in paths:
        assert client.get(path).status_code == 200
    actions = {item["action"] for item in client.get("/api/audit").json["items"]}
    assert "local-governance-marker" in actions
    assert "other-governance-marker" not in actions
    for path in ("/api/events", "/api/dashboard", "/api/scores", "/api/training/runs"):
        assert client.get(path).status_code == 410
