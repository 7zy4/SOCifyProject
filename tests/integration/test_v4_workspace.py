import pytest

from socify import create_app
from socify.autopsy_worker import job_authorized
from socify.db import get_db
from tests.integration.test_soc_workbench import alert


@pytest.fixture
def v4(app):
    app.config.update(LEGACY_TRAINING_TESTS=False, REQUIRE_CASE_APPROVAL=True, REQUIRE_INVESTIGATION_SELECTION=True)
    return app


def request_case(client, title="V4 retained incident"):
    response = client.post("/api/cases", json={"title": title, "reason": "alert_review", "objective": "Establish facts from retained evidence"})
    assert response.status_code == 201, response.json
    return response.json["id"]


def approve(client, case):
    response = client.post(f"/api/cases/{case}/approval", json={"decision": "approved", "version": 1, "reason": "Authorized investigation scope"})
    assert response.status_code == 200, response.json


def select(client, ids):
    return client.post("/api/investigation-selection", json={"case_ids": ids})


@pytest.mark.parametrize(
    "suffix,method,body",
    [
        ("/logs", "get", None),
        ("/records", "get", None),
        ("/samples", "get", None),
        ("/custody", "get", None),
        ("/chronology", "get", None),
        ("/records/asset", "post", {"name": "Premature work"}),
        ("/reports", "post", {"version": 1, "profile": "full"}),
        ("/imports", "post", {"filename": "test.json", "content": "[]"}),
        ("/transitions", "post", {"version": 1, "status": "open", "reason": "too early"}),
    ],
)
def test_unapproved_cases_cannot_be_worked_even_by_manager(v4, client, login_as, suffix, method, body):
    login_as("soc_manager")
    case = request_case(client)
    assert client.get(f"/api/cases/{case}").json["approval"]["state"] == "pending"
    response = getattr(client, method)(f"/api/cases/{case}" + suffix, json=body)
    # A missing route may still be intercepted by Flask's 404, so test only real routes.
    assert response.status_code == 409, response.json
    assert response.json["error"]["code"] == "CASE_APPROVAL_REQUIRED"
    assert select(client, [case]).status_code == 409


def test_review_permissions_conflict_rejection_and_scope(v4, client, login_as, database, user_ids):
    login_as("analyst")
    case = request_case(client)
    assert client.post(f"/api/cases/{case}/approval", json={"decision": "approved", "version": 1, "reason": "self approval"}).status_code == 403
    login_as("soc_manager")
    approve(client, case)
    assert client.post(f"/api/cases/{case}/approval", json={"decision": "rejected", "version": 1, "reason": "stale request"}).status_code == 409
    pending = request_case(client, "Rejected request")
    assert (
        client.post(f"/api/cases/{pending}/approval", json={"decision": "rejected", "version": 1, "reason": "Insufficient intake details"}).status_code == 200
    )
    assert select(client, [pending]).status_code == 409
    assert client.get(f"/api/cases/{case}/logs").status_code == 403
    assert select(client, [case]).status_code == 200
    assert client.get(f"/api/cases/{case}/logs").status_code == 200
    assert client.post(f"/api/incidents/{pending}/notes", json={"body": "premature"}).status_code == 409
    database.execute("DELETE FROM autopsy_case_members WHERE case_id=? AND user_id=?", (case, user_ids["analyst"]))
    login_as("analyst")
    assert select(client, [case]).status_code == 404


def test_two_related_cases_filter_monitoring_and_revalidate_access(v4, client, login_as, database, user_ids):
    login_as("analyst")
    cases = [request_case(client, f"Scope incident {index}") for index in range(3)]
    login_as("soc_manager")
    for case in cases:
        approve(client, case)
        alert(database, case, f"SCOPE-{case}")
    assert client.get("/api/soc/monitoring").json["total"] == 0
    assert client.get("/api/workflow/metrics").json["visible_cases"] == 0
    assert select(client, cases[:2]).status_code == 422
    response = client.post(f"/api/cases/{cases[0]}/relationships", json={"related_case_id": cases[1], "reason": "Shared synthetic campaign"})
    assert response.status_code == 200
    assert select(client, cases).status_code == 422
    assert select(client, [cases[0], cases[0]]).status_code == 422
    assert select(client, cases[:2]).status_code == 200
    data = client.get("/api/soc/monitoring").json
    assert data["total"] == 2 and sum(data["counts"].values()) == 2
    assert {row["case_id"] for row in data["items"]} == set(cases[:2])
    assert client.get("/api/workflow/metrics").json["visible_cases"] == 2
    assert client.get(f"/api/cases/{cases[2]}/logs").status_code == 403
    assert client.get(f"/api/cases/{cases[2]}").json["counts"] == {}
    login_as("analyst")
    assert select(client, cases[:2]).status_code == 200
    database.execute("DELETE FROM autopsy_case_members WHERE case_id=? AND user_id=?", (cases[1], user_ids["analyst"]))
    assert client.get("/api/investigation-selection").json["case_ids"] == []
    assert client.get("/api/soc/monitoring").json["total"] == 0


@pytest.mark.parametrize("value", [[], [True], [0], [2**64], ["1"], [1, 2, 3], "1", None])
def test_selection_rejects_malformed_inputs(v4, client, login_as, value):
    login_as("soc_manager")
    assert select(client, value).status_code == 422


def test_demo_switch_is_explicit_restricted_rotates_and_clears_scope(v4, client, login_as, database, user_ids):
    login_as("soc_manager")
    assert client.get("/api/demo/accounts").json["enabled"] is False
    assert client.post("/api/demo/switch", json={"user_id": user_ids["analyst"]}).status_code == 404
    v4.config["DEMO_MODE"] = True
    database.executemany("INSERT INTO demo_accounts(user_id) VALUES (?)", [(user_ids["soc_manager"],), (user_ids["analyst"],)])
    with client.session_transaction() as browser:
        browser["investigation_cases"] = [123]
    assert len(client.get("/api/demo/accounts").json["items"]) == 2
    assert client.post("/api/demo/switch", json={"user_id": user_ids["admin"]}).status_code == 404
    assert client.post("/api/demo/switch", json={"user_id": user_ids["analyst"]}).status_code == 200
    with client.session_transaction() as browser:
        assert browser["user_id"] == user_ids["analyst"] and "investigation_cases" not in browser and browser["session_id"]
    assert database.execute("SELECT COUNT(*) FROM security_audit_logs WHERE action='demo_account_switch'").fetchone()[0] == 1


def test_production_refuses_demo_mode(tmp_path):
    with pytest.raises(RuntimeError, match="restricted to development"):
        create_app({"ENV_NAME": "production", "DEMO_MODE": True, "DATABASE": str(tmp_path / "production.db")})


def test_pending_case_worker_and_migration_preservation(v4, client, login_as, database, user_ids):
    from socify.schema import ensure_schema

    login_as("soc_manager")
    case = request_case(client)
    with v4.app_context():
        assert job_authorized({"case_id": case, "created_by": user_ids["soc_manager"], "kind": "sample"}) is False
        ensure_schema(get_db())
    assert client.get(f"/api/cases/{case}").json["approval"]["state"] == "pending"


def test_csrf_is_required_for_selection_review_and_demo(v4, client, login_as):
    login_as("soc_manager")
    case = request_case(client)
    v4.config["WTF_CSRF_ENABLED"] = True
    for path, body in [
        ("/api/investigation-selection", {"case_ids": [case]}),
        (f"/api/cases/{case}/approval", {"decision": "approved", "version": 1, "reason": "reviewed"}),
        ("/api/demo/switch", {"user_id": 1}),
    ]:
        assert client.post(path, json=body).status_code == 400


@pytest.mark.parametrize(
    "change",
    [
        {"decision": []},
        {"decision": None},
        {"version": True},
        {"reason": 0},
        {"reason": "x" * 1001},
        {"reason": "bad\ud800text"},
        {"reason": "bad\x00text"},
        {"extra": "unsupported"},
    ],
)
def test_review_input_errors_do_not_change_request(v4, client, login_as, change):
    login_as("soc_manager")
    case = request_case(client)
    response = client.post(f"/api/cases/{case}/approval", json={"decision": "approved", "version": 1, "reason": "Authorized request", **change})
    assert response.status_code == 422
    assert client.get(f"/api/cases/{case}").json["approval"]["state"] == "pending"


def test_missing_review_fails_closed_and_restart_does_not_approve_it(v4, client, login_as, database):
    from socify.schema import ensure_schema

    login_as("soc_manager")
    case = request_case(client)
    database.execute("DELETE FROM case_approvals WHERE case_id=?", (case,))
    with v4.app_context():
        ensure_schema(get_db())
    assert client.get(f"/api/cases/{case}/logs").status_code == 409
    assert client.post(f"/api/cases/{case}/approval", json={"decision": "approved", "version": 1, "reason": "Must have an intake record"}).status_code == 409


def test_concurrent_decisions_have_one_winner(v4, client, login_as, user_ids, database):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    login_as("soc_manager")
    case = request_case(client)
    barrier = Barrier(2)

    def review(decision):
        browser = v4.test_client()
        with browser.session_transaction() as state:
            state.update(user_id=user_ids["soc_manager"], workspace_id=1)
        barrier.wait(timeout=5)
        return browser.post(f"/api/cases/{case}/approval", json={"decision": decision, "version": 1, "reason": "Concurrent manager decision"}).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(review, ["approved", "rejected"]))
    assert sorted(results) == [200, 409]
    assert database.execute("SELECT COUNT(*) FROM case_history WHERE case_id=? AND action IN ('case_approved','case_rejected')", (case,)).fetchone()[0] == 1


def test_body_based_team_assignment_cannot_bypass_approval_or_selection(v4, client, login_as, user_ids):
    login_as("soc_manager")
    case = request_case(client)
    body = {"job_id": 1, "case_id": case, "assignee": user_ids["analyst"], "instructions": "Cannot begin before review"}
    assert client.post("/api/team/assignments", json=body).status_code == 409
    approve(client, case)
    assert client.post("/api/team/assignments", json=body).status_code == 403
    assert select(client, [case]).status_code == 200
    job = client.post(f"/api/cases/{case}/imports", json={"filename": "task.json", "content": '[{"title":"Scoped work item"}]'}).json["id"]
    assert client.post("/api/team/assignments", json={**body, "job_id": job}).status_code == 201
    assert len(client.get("/api/team").json["assignments"]) == 1
    other = request_case(client, "Different work scope")
    approve(client, other)
    assert select(client, [other]).status_code == 200
    assert client.get("/api/team").json["assignments"] == []


def test_relationship_and_selection_cannot_cross_tenants(v4, client, login_as, database):
    login_as("soc_manager")
    first, other = request_case(client, "Tenant one"), request_case(client, "Other tenant")
    approve(client, first)
    approve(client, other)
    tenant = database.execute(
        "INSERT INTO training_workspaces(public_id,name,created_at) VALUES ('v4-private-tenant','Other workspace','2026-10-27T00:00:00Z')"
    ).lastrowid
    database.execute("UPDATE incident_cases SET workspace_id=? WHERE id=?", (tenant, other))
    assert client.post(f"/api/cases/{first}/relationships", json={"related_case_id": other, "reason": "Cannot connect workspaces"}).status_code == 404
    assert select(client, [first, other]).status_code == 404
    assert client.post(f"/api/cases/{first}/relationships", json={"related_case_id": first, "reason": "Self link invalid"}).status_code == 422
    assert client.post(f"/api/cases/{first}/relationships", json={"related_case_id": other, "reason": "bad\ud800text"}).status_code == 422


def test_selected_case_still_respects_restricted_imports(v4, client, login_as, database, user_ids):
    login_as("analyst")
    case = request_case(client)
    login_as("soc_manager")
    approve(client, case)
    assert select(client, [case]).status_code == 200
    job = client.post(
        f"/api/cases/{case}/imports", json={"filename": "private.json", "content": '[{"title":"RESTRICTED-V4-LOG","source_ip":"192.0.2.77"}]'}
    ).json["id"]
    assert client.put(f"/api/cases/{case}/imports/{job}/access", json={"restricted": True, "members": [], "reason": "Restricted subset"}).status_code == 200
    alert(database, case, "PRIVATE-BATCH-ALERT")
    login_as("analyst")
    assert select(client, [case]).status_code == 200
    assert client.get(f"/api/cases/{case}").json["full_case_access"] is False
    assert client.get(f"/api/cases/{case}/logs?q=RESTRICTED-V4-LOG").json["total"] == 0
    assert client.get("/api/soc/monitoring").json["total"] == 0
    assert client.get(f"/api/cases/{case}/records").status_code == 403
