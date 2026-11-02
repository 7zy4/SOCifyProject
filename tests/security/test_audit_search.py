"""Audit search preserves workspace and case metadata boundaries."""

import pytest

from socify.audit import record_audit
from tests.integration.test_workspace import request_case


def test_case_search_and_facets_do_not_disclose_other_workspaces_or_hidden_titles(app, client, login_as, database, user_ids):
    app.config.update(LEGACY_TRAINING_TESTS=False, REQUIRE_CASE_APPROVAL=False, REQUIRE_INVESTIGATION_SELECTION=False)
    login_as("soc_manager")
    case = request_case(client, "Private identity investigation")
    reference = client.get(f"/api/cases/{case}").json["reference"]
    record_audit(database, "review", "case", case, details={"decision": "approved"}, actor=user_ids["soc_manager"], workspace=1)
    other = database.execute("INSERT INTO training_workspaces(public_id,name,created_at) VALUES ('audit-other','Other','2026-11-02T00:00:00Z')").lastrowid
    record_audit(database, "foreign-only", "foreign-resource", 99, details={"note": "Private identity investigation"}, workspace=other)
    found = client.get("/api/audit", query_string={"q": reference, "action": "review", "resource": "case", "result": "success"}).json
    assert found["total"] == 1
    assert found["items"][0]["resource_reference"] == reference
    assert found["items"][0]["resource_title"] == "Private identity investigation"
    assert "foreign-only" not in found["filters"]["actions"]
    assert "foreign-resource" not in found["filters"]["resources"]
    login_as("auditor")
    assert client.get("/api/audit", query_string={"q": "Private identity investigation"}).json["total"] == 0
    rows = client.get("/api/audit?action=review&resource=case").json["items"]
    assert rows and all(row["resource_reference"] is None and row["resource_title"] is None for row in rows)
    login_as("soc_manager")
    assert client.post(f"/api/cases/{case}/members", json={"user_id": user_ids["auditor"], "responsibility": "reviewer"}).status_code == 200
    login_as("auditor")
    assert client.get("/api/audit", query_string={"q": reference, "action": "review"}).json["total"] == 1
    login_as("analyst")
    assert client.get("/api/audit", query_string={"q": reference}).status_code == 403


def test_audit_search_literal_text_results_and_pagination(client, login_as, database):
    login_as("admin")
    identifiers = [
        record_audit(database, "audit-probe", "retained", index, result="denied" if index == 1 else "success", details={"note": note}, workspace=1)
        for index, note in enumerate(["75% ready", "key_one", "ordinary record"])
    ]
    for query, expected in [("%", identifiers[0]), ("_", identifiers[1])]:
        data = client.get("/api/audit", query_string={"q": query, "action": "audit-probe"}).json
        assert data["total"] == 1 and data["items"][0]["id"] == expected
    assert client.get("/api/audit", query_string={"q": "%' OR 1=1 --"}).json["total"] == 0
    assert client.get("/api/audit?action=audit-probe&result=denied").json["total"] == 1
    first = client.get("/api/audit?action=audit-probe&page_size=2").json
    second = client.get("/api/audit?action=audit-probe&page_size=2&page=2").json
    assert first["total"] == second["total"] == 3
    assert [row["id"] for row in first["items"] + second["items"]] == list(reversed(identifiers))
    assert client.get("/api/audit?action=audit-probe&page=3&page_size=2").json["items"] == []


@pytest.mark.parametrize(
    "query,status",
    [
        ({"q": "x" * 201}, 422),
        ({"action": "x" * 101}, 422),
        ({"resource": "x" * 101}, 422),
        ({"result": "x" * 101}, 422),
        ({"page": str(2**64)}, 400),
        ({"page": "9" * 5000}, 400),
    ],
)
def test_audit_query_rejects_oversized_filters(client, login_as, query, status):
    login_as("admin")
    assert client.get("/api/audit", query_string=query).status_code == status
