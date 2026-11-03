"""A reviewed assignment cannot silently replace a colleague's newer work."""

import pytest


def snapshot(client, case_id):
    case = client.get(f"/api/cases/{case_id}").json
    custody = client.get(f"/api/cases/{case_id}/custody").json
    return {key: case[key] for key in ("version", "assignee", "members")}, custody


def test_stale_assignment_leaves_ownership_membership_and_audit_intact(autopsy_case, client, login_as, user_ids):
    login_as("soc_manager")
    url = f"/api/cases/{autopsy_case}/members"
    original = client.get(f"/api/cases/{autopsy_case}").json["version"]
    body = {"user_id": user_ids["analyst"], "responsibility": "owner", "version": original}
    response = client.post(url, json=body)
    assert response.status_code == 200, response.json
    before = snapshot(client, autopsy_case)
    response = client.post(url, json={**body, "responsibility": "reviewer"})
    assert response.status_code == 409 and response.json["error"]["code"] == "CASE_VERSION_CONFLICT"
    assert snapshot(client, autopsy_case) == before
    response = client.post(url, json={**body, "responsibility": "reviewer", "version": before[0]["version"]})
    assert response.status_code == 200
    member = next(row for row in response.json["members"] if row["user_id"] == body["user_id"])
    assert member["responsibility"] == "reviewer"
    after = snapshot(client, autopsy_case)
    assert after[0]["version"] > before[0]["version"]
    assert after[1]["total"] == before[1]["total"] + 1 and after[1]["integrity_valid"]


@pytest.mark.parametrize("version", [None, True, False, 0, -1, 1.5, "1", {}, [], 2**63])
def test_invalid_assignment_version_cannot_mutate_case(autopsy_case, client, login_as, user_ids, version):
    login_as("soc_manager")
    before = snapshot(client, autopsy_case)
    response = client.post(
        f"/api/cases/{autopsy_case}/members",
        json={"user_id": user_ids["auditor"], "responsibility": "reviewer", "version": version},
    )
    assert response.status_code == 422
    assert snapshot(client, autopsy_case) == before


@pytest.mark.parametrize("boundary", ["foreign", "inactive", "missing"])
def test_version_does_not_bypass_member_boundaries(autopsy_case, client, database, login_as, user_ids, boundary):
    login_as("soc_manager")
    member = user_ids["auditor"]
    if boundary == "foreign":
        database.execute("INSERT INTO training_workspaces(id,name,public_id,created_at) VALUES (99,'Separate','separate','2026-11-03T00:00:00Z')")
        database.execute("UPDATE users SET workspace_id=99 WHERE id=?", (member,))
    elif boundary == "inactive":
        database.execute("UPDATE users SET is_active=0 WHERE id=?", (member,))
    else:
        member = 999999
    before = snapshot(client, autopsy_case)
    response = client.post(
        f"/api/cases/{autopsy_case}/members",
        json={"user_id": member, "responsibility": "reviewer", "version": before[0]["version"]},
    )
    assert response.status_code == 404
    assert snapshot(client, autopsy_case) == before


def test_legacy_assignment_without_version_remains_supported(autopsy_case, client, login_as, user_ids):
    login_as("soc_manager")
    response = client.post(f"/api/cases/{autopsy_case}/members", json={"user_id": user_ids["auditor"], "responsibility": "reviewer"})
    assert response.status_code == 200
    assert any(row["user_id"] == user_ids["auditor"] and row["responsibility"] == "reviewer" for row in response.json["members"])


def test_current_version_does_not_grant_assignment_permission(autopsy_case, client, login_as, user_ids):
    login_as("analyst")
    version = client.get(f"/api/cases/{autopsy_case}").json["version"]
    response = client.post(f"/api/cases/{autopsy_case}/members", json={"user_id": user_ids["auditor"], "responsibility": "reviewer", "version": version})
    assert response.status_code == 403
