"""Retain verified report authors without exposing unrelated identities."""

import json

import pytest

from tests.integration.test_autopsy_reports import request_report


def add_note(client, case_id, visibility="team"):
    response = client.post(
        f"/api/cases/{case_id}/records/war_room",
        json={"title": f"{visibility} investigation decision", "body": "Retained gateway evidence reviewed", "visibility": visibility},
    )
    assert response.status_code == 201, response.json
    return response.json


def retained_snapshot(client, case_id, profile="full"):
    prepared = request_report(client, case_id, profile)
    assert prepared.status_code == 202, prepared.json
    path = f"/api/cases/{case_id}/reports/{prepared.json['id']}"
    return path, client.get(path).json["payload"]


def test_report_retains_author_and_editor_names_without_rewriting_history(autopsy_case, client, login_as, database, user_ids):
    for role, name in (("analyst", "Noura retained author"), ("soc_manager", "Salem retained editor")):
        database.execute("UPDATE users SET name=?,name_ar=?,name_en=? WHERE id=?", (name, name, name, user_ids[role]))
    note = add_note(client, autopsy_case)
    login_as("soc_manager")
    updated = client.patch(
        f"/api/cases/{autopsy_case}/records/{note['id']}",
        json={"version": note["version"], "payload": {**note["payload"], "body": "Independent review confirms the retained evidence"}},
    )
    assert updated.status_code == 200, updated.json
    path, snapshot = retained_snapshot(client, autopsy_case)
    record = snapshot["records"]["war_room"][0]
    assert record["created_by_name"] == "Noura retained author"
    assert record["updated_by_name"] == "Salem retained editor"
    assert (record["id"], record["created_by"], record["updated_by"]) == (note["id"], user_ids["analyst"], user_ids["soc_manager"])
    database.execute("UPDATE users SET name='Later account name',name_ar='',name_en='' WHERE id=?", (user_ids["analyst"],))
    database.execute("UPDATE users SET name='',name_ar='',name_en='' WHERE id=?", (user_ids["soc_manager"],))
    assert client.get(path).json["payload"] == snapshot


@pytest.mark.parametrize("unavailable", ["missing-name", "different-workspace"])
def test_report_does_not_guess_unavailable_editor_identity(autopsy_case, client, database, user_ids, unavailable):
    note = add_note(client, autopsy_case)
    editor = user_ids["instructor"]
    database.execute("UPDATE autopsy_records SET updated_by=? WHERE id=?", (editor, note["id"]))
    if unavailable == "missing-name":
        database.execute("UPDATE users SET name='',name_ar='',name_en='' WHERE id=?", (editor,))
    else:
        database.execute("UPDATE users SET workspace_id=999,name='OTHER_WORKSPACE_EDITOR',name_ar='',name_en='' WHERE id=?", (editor,))
    _, snapshot = retained_snapshot(client, autopsy_case)
    record = snapshot["records"]["war_room"][0]
    assert record["updated_by"] == editor and record["updated_by_name"] is None
    assert record["created_by_name"]
    assert "OTHER_WORKSPACE_EDITOR" not in json.dumps(snapshot)


def test_report_author_enrichment_respects_private_and_redacted_boundaries(autopsy_case, client, database, user_ids):
    database.execute("UPDATE users SET name='CONFIDENTIAL_AUTHOR_NAME',name_ar='',name_en='' WHERE id=?", (user_ids["analyst"],))
    add_note(client, autopsy_case)
    private = add_note(client, autopsy_case, "private")
    _, full = retained_snapshot(client, autopsy_case)
    assert len(full["records"]["war_room"]) == 1
    assert full["records"]["war_room"][0]["id"] != private["id"]
    _, redacted = retained_snapshot(client, autopsy_case, "metadata_only_v1")
    assert redacted["records"] == {}
    assert "CONFIDENTIAL_AUTHOR_NAME" not in json.dumps(redacted)
    assert "created_by_name" not in json.dumps(redacted) and "updated_by_name" not in json.dumps(redacted)
