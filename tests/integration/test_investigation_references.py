"""Searchable investigation references preserve scope and retained relationships."""

import pytest


def cause(client, case_id, title, whys=None):
    response = client.post(
        f"/api/cases/{case_id}/records/root_cause",
        json={"category": "unknown", "conclusion": title, "whys": whys or []},
    )
    assert response.status_code == 201, response.json
    return response.json


def test_record_search_and_focus_reach_older_causes_without_changing_paging(autopsy_case, client):
    old = cause(client, autopsy_case, "Retained 100%_scope question")
    for index in range(103):
        cause(client, autopsy_case, f"Retained unrelated question {index:03d}")
    base = f"/api/cases/{autopsy_case}/records"
    first = client.get(base, query_string={"kind": "root_cause", "limit": 25}).json
    assert len(first["items"]) == 25 and old["id"] not in {row["id"] for row in first["items"]}
    selected = client.get(base, query_string={"kind": "root_cause", "focus": old["id"]}).json
    assert len(selected["items"]) == 1 and selected["items"][0]["id"] == old["id"] and selected["next_before"] is None
    literal = client.get(base, query_string={"kind": "root_cause", "q": "%_"}).json
    assert len(literal["items"]) == 1 and literal["items"][0]["id"] == old["id"]
    ids, before = [], None
    while True:
        page = client.get(base, query_string={"kind": "root_cause", "q": "unrelated", "limit": 25, **({"before": before} if before else {})}).json
        ids.extend(row["id"] for row in page["items"])
        before = page["next_before"]
        if before is None:
            break
    assert len(ids) == len(set(ids)) == 103 and old["id"] not in ids


@pytest.mark.parametrize(
    "query", ["focus=0", "focus=-1", "focus=9223372036854775808", "focus=x", "focus=1&focus=2", "before=9223372036854775808", "q=a&q=b", "q=" + "a" * 201]
)
def test_record_reference_rejects_invalid_search_and_focus(autopsy_case, client, query):
    assert client.get(f"/api/cases/{autopsy_case}/records?{query}").status_code == 422


def test_search_and_exact_focus_do_not_reveal_private_or_foreign_records(autopsy_case, client, login_as):
    login_as("soc_manager")
    private = client.post(
        f"/api/cases/{autopsy_case}/records/war_room", json={"title": "Private finance decision", "body": "Manager-only retained note", "visibility": "private"}
    ).json
    other = client.post("/api/cases", json={"title": "Separate finance case"}).json["id"]
    foreign = cause(client, other, "Confidential finance hypothesis")
    login_as("analyst")
    base = f"/api/cases/{autopsy_case}/records"
    assert client.get(base, query_string={"q": "Private finance"}).json["items"] == []
    assert client.get(base, query_string={"focus": private["id"]}).status_code == 404
    missing = client.get(base, query_string={"kind": "root_cause", "focus": foreign["id"]})
    assert missing.status_code == 404 and "Confidential finance" not in missing.text
    assert client.get(f"/api/cases/{other}/records", query_string={"q": "finance"}).status_code == 404


def test_reference_focus_obeys_intake_and_investigation_selection(autopsy_case, app, client, database):
    retained = cause(client, autopsy_case, "Retained approval hypothesis")
    path = f"/api/cases/{autopsy_case}/records?kind=root_cause&focus={retained['id']}"
    app.config["REQUIRE_CASE_APPROVAL"] = True
    database.execute("UPDATE case_approvals SET state='pending' WHERE case_id=?", (autopsy_case,))
    assert client.get(path).status_code == 409
    app.config["REQUIRE_CASE_APPROVAL"] = False
    app.config["REQUIRE_INVESTIGATION_SELECTION"] = True
    assert client.get(path).status_code == 403
    assert client.post("/api/investigation-selection", json={"case_ids": [autopsy_case]}).status_code == 200
    assert client.get(path).status_code == 200


def test_linked_cause_branch_must_be_unlinked_before_removal(autopsy_case, client, user_ids):
    original = cause(
        client, autopsy_case, "Identity review hypothesis", [{"id": "identity", "question": "Why was the scope missed?", "answer": "Needs approval review"}]
    )
    action = {
        "title": "Review identity scope",
        "owner_id": user_ids["analyst"],
        "due_at": "2026-11-04T09:00:00Z",
        "status": "open",
        "root_cause_id": original["id"],
        "why_id": "identity",
    }
    created = client.post(f"/api/cases/{autopsy_case}/records/corrective", json=action)
    assert created.status_code == 201
    path = f"/api/cases/{autopsy_case}/records/{original['id']}"
    changed = {**original["payload"], "whys": []}
    blocked = client.patch(path, json={"version": 1, "payload": changed})
    assert blocked.status_code == 409 and blocked.json["error"]["code"] == "CAUSE_BRANCH_IN_USE"
    assert client.get(f"/api/cases/{autopsy_case}/records?focus={original['id']}").json["items"][0]["version"] == 1
    action.pop("why_id")
    assert client.patch(f"/api/cases/{autopsy_case}/records/{created.json['id']}", json={"version": 1, "payload": action}).status_code == 200
    assert client.patch(path, json={"version": 1, "payload": changed}).status_code == 200
