import json

import pytest


def create_template(client, steps=None, name="Local containment"):
    return client.post(
        "/api/autopsy/procedures",
        json={"name": name, "steps": steps or [{"title": "Record containment result", "phase": "containment", "approval_required": True}]},
    )


def test_procedure_version_snapshot_evidence_and_approval(autopsy_case, client, login_as, database):
    assert create_template(client).status_code == 403
    login_as("soc_manager")
    template = create_template(client)
    assert template.status_code == 201
    identifier = template.json["id"]
    assert client.post(f"/api/cases/{autopsy_case}/procedures", json={"template_id": identifier}).status_code == 404
    assert client.post(f"/api/autopsy/procedures/{identifier}/publish").status_code == 200
    assert client.post(f"/api/autopsy/procedures/{identifier}/publish").status_code == 409
    login_as("analyst")
    applied = client.post(f"/api/cases/{autopsy_case}/procedures", json={"template_id": identifier})
    assert applied.status_code == 201
    record = applied.json
    assert record["payload"]["execution_mode"] == "documentation_only"
    assert client.post(f"/api/cases/{autopsy_case}/procedures", json={"template_id": identifier}).json["duplicate"]
    path = f"/api/cases/{autopsy_case}/procedures/{record['id']}/steps/1"
    assert client.patch(path, json={"version": 1, "status": "completed"}).status_code == 422
    assert client.patch(path, json={"version": 1, "status": "not_applicable", "notes": "Not needed for this case"}).status_code == 403
    imported = client.post(f"/api/cases/{autopsy_case}/imports", json={"filename": "test.json", "content": '[{"title":"Retained containment proof"}]'})
    assert imported.status_code == 201
    evidence = client.get(f"/api/cases/{autopsy_case}").json["evidence"][0]["id"]
    body = {"version": 1, "status": "completed", "evidence_id": evidence, "notes": "Approved action documented locally"}
    pending = client.patch(path, json=body)
    assert pending.status_code == 200, pending.json
    assert pending.json["payload"]["steps"][0]["status"] == "awaiting_approval"
    assert client.patch(path, json=body).status_code == 409
    login_as("soc_manager")
    approved = client.patch(path, json={**body, "version": 2})
    assert approved.json["payload"]["steps"][0]["approved_by"]
    second = create_template(client, [{"title": "New changed step"}])
    assert second.json["version"] == 2
    assert client.post(f"/api/autopsy/procedures/{second.json['id']}/publish").status_code == 200
    old = database.execute("SELECT payload FROM autopsy_records WHERE id = ?", (record["id"],)).fetchone()[0]
    assert json.loads(old)["steps"][0]["title"] == "Record containment result"
    login_as("analyst")
    assert client.patch(path, json={"version": 3, "status": "pending"}).status_code == 403
    assert client.get("/api/autopsy/procedures").json["items"][0]["id"] == second.json["id"]


@pytest.mark.parametrize(
    "steps",
    [
        [],
        [{"title": "x", "phase": []}],
        [{"title": "x", "role": {}}],
        [{"title": "x", "required": 1}],
        [{"title": "x", "run": "shell"}],
        [None],
        [{"title": ""}],
    ],
)
def test_template_validation(autopsy_case, client, login_as, steps):
    login_as("soc_manager")
    assert client.post("/api/autopsy/procedures", json={"name": "Invalid", "steps": steps}).status_code == 422


def test_template_seeds_roles_bola_and_closed_case(autopsy_case, client, login_as, database):
    login_as("soc_manager")
    assert client.post("/api/autopsy/procedures/seed").json["added"] == 6
    assert client.post("/api/autopsy/procedures/seed").json["added"] == 0
    template = create_template(client, [{"title": "Reviewer only", "role": "reviewer", "required": False}]).json["id"]
    assert client.post(f"/api/autopsy/procedures/{template}/publish").status_code == 200
    record = client.post(f"/api/cases/{autopsy_case}/procedures", json={"template_id": template}).json["id"]
    path = f"/api/cases/{autopsy_case}/procedures/{record}/steps/1"
    login_as("analyst")
    assert client.patch(path, json={"version": 1, "status": "in_progress"}).status_code == 403
    login_as("auditor")
    assert client.get("/api/autopsy/procedures").status_code == 200
    assert client.post(f"/api/cases/{autopsy_case}/procedures", json={"template_id": template}).status_code == 403
    login_as("soc_manager")
    assert client.patch(path, json={"version": 1, "status": []}).status_code == 422
    assert client.patch(path.replace("steps/1", "steps/99"), json={"version": 1, "status": "pending"}).status_code == 404
    assert client.patch(path, json={"version": 1, "status": "completed", "evidence_id": 999999}).status_code == 422
    assert client.patch(path, json={"version": 1, "status": "failed"}).status_code == 422
    assert client.patch(path, json={"version": 1, "status": "completed"}).status_code == 200
    assert client.patch(path, json={"version": 2, "status": "pending"}).status_code == 200
    database.execute("UPDATE incident_cases SET status = 'closed' WHERE id = ?", (autopsy_case,))
    assert client.patch(path, json={"version": 3, "status": "in_progress"}).status_code == 409
    assert client.post(f"/api/cases/{autopsy_case}/procedures", json={"template_id": template}).status_code == 409
