import hashlib
import io
import json
import secrets

import pytest

from socify.autopsy_samples import parse_vt_report
from socify.timeutils import iso_now


def test_original_legacy_reports_are_archived_without_regeneration(autopsy_case, client, database, login_as, user_ids):
    base = f"/api/cases/{autopsy_case}"
    assert client.get(f"/api/incidents/{autopsy_case}/report").status_code == 404
    content = json.dumps({"legacy": "Retained incident conclusions"})
    digest = hashlib.sha256(content.encode()).hexdigest()
    database.execute(
        "INSERT INTO case_reports(case_id, revision, format, content, sha256, created_by, created_at) VALUES (?, 1, 'json', ?, ?, ?, ?)",
        (autopsy_case, content, digest, user_ids["analyst"], iso_now()),
    )
    database.execute("UPDATE incident_cases SET root_cause = 'Historical conclusion retained' WHERE id = ?", (autopsy_case,))
    assert client.get(base).json["archived_reports"][0]["sha256"] == digest
    assert client.get(f"/api/incidents/{autopsy_case}/report?format=json&revision=1").data == content.encode()
    report = client.post(base + "/reports", json={"version": client.get(base).json["version"]})
    snapshot = client.get(base + f"/reports/{report.json['id']}").json["payload"]
    assert snapshot["legacy_closure"]["root_cause"] == "Historical conclusion retained"
    database.execute("UPDATE case_reports SET sha256 = ? WHERE case_id = ?", ("0" * 64, autopsy_case))
    assert client.get(f"/api/incidents/{autopsy_case}/report").status_code == 409
    login_as("soc_manager")
    assert client.post(base + "/members", json={"user_id": user_ids["auditor"], "responsibility": "reviewer"}).status_code == 200
    login_as("auditor")
    assert client.get(f"/api/incidents/{autopsy_case}/report").status_code == 403


def test_escalation_cannot_forge_role_level_or_assign_a_role_without_update_permission(autopsy_case, client, database, user_ids, login_as):
    responder = database.execute(
        "INSERT INTO users(email, password_hash, name, role, workspace_id, is_active) SELECT 'routing-l2@example.test', password_hash, 'Routing responder', 'l2_responder', 1, 1 FROM users WHERE id = ? RETURNING id",
        (user_ids["analyst"],),
    ).fetchone()[0]
    payload = {"to_user": responder, "from_level": "management", "to_level": "l2", "reason": "Inspect routing evidence", "priority": "high", "status": "raised"}
    base = f"/api/cases/{autopsy_case}/records/escalation"
    assert client.post(base, json=payload).status_code == 422
    assert client.post(base, json={**payload, "from_level": "l1", "to_user": user_ids["auditor"]}).status_code == 422
    login_as("soc_manager")
    assert client.put("/api/team/roles/l2_responder", json={"permissions": ["cases.read"]}).status_code == 200
    login_as("analyst")
    assert client.post(base, json={**payload, "from_level": "l1"}).status_code == 422
    login_as("soc_manager")
    assert client.put("/api/team/roles/l2_responder", json={"permissions": ["cases.read", "cases.update"]}).status_code == 200
    login_as("analyst")
    created = client.post(base, json={**payload, "from_level": "l1"})
    assert created.status_code == 201
    assert (
        client.patch(
            f"/api/cases/{autopsy_case}/records/{created.json['id']}",
            json={"version": 1, "payload": {**payload, "from_level": "l1", "to_user": user_ids["soc_manager"]}},
        ).status_code
        == 422
    )


@pytest.mark.parametrize("payload", [[], {}, {"reason": ""}, {"reason": "Reason", "handoff_to": True}, {"reason": "Reason", "is_admin": True}])
def test_handoff_rejects_invalid_payload_without_deactivating_user(autopsy_case, client, login_as, user_ids, database, payload):
    login_as("soc_manager")
    assert client.post(f"/api/team/members/{user_ids['analyst']}/deactivate", json=payload).status_code == 422
    assert database.execute("SELECT is_active FROM users WHERE id = ?", (user_ids["analyst"],)).fetchone()[0] == 1


def test_handoff_refuses_last_manager_and_unauthorized_changes(autopsy_case, client, database, login_as, user_ids):
    assert client.post(f"/api/team/members/{user_ids['soc_manager']}/deactivate", json={"reason": "Unauthorized attempt"}).status_code == 403
    login_as("soc_manager")
    database.execute("UPDATE users SET is_active = 0 WHERE role = 'admin'")
    assert client.post(f"/api/team/members/{user_ids['soc_manager']}/deactivate", json={"reason": "Must retain a manager"}).status_code == 409
    assert client.post("/api/team/members/999999/deactivate", json={"reason": "Unknown member"}).status_code == 404
    assert client.post(f"/api/team/members/{user_ids['analyst']}/deactivate", json={"reason": "Reason", "handoff_to": 999999}).status_code == 422


def test_samples_reject_unknown_forms_closed_cases_and_cross_case_ids(autopsy_case, client, database, login_as):
    base = f"/api/cases/{autopsy_case}"
    assert client.post(base + "/samples", data={"unknown": "value"}).status_code == 422
    assert client.post(base + "/samples/999999/analyze", json={"command": "execute"}).status_code == 422
    assert client.post(base + "/samples/999999/analyze", json={}).status_code == 404
    assert client.post(base + "/reputation/virustotal", data={"api_key": secrets.token_urlsafe(20)}).status_code == 422
    login_as("soc_manager")
    assert client.get(base + "/samples/999999/download").status_code == 404
    database.execute("UPDATE incident_cases SET status = 'closed' WHERE id = ?", (autopsy_case,))
    assert client.post(base + "/samples", data={"file": (io.BytesIO(b"Synthetic"), "test.bin")}).status_code == 409
    assert client.post(base + "/samples/999999/analyze", json={}).status_code == 409
    with pytest.raises(ValueError):
        parse_vt_report(b"", "0" * 64)
    with pytest.raises(ValueError):
        parse_vt_report(b"a" * (1024 * 1024 + 1), "0" * 64)


def test_private_views_and_reversed_time_ranges_are_validated(autopsy_case, client):
    base = f"/api/cases/{autopsy_case}/records"
    assert (
        client.post(
            base + "/timeline_view", json={"title": "Invalid period", "visibility": "team", "start": "2026-10-25T00:00:00Z", "end": "2026-10-24T00:00:00Z"}
        ).status_code
        == 422
    )
    assert client.post(base + "/bookmark", json={"title": "Foreign event", "visibility": "team", "event_id": 999999}).status_code == 422
