import hashlib
import io
import json
from email.message import EmailMessage

import pytest

from socify.autopsy_email import inspect_email
from socify.autopsy_pipeline import case_full_access, full_case_scope_sql
from socify.autopsy_reports import build_snapshot
from socify.db import get_db
from socify.security import current_user


def alert(database, case_id, suffix, severity="high"):
    rule = database.execute("SELECT id FROM rules ORDER BY id LIMIT 1").fetchone()[0]
    return database.execute(
        """INSERT INTO alerts(alert_id,workspace_id,rule_id,rule_version,reason,evidence,severity,confidence,detected_at,dedup_key,trace,owner_case_id)
        VALUES (?,1,?,1,?,'{}',?,0.8,'2026-10-27T08:00:00Z',?,'{}',?)""",
        (f"SOC-WORK-{suffix}", rule, f"Synthetic finding {suffix}", severity, f"workbench-{suffix}", case_id),
    ).lastrowid


def test_monitoring_filters_channels_pagination_and_membership(autopsy_case, client, login_as, database, user_ids):
    first = alert(database, autopsy_case, "VISIBLE", "critical")
    alert(database, autopsy_case, "VISIBLE-2", "low")
    login_as("soc_manager")
    other = client.post("/api/cases", json={"title": "Restricted management case", "reason": "alert_review", "objective": "Test case isolation"}).json["id"]
    alert(database, other, "HIDDEN")
    database.execute("UPDATE incident_cases SET status='investigating' WHERE id=?", (other,))
    response = client.get("/api/soc/monitoring")
    assert response.status_code == 200, response.json
    assert response.json["counts"] == {"main": 2, "investigation": 1, "closed": 0}
    login_as("analyst")
    response = client.get("/api/soc/monitoring?page_size=1&sort=severity")
    assert response.status_code == 200, response.json
    assert response.json["total"] == 2 and len(response.json["items"]) == 1
    assert response.json["items"][0]["id"] == first
    assert response.json["counts"]["investigation"] == 0
    assert "Restricted management" not in response.text and "HIDDEN" not in response.text
    assert client.get("/api/soc/monitoring?page_size=1&page=2&sort=severity").json["items"][0]["id"] != first
    assert client.get("/api/soc/monitoring?severity=critical").json["total"] == 1
    assert client.get("/api/soc/monitoring?q=VISIBLE-2").json["total"] == 1
    assert client.get("/api/soc/monitoring?q=%25").json["total"] == 0
    database.execute("UPDATE incident_cases SET assignee=? WHERE id=?", (user_ids["analyst"], autopsy_case))
    assert client.get("/api/soc/monitoring?mine=1").json["total"] == 2
    database.execute("UPDATE incident_cases SET status='closed' WHERE id=?", (autopsy_case,))
    assert client.get("/api/soc/monitoring?channel=closed").json["total"] == 2
    assert client.get("/api/soc/monitoring").json["total"] == 0
    database.execute("DELETE FROM autopsy_case_members WHERE case_id=?", (autopsy_case,))
    assert client.get("/api/soc/monitoring?channel=closed").json["total"] == 0


@pytest.mark.parametrize(
    "query",
    [
        "channel=unknown",
        "page=0",
        "page_size=51",
        "sort=1;DROP",
        "direction=sideways",
        "severity=urgent",
        "mine=yes",
        "q=" + "x" * 201,
        "page=1&page=2",
        "unsupported=1",
    ],
)
def test_monitoring_rejects_invalid_queries(autopsy_case, client, query):
    assert client.get("/api/soc/monitoring?" + query).status_code == 422


def test_monitoring_cannot_bypass_restricted_batches_or_workspace(autopsy_case, app, client, login_as, database, user_ids):
    alert(database, autopsy_case, "BATCH-PRIVATE")
    login_as("soc_manager")
    base = f"/api/cases/{autopsy_case}"
    job = client.post(base + "/imports", json={"filename": "restricted.json", "content": '[{"title":"Restricted batch"}]'}).json["id"]
    assert client.put(base + f"/imports/{job}/access", json={"restricted": True, "members": [], "reason": "Synthetic restricted batch"}).status_code == 200
    login_as("analyst")
    assert client.get(base).json["full_case_access"] is False
    response = client.get("/api/soc/monitoring")
    assert response.json["total"] == 0 and sum(response.json["counts"].values()) == 0
    assert "BATCH-PRIVATE" not in response.text
    with app.test_request_context():
        with client.session_transaction() as session:
            from flask import session as request_session

            request_session.update(dict(session))
        user = current_user()
        clause, args = full_case_scope_sql(user)
        result = get_db().execute("SELECT c.id FROM incident_cases c WHERE c.id=?" + clause, (autopsy_case, *args)).fetchone()
        assert (result is not None) == case_full_access(autopsy_case) is False
    login_as("soc_manager")
    assert (
        client.put(base + f"/imports/{job}/access", json={"restricted": True, "members": [user_ids["analyst"]], "reason": "Authorized for review"}).status_code
        == 200
    )
    login_as("analyst")
    assert client.get("/api/soc/monitoring").json["total"] == 1
    database.execute("DELETE FROM autopsy_case_members WHERE case_id=? AND user_id=?", (autopsy_case, user_ids["analyst"]))
    assert client.get("/api/soc/monitoring").json["total"] == 0


def message():
    mail = EmailMessage()
    mail["From"], mail["To"], mail["Subject"] = "sender@example.test", "analyst@example.test", "Synthetic suspicious message"
    mail["Authentication-Results"] = "forged.example; dkim=pass"
    mail.set_content("Review https://example.test/path without opening it.")
    mail.add_alternative(
        '<html><script>window.pwned=true</script><a href="https://example.test/hidden">Inspect</a><img src="https://tracker.test/a"></html>', subtype="html"
    )
    mail.add_attachment(b"Synthetic attachment, never executed", maintype="application", subtype="octet-stream", filename="payload.bin")
    return mail.as_bytes()


def test_email_inspection_retains_original_and_reports_without_active_content(autopsy_case, app, client, database):
    base = f"/api/cases/{autopsy_case}"
    raw = message()
    uploaded = client.post(base + "/samples", data={"file": (io.BytesIO(raw), "investigation.eml")}, content_type="multipart/form-data")
    assert uploaded.status_code == 201
    sample_id = uploaded.json["id"]
    endpoint = base + f"/samples/{sample_id}/email-review"
    response = client.post(endpoint, json={})
    assert response.status_code == 201, response.json
    payload = response.json["payload"]
    assert payload["sha256"] == hashlib.sha256(raw).hexdigest()
    assert payload["headers"]["Authentication-Results"].startswith("forged.example")
    assert payload["attachments"][0]["sha256"] == hashlib.sha256(b"Synthetic attachment, never executed").hexdigest()
    assert "https://example.test/hidden" in payload["urls"]
    assert "window.pwned" not in payload["body"] and "<img" not in payload["body"]
    assert "not independently verified" in payload["limitations"]
    stored = database.execute("SELECT ciphertext FROM autopsy_samples WHERE id=?", (sample_id,)).fetchone()[0]
    assert raw not in bytes(stored)
    assert client.post(endpoint, json={}).json["duplicate"] is True
    assert database.execute("SELECT COUNT(*) FROM autopsy_records WHERE kind='analysis'").fetchone()[0] == 1
    with app.test_request_context():
        from flask import session

        with client.session_transaction() as existing:
            session.update(dict(existing))
        case = get_db().execute("SELECT * FROM incident_cases WHERE id=?", (autopsy_case,)).fetchone()
        snapshot = build_snapshot(case, 1, "full")
        assert "eml_static_v1" in json.dumps(snapshot)
    assert client.get(base + "/custody").json["integrity_valid"] is True
    database.execute("UPDATE incident_cases SET status='closed' WHERE id=?", (autopsy_case,))
    assert client.post(endpoint, json={}).status_code == 409


def test_email_requires_permissions_case_scope_integrity_and_bounds(autopsy_case, client, login_as, database, user_ids, monkeypatch):
    base = f"/api/cases/{autopsy_case}"
    uploaded = client.post(base + "/samples", data={"file": (io.BytesIO(message()), "mail.eml")}, content_type="multipart/form-data").json
    endpoint = base + f"/samples/{uploaded['id']}/email-review"
    assert client.post(endpoint, json={"content": "arbitrary"}).status_code == 422
    login_as("soc_manager")
    assert client.post(f"/api/cases/{autopsy_case + 999}/samples/{uploaded['id']}/email-review", json={}).status_code == 404
    database.execute(
        "INSERT INTO autopsy_case_members(case_id,user_id,responsibility,assigned_by,assigned_at) VALUES (?,?,'reviewer',?,'2026-10-27T00:00:00Z')",
        (autopsy_case, user_ids["auditor"], user_ids["soc_manager"]),
    )
    login_as("auditor")
    assert client.post(endpoint, json={}).status_code == 403
    login_as("analyst")
    from cryptography.fernet import InvalidToken

    class BrokenCipher:
        def decrypt(self, value):
            raise InvalidToken

    with monkeypatch.context() as patch:
        patch.setattr("socify.autopsy_email.cipher", BrokenCipher)
        assert client.post(endpoint, json={}).status_code == 409
    with pytest.raises(ValueError):
        inspect_email(b"not a message")
    with pytest.raises(ValueError):
        inspect_email(b"x" * (2 * 1024 * 1024 + 1))
    html = inspect_email(
        b'From: sender@example.test\nSubject: HTML only\nContent-Type: text/html; charset=unknown-charset\n\n<p>Hello</p><script>evil()</script><a href="https://example.test">link</a>'
    )
    assert "Hello" in html["body"] and "evil()" not in html["body"]


def test_email_review_cursor_and_resource_limits(autopsy_case, client, database):
    base = f"/api/cases/{autopsy_case}"
    for index in range(12):
        payload = json.dumps({"title": f"Retained email {index}", "method": "eml_static_v1", "body": "Synthetic retained text"})
        database.execute(
            "INSERT INTO autopsy_records(case_id,kind,payload,created_by,updated_by,created_at,updated_at) VALUES (?,'analysis',?,3,3,'2026-10-27T00:00:00Z','2026-10-27T00:00:00Z')",
            (autopsy_case, payload),
        )
    first = client.get(base + "/email-reviews")
    assert first.status_code == 200 and len(first.json["items"]) == 10
    second = client.get(base + f"/email-reviews?before={first.json['next_before']}").json
    assert len(second["items"]) == 2 and second["next_before"] is None
    assert not set(row["id"] for row in first.json["items"]) & set(row["id"] for row in second["items"])
    assert client.get(base + "/email-reviews?before=0").status_code == 422
    assert client.get(base + "/email-reviews?unknown=1").status_code == 422
    with pytest.raises(ValueError, match="MIME"):
        inspect_email(b"From: sender@example.test\n" + b"X-Header: retained\n" * 201 + b"\nbody")


def test_monitoring_filters_workspace_and_custom_role_permissions(autopsy_case, app, client, database, login_as):
    alert(database, autopsy_case, "TENANT-SCOPE")
    login_as("soc_manager")
    assert client.get("/api/soc/monitoring").json["total"] == 1
    workspace = database.execute(
        "INSERT INTO training_workspaces(public_id,name,created_at) VALUES ('soc-isolation-test','Synthetic isolated tenant','2026-10-27T00:00:00Z')"
    ).lastrowid
    database.execute("UPDATE incident_cases SET workspace_id=? WHERE id=?", (workspace, autopsy_case))
    assert client.get("/api/soc/monitoring").json["total"] == 0
    assert client.put("/api/team/roles/analyst", json={"permissions": []}).status_code == 200
    login_as("analyst")
    assert client.get("/api/soc/monitoring").status_code == 403
    assert client.get("/monitoring").status_code == 403
