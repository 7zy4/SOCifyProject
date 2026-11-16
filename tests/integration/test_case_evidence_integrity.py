import hashlib
import sqlite3

import pytest

from socify import cases, create_app
from tests.conftest import issue_session


def prepared_case(client, login_as):
    login_as("soc_manager")
    created = client.post("/api/incidents", json={"title": "Evidence integrity exercise"})
    assert created.status_code == 201
    case_id = created.json["id"]
    url = f"/api/incidents/{case_id}"
    evidence = client.post(
        url + "/evidence",
        json={"type": "raw_log", "reference_id": "closure-log", "title": "Synthetic log", "content": "Training evidence"},
    )
    assert evidence.status_code == 201
    return case_id, evidence.json["id"]


def test_evidence_access_is_audited_and_content_cannot_be_replaced(client, login_as, database):
    case_id, evidence_id = prepared_case(client, login_as)
    url = f"/api/incidents/{case_id}/evidence/{evidence_id}"
    response = client.get(url)
    assert response.status_code == 200
    assert response.json["accessed_at"]
    assert response.json["sha256"] == hashlib.sha256(b"Training evidence").hexdigest()
    audit = database.execute(
        "SELECT * FROM security_audit_logs WHERE action = 'read' AND resource_type = 'case_evidence' AND resource_id = ?", (str(evidence_id),)
    ).fetchone()
    assert audit is not None
    for sql in ("UPDATE case_evidence SET sha256 = 'replacement' WHERE id = ?", "DELETE FROM case_evidence WHERE id = ?"):
        with pytest.raises(sqlite3.IntegrityError, match="immutable case evidence"):
            database.execute(sql, (evidence_id,))
    assert client.get(f"/api/incidents/{case_id + 999}/evidence/{evidence_id}").status_code == 404


def test_evidence_content_is_encrypted_preserved_and_downloadable(client, login_as, database):
    case_id, evidence_id = prepared_case(client, login_as)
    url = f"/api/incidents/{case_id}"
    stored = database.execute("SELECT ciphertext FROM case_evidence_content WHERE evidence_id = ?", (evidence_id,)).fetchone()[0]
    assert "Training evidence" not in stored
    assert stored
    assert "ciphertext" not in client.get(url).text
    detail = client.get(f"{url}/evidence/{evidence_id}")
    assert detail.json["content_available"] is True
    assert "ciphertext" not in detail.text
    response = client.get(f"{url}/evidence/{evidence_id}/content")
    assert response.status_code == 200
    assert response.data == b"Training evidence"
    assert response.headers["X-Evidence-SHA256"] == hashlib.sha256(response.data).hexdigest()
    assert response.mimetype == "application/octet-stream"
    assert response.headers["Content-Disposition"].startswith("attachment;")
    assert response.headers["Cache-Control"] == "no-store"
    for sql in ("UPDATE case_evidence_content SET ciphertext = 'replacement' WHERE evidence_id = ?", "DELETE FROM case_evidence_content WHERE evidence_id = ?"):
        with pytest.raises(sqlite3.IntegrityError, match="immutable evidence content"):
            database.execute(sql, (evidence_id,))
    assert database.execute("SELECT COUNT(*) FROM case_history WHERE case_id = ? AND action = 'evidence_downloaded'", (case_id,)).fetchone()[0] == 1


@pytest.mark.parametrize("corruption", ["wrong-content", None])
def test_evidence_integrity_failure_never_returns_unverified_content(client, login_as, monkeypatch, corruption):
    case_id, evidence_id = prepared_case(client, login_as)

    def decrypt(_):
        if corruption is None:
            raise ValueError("sensitive decryption detail")
        return corruption

    monkeypatch.setattr(cases, "decrypt_secret", decrypt)
    response = client.get(f"/api/incidents/{case_id}/evidence/{evidence_id}/content")
    assert response.status_code == 409
    assert response.json["error"]["code"] == "EVIDENCE_INTEGRITY_FAILURE"
    assert "sensitive decryption detail" not in response.text
    assert "wrong-content" not in response.text


def test_evidence_reference_without_retained_content_is_explicit(client, login_as, store_event):
    login_as("soc_manager")
    event_id = store_event({"source": "evidence-reference", "title": "Source event"})
    case_id = client.post("/api/incidents", json={"title": "Referenced evidence", "event_ids": [event_id]}).json["id"]
    url = f"/api/incidents/{case_id}"
    evidence_id = client.get(url).json["evidence"][0]["id"]
    assert client.get(f"{url}/evidence/{evidence_id}").json["content_available"] is False
    response = client.get(f"{url}/evidence/{evidence_id}/content")
    assert response.status_code == 409
    assert response.json["error"]["code"] == "EVIDENCE_CONTENT_UNAVAILABLE"


def test_retained_evidence_survives_application_restart(app, client, login_as, user_ids):
    case_id, evidence_id = prepared_case(client, login_as)
    restarted = create_app(dict(app.config))
    with restarted.test_client() as restored_client:
        with restored_client.session_transaction() as session:
            session["user_id"] = user_ids["soc_manager"]
            session["session_id"] = issue_session(restarted, user_ids["soc_manager"])
            session["workspace_id"] = 1
            session["user_role"] = "soc_manager"
        response = restored_client.get(f"/api/incidents/{case_id}/evidence/{evidence_id}/content")
        assert response.status_code == 200
        assert response.data == b"Training evidence"
