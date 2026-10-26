import pytest
from flask import session

from socify.autopsy_api import case_summary
from socify.db import get_db, transaction


def import_logs(client, base, filename, titles):
    import json

    response = client.post(base + "/imports", json={"filename": filename, "content": json.dumps([{"title": title} for title in titles])})
    assert response.status_code == 201, response.json
    return response.json


def totals(client, base):
    return (
        client.get(base).json["counts"]["events"],
        client.get(base + "/logs").json["total"],
        client.get(base + "/timeline").json["total"],
    )


def test_counts_track_empty_imported_and_removed_links_in_all_case_views(autopsy_case, client, database):
    base = f"/api/cases/{autopsy_case}"
    assert totals(client, base) == (0, 0, 0)
    import_logs(client, base, "first.json", ("Count first", "Count second"))
    assert totals(client, base) == (2, 2, 2)
    import_logs(client, base, "next.json", ("Count third",))
    assert totals(client, base) == (3, 3, 3)
    event = client.get(base + "/logs").json["items"][0]["id"]
    database.execute("DELETE FROM case_events WHERE case_id=? AND event_id=?", (autopsy_case, event))
    assert totals(client, base) == (2, 2, 2)
    assert client.get(base + "/chronology").json["total"] == 2


def test_warm_counts_never_replace_fresh_batch_access_checks(autopsy_case, client, database, login_as, user_ids):
    base = f"/api/cases/{autopsy_case}"
    import_logs(client, base, "public.json", ("Public first", "Public second"))
    login_as("soc_manager")
    private = import_logs(client, base, "private.json", ("Private manager evidence",))
    assert client.post(base + "/members", json={"user_id": user_ids["auditor"], "responsibility": "reviewer"}).status_code == 200
    login_as("auditor")
    assert totals(client, base) == (3, 3, 3)
    version = client.get(base).json["version"]
    database.execute(
        "INSERT INTO autopsy_batch_access(job_id,restricted,changed_by,changed_at) VALUES (?,1,?,'2026-10-26T10:00:00Z')",
        (private["id"], user_ids["soc_manager"]),
    )
    assert client.get(base).json["version"] == version
    assert totals(client, base) == (2, 2, 2)
    assert client.get(base + "/chronology").status_code == 403


def test_rolled_back_summary_cannot_poison_counts_when_a_committed_edit_reuses_the_version(autopsy_case, app, client, database, user_ids):
    base = f"/api/cases/{autopsy_case}"
    import_logs(client, base, "rollback.json", ("Retained first", "Retained second"))
    assert totals(client, base) == (2, 2, 2)
    event = client.get(base + "/logs").json["items"][0]["id"]
    with app.test_request_context():
        session.update(user_id=user_ids["analyst"], workspace_id=1)
        with pytest.raises(RuntimeError, match="Rollback fixture"), transaction():
            get_db().execute("DELETE FROM case_events WHERE case_id=? AND event_id=?", (autopsy_case, event))
            assert case_summary(autopsy_case).json["counts"]["events"] == 1
            aborted_version = get_db().execute("SELECT version FROM incident_cases WHERE id=?", (autopsy_case,)).fetchone()[0]
            raise RuntimeError("Rollback fixture")
    added = client.post(
        base + "/records/timeline",
        json={"title": "Committed investigator note", "event_time": "2026-10-20T10:00:00Z", "category": "observed", "source": "Synthetic count rollback proof"},
    )
    assert added.status_code == 201, added.json
    assert client.get(base).json["version"] == aborted_version
    assert totals(client, base) == (2, 2, 2)
    assert client.get(base + "/chronology").json["total"] == 3
