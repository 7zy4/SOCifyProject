import json
import sqlite3
import time

import pytest

from socify import autopsy_reports, autopsy_worker, import_worker
from socify.db import get_db


def test_worker_claims_back_off_without_claiming_or_crashing_while_another_writer_holds_the_database(autopsy_case, app, client, database):
    database.execute("PRAGMA journal_mode=WAL")
    base = f"/api/cases/{autopsy_case}"
    queued = client.post(base + "/reports", json={"version": client.get(base).json["version"]}).json
    imported = client.post(base + "/imports?defer=1", json={"filename": "claim.json", "content": '[{"title":"Queued contention evidence"}]'}).json
    database.execute("BEGIN IMMEDIATE")
    try:
        started = time.monotonic()
        with app.app_context():
            assert autopsy_worker.claim_job("must-back-off") is None
            assert import_worker.claim_import_job(get_db(), "must-back-off") is None
            assert get_db().execute("PRAGMA busy_timeout").fetchone()[0] == 15000
        assert time.monotonic() - started < 1
        assert database.execute("SELECT attempts FROM autopsy_jobs WHERE id=?", (queued["job_id"],)).fetchone()[0] == 0
        assert database.execute("SELECT status FROM ingestion_jobs WHERE id=?", (imported["id"],)).fetchone()[0] == "queued"
    finally:
        database.rollback()
    with app.app_context():
        assert autopsy_worker.claim_job("writer-released")["id"] == queued["job_id"]
        assert import_worker.claim_import_job(get_db(), "writer-released") == imported["id"]


@pytest.mark.parametrize(
    "module,method,args", [(autopsy_worker, "claim_job_locked", ("full-storage",)), (import_worker, "claim_import_job_locked", (None, "full-storage", 60))]
)
def test_worker_claims_do_not_hide_nontransient_storage_errors(monkeypatch, module, method, args):
    def fail(*_):
        error = sqlite3.OperationalError("Synthetic full storage")
        error.sqlite_errorcode = sqlite3.SQLITE_FULL
        raise error

    monkeypatch.setattr(module, method, fail)
    function = autopsy_worker.claim_job if module is autopsy_worker else import_worker.claim_import_job
    with pytest.raises(sqlite3.OperationalError, match="Synthetic full storage"):
        function(*args)


@pytest.mark.parametrize("change,status", [("case-version", 409), ("role-policy", 403), ("case-archived", 404), ("batch-scope", 403)])
def test_report_snapshot_allows_writers_and_rechecks_case_and_permissions_before_publication(
    autopsy_case, app, client, database, login_as, monkeypatch, change, status
):
    database.execute("PRAGMA journal_mode=WAL")
    login_as("soc_manager")
    base = f"/api/cases/{autopsy_case}"
    imported = client.post(base + "/imports", json={"filename": "snapshot.json", "content": '[{"title":"Snapshot scope evidence"}]'}).json
    if change in {"batch-scope", "role-policy"}:
        login_as("analyst")
    version = client.get(base).json["version"]
    original = autopsy_reports.build_snapshot

    def snapshot(*args):
        result = original(*args)
        if change == "case-version":
            database.execute("UPDATE incident_cases SET version=version+1 WHERE id=?", (autopsy_case,))
        elif change == "case-archived":
            database.execute("UPDATE incident_cases SET archived_at='2026-10-26T10:00:00Z' WHERE id=?", (autopsy_case,))
        elif change == "batch-scope":
            database.execute(
                "INSERT INTO autopsy_batch_access(job_id,restricted,changed_by,changed_at) VALUES (?,1,?,'2026-10-26T10:00:00Z')",
                (imported["id"], imported["created_by"]),
            )
        else:
            database.execute(
                "INSERT INTO team_role_permissions(workspace_id,role,permissions) VALUES (1,'analyst',?) ON CONFLICT(workspace_id,role) DO UPDATE SET permissions=excluded.permissions",
                (json.dumps(["cases.read"]),),
            )
        return result

    monkeypatch.setattr(autopsy_reports, "build_snapshot", snapshot)
    response = client.post(base + "/reports", json={"version": version})
    assert response.status_code == status, response.json
    assert database.execute("SELECT COUNT(*) FROM autopsy_reports WHERE case_id=?", (autopsy_case,)).fetchone()[0] == 0
    assert database.execute("SELECT COUNT(*) FROM autopsy_jobs WHERE case_id=?", (autopsy_case,)).fetchone()[0] == 0
