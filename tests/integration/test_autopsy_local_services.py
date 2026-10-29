import time

from scripts.environment import load_environment
from scripts.local_services import local_worker_services
from tests.integration.test_playbook_worker import _queued_run


def test_local_worker_process_shares_case_database_and_encryption_keys(autopsy_case, app, client):
    created = client.post(
        f"/api/cases/{autopsy_case}/imports?defer=1", json={"filename": "background.jsonl", "content": '{"title":"Separate process evidence"}\n'}
    )
    assert created.status_code == 202
    with local_worker_services(app.config) as processes:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            status = client.get(f"/api/cases/{autopsy_case}/imports/{created.json['id']}").json
            if status["status"] in {"completed", "completed_with_errors", "failed"}:
                break
            time.sleep(0.05)
        assert status["status"] == "completed", status
        assert status["accepted"] == 1
        assert client.get(f"/api/cases/{autopsy_case}/logs").json["items"][0]["title"] == "Separate process evidence"
    assert all(not process.is_alive() for process in processes)


def test_environment_loader_preserves_existing_root_database_and_saved_keys(monkeypatch, tmp_path):
    for key in ("SOCIFY_ENV", "SOCIFY_DATABASE", "SOCIFY_SECRET_KEY", "SOCIFY_CREDENTIAL_KEY"):
        monkeypatch.delenv(key, raising=False)
    database = tmp_path / "socify.db"
    database.write_bytes(b"Existing database marker")
    load_environment(tmp_path)
    import os

    assert os.environ["SOCIFY_DATABASE"] == str(database)
    saved = (tmp_path / "instance" / "codespaces.env").read_bytes()
    load_environment(tmp_path)
    assert (tmp_path / "instance" / "codespaces.env").read_bytes() == saved
    assert database.read_bytes() == b"Existing database marker"


def test_local_supervisor_processes_pending_playbooks_without_duplicate_effects(app, client, login_as, database):
    login_as("admin")
    identifier = _queued_run(client, app, [{"action": "notify_training_team"}], "local-supervised-playbook")
    with local_worker_services(app.config) as processes:
        assert {process.name for process in processes} == {"socify-local-import", "socify-local-autopsy", "socify-local-playbook"}
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            run = client.get(f"/api/playbook-runs/{identifier}").json
            if run["state"] in {"succeeded", "failed"}:
                break
            time.sleep(0.05)
        assert run["state"] == "succeeded", run
        assert run["steps"][0]["attempt"] == 1
    assert all(not process.is_alive() for process in processes)
    assert database.execute("SELECT COUNT(*) FROM outbox_events WHERE event_type='training.notification'").fetchone()[0] == 1
