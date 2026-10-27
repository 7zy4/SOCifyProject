import io
import json
import sqlite3
from types import SimpleNamespace

import pytest

from scripts import start_v4_demo
from scripts.prepare_v4_demo import TEAM, provision


def old_incomplete(directory):
    directory.mkdir()
    emails = [f"{handle}@demo.socify.test" for handle, _name, _role in TEAM]
    (directory / "accounts.json").write_text(json.dumps([{"email": email} for email in emails]))
    (directory / "runtime.env").write_text("Synthetic retained keys")
    with sqlite3.connect(directory / "socify.db") as database:
        database.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT)")
        database.execute("CREATE TABLE demo_accounts(user_id INTEGER)")
        for index, email in enumerate(emails, 1):
            database.execute("INSERT INTO users VALUES (?,?)", (index, email))
            database.execute("INSERT INTO demo_accounts VALUES (?)", (index,))


def test_failed_legacy_demo_is_preserved_before_atomic_replacement(tmp_path, monkeypatch):
    directory = tmp_path / "demo"
    old_incomplete(directory)
    previous = (directory / "socify.db").read_bytes()

    def ready(staging):
        staging.mkdir()
        (staging / "manifest.json").write_text('{"synthetic":true}')

    monkeypatch.setattr(start_v4_demo, "provision", ready)
    start_v4_demo.prepare(directory)
    backups = list(tmp_path.glob("demo.incomplete-*"))
    assert len(backups) == 1
    assert (backups[0] / "socify.db").read_bytes() == previous
    assert (backups[0] / "runtime.env").read_text() == "Synthetic retained keys"
    assert json.loads((directory / "manifest.json").read_text())["synthetic"]


def test_failed_new_provision_never_publishes_a_ready_directory(tmp_path, monkeypatch):
    directory = tmp_path / "demo"

    def interrupted(staging):
        staging.mkdir()
        (staging / "retained-diagnostic").write_text("Synthetic partial state")
        raise RuntimeError("Synthetic backend outage")

    monkeypatch.setattr(start_v4_demo, "provision", interrupted)
    with pytest.raises(RuntimeError, match="backend outage"):
        start_v4_demo.prepare(directory)
    assert not directory.exists()
    assert len(list(tmp_path.glob(".demo.preparing-*/retained-diagnostic"))) == 1


def test_existing_non_demo_directory_is_preserved(tmp_path):
    directory = tmp_path / "demo"
    directory.mkdir()
    (directory / "evidence").write_text("Retained company evidence")
    with pytest.raises(RuntimeError, match="preserved"):
        start_v4_demo.prepare(directory)
    assert (directory / "evidence").read_text() == "Retained company evidence"
    assert list(tmp_path.iterdir()) == [directory]


def test_real_demo_credentials_ignore_global_database_and_survive_restart(tmp_path, monkeypatch):
    directory = tmp_path / "demo"
    provision(directory)
    accounts_before = (directory / "accounts.json").read_bytes()
    keys_before = (directory / "runtime.env").read_bytes()
    monkeypatch.setenv("SOCIFY_DATABASE", str(tmp_path / "different-global.db"))
    start_v4_demo.verify_accounts(directory)
    start_v4_demo.prepare(directory)
    start_v4_demo.verify_accounts(directory)
    assert (directory / "accounts.json").read_bytes() == accounts_before
    assert (directory / "runtime.env").read_bytes() == keys_before
    assert not (tmp_path / "different-global.db").exists()


@pytest.mark.parametrize("corrupt", [True, False])
def test_only_snapshot_corruption_triggers_an_independent_builder(monkeypatch, corrupt):
    class Build:
        stdout = io.StringIO("parent snapshot missing does not exist\n" if corrupt else "registry unavailable\n")

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def wait(self):
            return 1

    calls = []
    monkeypatch.setattr(start_v4_demo.subprocess, "Popen", lambda *_args, **_kwargs: Build())
    monkeypatch.setattr(start_v4_demo.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(returncode=1))
    monkeypatch.setattr(start_v4_demo, "command", lambda arguments, **_kwargs: calls.append(arguments))
    if corrupt:
        start_v4_demo.build_analysis("synthetic-fingerprint")
        assert calls[0][:3] == ["docker", "buildx", "create"]
        assert calls[1][:3] == ["docker", "buildx", "build"]
        assert "--load" in calls[1]
    else:
        with pytest.raises(RuntimeError, match="image build failed"):
            start_v4_demo.build_analysis("synthetic-fingerprint")
        assert calls == []
