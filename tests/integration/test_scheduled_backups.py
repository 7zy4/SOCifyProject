"""The backup scheduler takes verified backups, encrypts them when configured, keeps N files and survives failures."""

import dataclasses
import json
import os
import sqlite3
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from scripts import backup_scheduler
from socify.config import BackupSettings, backup_settings
from socify.db import connect_path
from socify.timeutils import utc_now

KEY = "b" * 40
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def settings(app, tmp_path):
    return BackupSettings(database=app.config["DATABASE"], directory=str(tmp_path / "backups"), interval_hours=24.0, keep=3, key=None)


@pytest.fixture
def connection(settings):
    opened = connect_path(settings.database)
    yield opened
    opened.close()


def _files(settings):
    return sorted(entry.name for entry in Path(settings.directory).iterdir())


def test_a_run_writes_a_verified_named_backup_and_records_it(settings, connection):
    assert backup_scheduler.run_once(connection, settings)
    names = _files(settings)
    assert len(names) == 1 and backup_scheduler.BACKUP_NAME.fullmatch(names[0]) and names[0].endswith(".db")
    restored = sqlite3.connect(Path(settings.directory) / names[0])
    assert restored.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert restored.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0
    restored.close()
    run = connection.execute("SELECT status, file_name, size_bytes, sha256, encrypted, error FROM backup_runs").fetchone()
    assert run["status"] == "succeeded" and run["file_name"] == names[0] and run["size_bytes"] > 0 and len(run["sha256"]) == 64
    assert run["encrypted"] == 0 and run["error"] is None


def test_an_encrypted_backup_restores_with_the_backup_key_only(settings, connection, tmp_path, monkeypatch):
    encrypted = dataclasses.replace(settings, key=KEY)
    assert backup_scheduler.run_once(connection, encrypted)
    [name] = _files(settings)
    assert name.endswith(".db.enc") and not (Path(settings.directory) / name).read_bytes().startswith(b"SQLite format 3")
    destination = tmp_path / "restored" / "socify.db"
    command = [sys.executable, "-m", "scripts.restore", str(Path(settings.directory) / name), str(destination), "--confirm", "RESTORE", "--decrypt"]
    # The restore command line is fixed here and runs this repository's own script.
    refused = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, env={**os.environ, "SOCIFY_BACKUP_KEY": "w" * 40}, check=False)  # noqa: S603
    assert refused.returncode != 0 and not destination.exists()
    restored = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, env={**os.environ, "SOCIFY_BACKUP_KEY": KEY}, check=False)  # noqa: S603
    assert restored.returncode == 0, restored.stderr
    assert json.loads(restored.stdout)["integrity"] == "ok"
    check = sqlite3.connect(destination)
    assert check.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0
    check.close()
    assert sorted(entry.name for entry in destination.parent.iterdir()) == ["socify.db"]


def test_retention_keeps_the_newest_backups_and_leaves_other_files(settings, connection):
    directory = Path(settings.directory)
    directory.mkdir(parents=True)
    for day in range(1, 6):
        (directory / f"socify-202601{day:02d}T000000Z.db").write_bytes(b"old")
    (directory / "operator-notes.txt").write_text("keep me", encoding="utf-8")
    assert backup_scheduler.run_once(connection, settings)
    names = _files(settings)
    assert "operator-notes.txt" in names
    kept = [name for name in names if name.startswith("socify-")]
    assert len(kept) == 3 and "socify-20260105T000000Z.db" in kept and "socify-20260101T000000Z.db" not in kept


def test_a_failed_run_is_recorded_and_the_scheduler_carries_on(settings, connection, monkeypatch):
    broken = dataclasses.replace(settings, database=str(Path(settings.directory) / "missing.db"))
    assert backup_scheduler.run_once(connection, broken) is False
    failed = connection.execute("SELECT status, error, file_name FROM backup_runs").fetchone()
    assert failed["status"] == "failed" and failed["error"] == "ValueError" and failed["file_name"] is None
    assert not list(Path(settings.directory).glob(".*partial"))
    assert backup_scheduler.run_once(connection, settings)


def test_the_schedule_waits_for_the_interval_after_a_success(settings, connection):
    assert backup_scheduler.seconds_until_due(connection, 24) == 0
    backup_scheduler.run_once(connection, settings)
    assert 23 * 3600 < backup_scheduler.seconds_until_due(connection, 24) <= 24 * 3600
    stale = (utc_now() - timedelta(hours=25)).isoformat().replace("+00:00", "Z")
    connection.execute("UPDATE backup_runs SET finished_at = ?", (stale,))
    assert backup_scheduler.seconds_until_due(connection, 24) == 0


def test_serve_beats_and_runs_once(settings, connection):
    backup_scheduler.serve(settings, once=True, sleep=lambda _seconds: None)
    beat = connection.execute("SELECT state FROM worker_heartbeats WHERE name = 'backup'").fetchone()
    assert beat["state"] == "idle" and len(_files(settings)) == 1


def test_metrics_report_the_age_of_the_last_successful_backup(app, client, settings, connection):
    app.config.update(METRICS_TOKEN="m" * 32)
    headers = {"Authorization": "Bearer " + "m" * 32}
    assert "socify_backup_last_success_age_seconds" not in client.get("/health/metrics", headers=headers).get_data(as_text=True)
    backup_scheduler.run_once(connection, settings)
    metrics = client.get("/health/metrics", headers=headers).get_data(as_text=True)
    line = next(line for line in metrics.splitlines() if line.startswith("socify_backup_last_success_age_seconds "))
    assert float(line.split()[1]) < 60


@pytest.mark.parametrize(
    ("variables", "message"),
    [
        ({"SOCIFY_BACKUP_INTERVAL_HOURS": "0"}, "SOCIFY_BACKUP_INTERVAL_HOURS"),
        ({"SOCIFY_BACKUP_INTERVAL_HOURS": "800"}, "SOCIFY_BACKUP_INTERVAL_HOURS"),
        ({"SOCIFY_BACKUP_KEEP": "0"}, "SOCIFY_BACKUP_KEEP"),
        ({"SOCIFY_BACKUP_KEY": "short"}, "SOCIFY_BACKUP_KEY"),
    ],
)
def test_backup_settings_are_validated(monkeypatch, variables, message):
    monkeypatch.setenv("SOCIFY_DATABASE", "/data/socify.db")
    for name, value in variables.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(RuntimeError, match=message):
        backup_settings()


def test_backup_settings_defaults(monkeypatch):
    for name in ("SOCIFY_BACKUP_INTERVAL_HOURS", "SOCIFY_BACKUP_KEEP", "SOCIFY_BACKUP_KEY", "SOCIFY_BACKUP_DIR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SOCIFY_DATABASE", "/data/socify.db")
    assert backup_settings() == BackupSettings(database="/data/socify.db", directory="/backups", interval_hours=24.0, keep=14, key=None)
