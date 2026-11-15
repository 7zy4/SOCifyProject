"""Numbered migrations: versioning, refusal of newer databases, atomic failure and concurrent start-up."""

import gzip
import multiprocessing
import sqlite3
from pathlib import Path

import pytest

from socify import create_app, migrations
from socify.db import connect_path
from socify.migrations import MIGRATIONS, SchemaVersionError, schema_version
from socify.schema import ensure_schema

FIXTURE = Path(__file__).parents[1] / "fixtures" / "v2" / "synthetic-v2.db.gz"
NEWEST = MIGRATIONS[-1][0]


def _objects(path):
    connection = sqlite3.connect(path)
    try:
        return sorted(connection.execute("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall())
    finally:
        connection.close()


def _columns(path):
    connection = sqlite3.connect(path)
    try:
        tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")]
        return {table: sorted((row[1], row[2], row[3], row[4], row[5]) for row in connection.execute(f"PRAGMA table_info({table})")) for table in tables}
    finally:
        connection.close()


def _migrate(path):
    connection = connect_path(str(path), True)
    try:
        ensure_schema(connection)
        return schema_version(connection)
    finally:
        connection.close()


def test_steps_are_numbered_from_one_without_gaps():
    assert [number for number, _description, _step in MIGRATIONS] == list(range(1, len(MIGRATIONS) + 1))


def test_new_database_records_the_newest_version_and_reopening_changes_nothing(tmp_path):
    path = tmp_path / "fresh.db"
    assert _migrate(path) == NEWEST
    created = _objects(path)
    assert _migrate(path) == NEWEST and _migrate(path) == NEWEST
    assert _objects(path) == created


def test_database_from_before_numbering_is_upgraded_to_the_same_schema(tmp_path):
    fresh, unnumbered = tmp_path / "fresh.db", tmp_path / "unnumbered.db"
    _migrate(fresh)
    _migrate(unnumbered)
    connection = sqlite3.connect(unnumbered)
    connection.execute("PRAGMA user_version = 0")  # what every database created before this release contains
    connection.close()
    assert _migrate(unnumbered) == NEWEST
    assert _objects(unnumbered) == _objects(fresh)


def test_v2_fixture_upgrade_has_the_fresh_schema(tmp_path):
    fresh, upgraded = tmp_path / "fresh.db", tmp_path / "v2.db"
    _migrate(fresh)
    upgraded.write_bytes(gzip.decompress(FIXTURE.read_bytes()))
    assert _migrate(upgraded) == NEWEST
    # Columns added to an existing table by ALTER TABLE sit at its end, so compare definitions, not the CREATE text.
    assert _columns(upgraded) == _columns(fresh)
    indexes_and_triggers = [row for row in _objects(fresh) if row[0] in {"index", "trigger", "view"}]
    assert [row for row in _objects(upgraded) if row[0] in {"index", "trigger", "view"}] == indexes_and_triggers


def test_database_from_a_newer_release_is_refused(tmp_path):
    path = tmp_path / "newer.db"
    _migrate(path)
    before = _objects(path)
    connection = sqlite3.connect(path)
    connection.execute(f"PRAGMA user_version = {NEWEST + 1}")
    connection.close()
    with pytest.raises(SchemaVersionError, match=rf"version {NEWEST + 1} is newer than this SOCify release supports \({NEWEST}\)"):
        create_app({"DATABASE": str(path), "TESTING": True, "SECRET_KEY": "s", "CREDENTIAL_KEY": "c"})
    assert _objects(path) == before
    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == NEWEST + 1
    connection.close()


@pytest.mark.parametrize("start", ["new", "current"])
def test_failed_step_leaves_no_partial_schema_and_no_version_change(tmp_path, monkeypatch, start):
    path = tmp_path / "failing.db"
    if start == "current":
        _migrate(path)
    before_objects = _objects(path) if path.exists() else []
    before_version = NEWEST if start == "current" else 0

    def failing_step(connection):
        connection.execute("CREATE TABLE half_applied (id INTEGER)")
        connection.execute("INSERT INTO half_applied VALUES (1)")
        raise RuntimeError("step failed after changing the schema")

    monkeypatch.setattr(migrations, "MIGRATIONS", [*MIGRATIONS, (NEWEST + 1, "Failing step", failing_step)])
    with pytest.raises(RuntimeError, match="step failed after changing the schema"):
        _migrate(path)
    assert _objects(path) == before_objects
    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == before_version
    connection.close()
    monkeypatch.setattr(migrations, "MIGRATIONS", MIGRATIONS)
    assert _migrate(path) == NEWEST


def _start(path, barrier, results):
    barrier.wait(timeout=60)
    try:
        create_app({"DATABASE": path, "TESTING": False, "SECRET_KEY": "s" * 32, "CREDENTIAL_KEY": "c" * 32})
        results.put("ok")
    except Exception as error:  # reported to the parent test
        results.put(f"{type(error).__name__}: {error}")


@pytest.mark.parametrize("existing", [False, True], ids=["empty", "existing"])
def test_five_processes_starting_together_agree_on_one_schema(tmp_path, existing):
    path = tmp_path / "shared.db"
    reference = tmp_path / "reference.db"
    _migrate(reference)
    if existing:
        _migrate(path)
    context = multiprocessing.get_context("spawn")
    barrier, results = context.Barrier(5), context.Queue()
    processes = [context.Process(target=_start, args=(str(path), barrier, results)) for _ in range(5)]
    for process in processes:
        process.start()
    outcomes = [results.get(timeout=120) for _ in processes]
    for process in processes:
        process.join(timeout=30)
    assert outcomes == ["ok"] * 5, outcomes
    assert all(process.exitcode == 0 for process in processes)
    assert _objects(path) == _objects(reference)
    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == NEWEST
    assert connection.execute("SELECT COUNT(*) FROM training_workspaces").fetchone()[0] == 1
    connection.close()
