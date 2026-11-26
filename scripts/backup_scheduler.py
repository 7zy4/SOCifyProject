"""Scheduled online backups of the SOCify database.

Every SOCIFY_BACKUP_INTERVAL_HOURS the scheduler takes an online backup with its integrity check, names it
socify-YYYYMMDDTHHMMSSZ.db (or .db.enc when SOCIFY_BACKUP_KEY is set), keeps the newest SOCIFY_BACKUP_KEEP files,
and records each run in backup_runs. It writes a worker heartbeat while it waits, so the container health check and
/health/metrics can tell when it stops. A failed run is recorded and retried at the next interval; it never stops
the scheduler. The service needs no credential key and no network.
"""

import argparse
import hashlib
import logging
import re
import sqlite3
import time
from datetime import timedelta
from pathlib import Path

from socify.backup_crypto import encrypt_file
from socify.config import BackupSettings, backup_settings
from socify.db import connect_path
from socify.operations import backup_database
from socify.timeutils import iso_now, parse_timestamp, utc_now
from socify.worker_health import Heartbeat

BACKUP_NAME = re.compile(r"socify-\d{8}T\d{6}Z\.db(?:\.enc)?")
RUN_HISTORY = 200
log = logging.getLogger("socify.backup")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def prune_backups(directory: Path, keep: int) -> list[str]:
    """Delete all but the newest `keep` finished backups; other files in the directory are never touched."""
    finished = sorted((entry for entry in directory.iterdir() if entry.is_file() and BACKUP_NAME.fullmatch(entry.name)), key=lambda entry: entry.name)
    removed = finished[:-keep] if keep > 0 else []
    for entry in removed:
        entry.unlink()
    return [entry.name for entry in removed]


def run_backup(database: str, directory: Path, keep: int, key: str | None) -> dict[str, object]:
    """Take one verified backup, encrypt it when a key is configured, and apply retention."""
    directory.mkdir(parents=True, exist_ok=True)
    # A run that was killed mid-way leaves its unencrypted staging copy; never let it outlive the next run.
    for leftover in directory.glob(".socify-*.partial*"):
        leftover.unlink(missing_ok=True)
    for leftover in directory.glob("socify-*.enc.partial"):
        leftover.unlink(missing_ok=True)
    name = f"socify-{utc_now().strftime('%Y%m%dT%H%M%SZ')}.db"
    staged = directory / f".{name}.partial"
    try:
        verification = backup_database(database, str(staged))
        if key:
            target = directory / f"{name}.enc"
            encrypt_file(staged, target, key)
        else:
            target = directory / name
            staged.replace(target)
    finally:
        staged.unlink(missing_ok=True)
    removed = prune_backups(directory, keep)
    return {
        "file_name": target.name,
        "size": target.stat().st_size,
        "sha256": _sha256(target),
        "encrypted": bool(key),
        "integrity": verification["integrity"],
        "removed": removed,
    }


def record_run(connection: sqlite3.Connection, started_at: str, status: str, details: dict[str, object] | None = None, error: str | None = None) -> None:
    details = details or {}
    connection.execute(
        "INSERT INTO backup_runs (started_at, finished_at, status, file_name, size_bytes, sha256, encrypted, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (started_at, iso_now(), status, details.get("file_name"), details.get("size"), details.get("sha256"), 1 if details.get("encrypted") else 0, error),
    )
    connection.execute("DELETE FROM backup_runs WHERE id NOT IN (SELECT id FROM backup_runs ORDER BY id DESC LIMIT ?)", (RUN_HISTORY,))


def last_success(connection: sqlite3.Connection) -> str | None:
    row = connection.execute("SELECT MAX(finished_at) FROM backup_runs WHERE status = 'succeeded'").fetchone()
    return row[0] if row and row[0] else None


def run_once(connection: sqlite3.Connection, settings: BackupSettings) -> bool:
    """One scheduled run; the outcome is recorded either way and a failure is reported by type, never raised."""
    started = iso_now()
    try:
        details = run_backup(settings.database, Path(settings.directory), settings.keep, settings.key)
    except (OSError, sqlite3.Error, RuntimeError, ValueError) as error:
        log.error("backup_failed error_type=%s", type(error).__name__)
        record_run(connection, started, "failed", error=type(error).__name__)
        return False
    record_run(connection, started, "succeeded", details)
    log.info("backup_succeeded file=%s size=%s removed=%s", details["file_name"], details["size"], details["removed"])
    return True


def seconds_until_due(connection: sqlite3.Connection, interval_hours: float) -> float:
    latest = last_success(connection)
    if latest is None:
        return 0.0
    return max((parse_timestamp(latest) + timedelta(hours=interval_hours) - utc_now()).total_seconds(), 0.0)


def serve(settings: BackupSettings, once: bool = False, sleep=time.sleep) -> None:
    connection = connect_path(settings.database)
    heartbeat = Heartbeat("backup")
    try:
        heartbeat.beat(connection, "ready", force=True)
        while True:
            if seconds_until_due(connection, settings.interval_hours) <= 0:
                heartbeat.beat(connection, "active", force=True)
                succeeded = run_once(connection, settings)
                heartbeat.beat(connection, "idle" if succeeded else "failed", force=True)
                if once:
                    return
                # A failure waits a full interval before the next attempt, so a broken disk is not hammered.
                if not succeeded:
                    deadline = time.monotonic() + settings.interval_hours * 3600
                    while time.monotonic() < deadline:
                        heartbeat.beat(connection, "failed")
                        sleep(min(30.0, max(deadline - time.monotonic(), 0.0)))
                    continue
            heartbeat.beat(connection, "idle")
            sleep(min(30.0, max(seconds_until_due(connection, settings.interval_hours), 1.0)))
    finally:
        connection.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run scheduled SOCify database backups.")
    parser.add_argument("--once", action="store_true", help="take one backup now and exit")
    arguments = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = backup_settings()
    if arguments.once:
        connection = connect_path(settings.database)
        try:
            raise SystemExit(0 if run_once(connection, settings) else 1)
        finally:
            connection.close()
    serve(settings)


if __name__ == "__main__":
    main()
