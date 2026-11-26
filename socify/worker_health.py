"""Worker heartbeats, so a stuck worker can be told apart from an idle one.

Each long-running worker records a heartbeat when it starts, after each job, and at least every HEARTBEAT_SECONDS
while it waits for work. A worker in the middle of a long job holds a live lease on that job instead, so the health
check accepts either a recent heartbeat or a job the worker is still leasing.
"""

import os
import socket
import sqlite3
import time

from .timeutils import iso_now, parse_timestamp, utc_now
from .version import VERSION

HEARTBEAT_SECONDS = 30
WORKER_NAMES = ("import-worker", "autopsy-worker", "backup", "egress")

# The job tables a worker leases, keyed by worker name: (table, state column).
LEASED_JOBS = {"import-worker": ("ingestion_jobs", "status"), "autopsy-worker": ("autopsy_jobs", "state")}


def _busy(error: sqlite3.Error) -> bool:
    # Same test as socify.db.database_is_busy, kept here so health checks import no Flask code.
    return getattr(error, "sqlite_errorcode", 0) & 0xFF in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}


def worker_instance() -> str:
    return f"{socket.gethostname()}-{os.getpid()}"


def record_heartbeat(connection: sqlite3.Connection, name: str, instance: str, started_at: str, state: str) -> bool:
    """Upsert the worker's row; a busy database skips this beat instead of stopping the worker. Returns whether it was written."""
    if name not in WORKER_NAMES:
        raise ValueError("unknown worker name")
    try:
        connection.execute(
            """INSERT INTO worker_heartbeats (name, instance, pid, version, started_at, last_beat_at, state) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET instance = excluded.instance, pid = excluded.pid, version = excluded.version,
            started_at = excluded.started_at, last_beat_at = excluded.last_beat_at, state = excluded.state""",
            (name, instance, os.getpid(), VERSION, started_at, iso_now(), state),
        )
    except sqlite3.OperationalError as error:
        if not _busy(error):
            raise
        return False
    return True


class Heartbeat:
    """A worker's heartbeat: written at once when forced or when the state changes, otherwise at most once per interval."""

    def __init__(self, name: str, instance: str | None = None, interval: float = HEARTBEAT_SECONDS) -> None:
        self.name = name
        self.instance = instance or worker_instance()
        self.interval = interval
        self.started_at = iso_now()
        self._last: float | None = None
        self._state: str | None = None

    def beat(self, connection: sqlite3.Connection, state: str = "idle", *, force: bool = False) -> None:
        moment = time.monotonic()
        if not force and state == self._state and self._last is not None and moment - self._last < self.interval:
            return
        if record_heartbeat(connection, self.name, self.instance, self.started_at, state):
            self._last, self._state = moment, state


def heartbeat_ages(connection: sqlite3.Connection) -> dict[str, float]:
    """Seconds since each known worker's last heartbeat; workers that never reported are left out."""
    now = utc_now()
    ages: dict[str, float] = {}
    for row in connection.execute("SELECT name, last_beat_at FROM worker_heartbeats").fetchall():
        if row[0] in WORKER_NAMES:
            ages[row[0]] = max((now - parse_timestamp(row[1])).total_seconds(), 0.0)
    return ages


def worker_healthy(connection: sqlite3.Connection, name: str, max_age: float) -> bool:
    """A recent heartbeat, or a job the reporting worker still holds an unexpired lease on."""
    row = connection.execute("SELECT instance, last_beat_at FROM worker_heartbeats WHERE name = ?", (name,)).fetchone()
    if row is None:
        return False
    if (utc_now() - parse_timestamp(row[1])).total_seconds() <= max_age:
        return True
    leased = LEASED_JOBS.get(name)
    if leased is None:
        return False
    table, state = leased  # fixed names from LEASED_JOBS, never request input
    busy = connection.execute(
        f"SELECT 1 FROM {table} WHERE {state} = 'processing' AND worker_id = ? AND lease_expires_at > ? LIMIT 1", (row[0], iso_now())
    ).fetchone()
    return busy is not None
