import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from flask import current_app, g


def connect_path(path: str, testing: bool = False) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=15, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 15000")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = NORMAL")
    connection.execute("PRAGMA temp_store = MEMORY")
    connection.execute("PRAGMA mmap_size = 67108864")
    return connection


def connect_readonly(path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    connection.execute("PRAGMA busy_timeout = 15000")
    return connection


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect_path(str(current_app.config["DATABASE"]), bool(current_app.config.get("TESTING")))
    return g.db


def close_db(_: object | None = None) -> None:
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def database_is_busy(error: sqlite3.Error) -> bool:
    return getattr(error, "sqlite_errorcode", 0) & 0xFF in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}


@contextmanager
def transaction(connection: sqlite3.Connection | None = None, *, immediate: bool = True, wait: bool = True) -> Iterator[sqlite3.Connection]:
    target = connection or get_db()
    timeout = target.execute("PRAGMA busy_timeout").fetchone()[0] if not wait else None
    try:
        if timeout is not None:
            target.execute("PRAGMA busy_timeout = 0")
        target.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    finally:
        if timeout is not None:
            target.execute(f"PRAGMA busy_timeout = {int(timeout)}")
    try:
        yield target
        target.commit()
    except Exception:
        target.rollback()
        raise


def fetch_one(query: str, parameters: tuple[object, ...] = ()) -> sqlite3.Row | None:
    return get_db().execute(query, parameters).fetchone()


def fetch_all(query: str, parameters: tuple[object, ...] = ()) -> list[sqlite3.Row]:
    return get_db().execute(query, parameters).fetchall()


def inserted_id(cursor: sqlite3.Cursor) -> int:
    value = cursor.lastrowid
    if value is None:
        raise RuntimeError("database insert did not return an identifier")
    return int(value)
