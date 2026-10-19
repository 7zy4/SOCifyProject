import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from flask import current_app, g


def connect_path(path: str, testing: bool = False) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    if not testing:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
    return connection


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect_path(str(current_app.config["DATABASE"]), bool(current_app.config.get("TESTING")))
    return g.db


def close_db(_: object | None = None) -> None:
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


@contextmanager
def transaction(connection: sqlite3.Connection | None = None) -> Iterator[sqlite3.Connection]:
    target = connection or get_db()
    target.execute("BEGIN IMMEDIATE")
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
