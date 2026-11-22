import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from flask import current_app, g

from .case_titles import localized_case_title
from .task_titles import task_title
from .user_names import localized_name


def connect_path(path: str, testing: bool = False) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=15, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.create_function("socify_user_name", 3, localized_name)
    connection.create_function("socify_task_title", 2, task_title)
    connection.create_function("socify_case_title", 2, localized_case_title)
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
    connection.create_function("socify_user_name", 3, localized_name)
    connection.create_function("socify_task_title", 2, task_title)
    connection.create_function("socify_case_title", 2, localized_case_title)
    connection.execute("PRAGMA query_only = ON")
    connection.execute("PRAGMA busy_timeout = 15000")
    return connection


def get_db() -> sqlite3.Connection:
    """The request's database connection, opened on first use and closed when the application context ends."""
    if "db" not in g:
        g.db = connect_path(str(current_app.config["DATABASE"]), bool(current_app.config.get("TESTING")))
    return g.db


def close_db(_: object | None = None) -> None:
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def database_is_busy(error: sqlite3.Error) -> bool:
    """True when the error means another connection holds the database (SQLITE_BUSY or SQLITE_LOCKED)."""
    return getattr(error, "sqlite_errorcode", 0) & 0xFF in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}


@contextmanager
def transaction(connection: sqlite3.Connection | None = None, *, immediate: bool = True, wait: bool = True) -> Iterator[sqlite3.Connection]:
    """Run the block in one SQLite transaction (BEGIN IMMEDIATE unless immediate=False), committing on success and rolling back on any exception; wait=False fails at once instead of waiting for a busy database."""
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


def inserted_id(cursor: sqlite3.Cursor) -> int:
    """The row id an INSERT produced; raises if SQLite returned none."""
    value = cursor.lastrowid
    if value is None:
        raise RuntimeError("database insert did not return an identifier")
    return int(value)
