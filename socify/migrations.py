"""Numbered schema migrations. SQLite's ``user_version`` records the last one applied to a database.

Adding a migration:
- Append ``(number, description, function)`` with the next number. Never renumber, reorder or edit a step that
  has shipped; correct it with a new step.
- Every step runs inside the start-up write transaction (``BEGIN IMMEDIATE`` in ``socify.schema.ensure_schema``),
  so a failure leaves neither a partial schema nor an advanced ``user_version``, and concurrent processes wait
  for the first one instead of migrating twice.
- Step 1 is the baseline: the idempotent set-up of the whole schema. It also
  reconciles data on each start (expired import leases, built-in rules for every workspace, column fills),
  so it keeps running on every start; later steps run once. A later step that drops or renames something the
  baseline creates must change the baseline in the same commit, or the next start would create it again.
"""

import sqlite3
from collections.abc import Callable

Step = Callable[[sqlite3.Connection], None]


class SchemaVersionError(RuntimeError):
    """The database was migrated by a newer release than the running code."""


def _baseline(connection: sqlite3.Connection) -> None:
    from .schema import baseline_schema

    baseline_schema(connection)


MIGRATIONS: list[tuple[int, str, Step]] = [
    (1, "Baseline schema and start-up reconciliation", _baseline),
]


def schema_version(connection: sqlite3.Connection) -> int:
    return int(connection.execute("PRAGMA user_version").fetchone()[0])


def apply_migrations(connection: sqlite3.Connection) -> tuple[int, int]:
    """Bring the database to the newest version and return (version found, version now).

    The caller must already hold the write transaction.
    """
    found = schema_version(connection)
    newest = MIGRATIONS[-1][0]
    if found > newest:
        raise SchemaVersionError(
            f"Database schema version {found} is newer than this SOCify release supports ({newest}). "
            "A newer release has upgraded this database: run that release again, or restore the backup taken before the upgrade."
        )
    for number, _description, step in MIGRATIONS:
        if number == 1 or number > found:
            step(connection)
        if number > found:
            connection.execute(f"PRAGMA user_version = {int(number)}")
    return found, newest
