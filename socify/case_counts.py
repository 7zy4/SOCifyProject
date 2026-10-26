from contextlib import contextmanager
from functools import lru_cache, wraps
from pathlib import Path

from flask import current_app, g

from .autopsy_pipeline import case_full_access
from .db import get_db
from .operational import operational_mode


@contextmanager
def read_snapshot():
    connection = get_db()
    owned = not connection.in_transaction
    previous = getattr(g, "case_count_read_snapshot", False)
    if owned:
        connection.execute("BEGIN")
        g.case_count_read_snapshot = True
    try:
        yield
    finally:
        if owned:
            connection.rollback()
            g.case_count_read_snapshot = previous


def consistent_read(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with read_snapshot():
            return function(*args, **kwargs)

    return wrapped


@lru_cache(maxsize=512)
def count_for_revision(namespace, database, case_id, version, job_id, active_only):
    clauses, args = ["case_id=?"], [case_id]
    if job_id is not None:
        clauses.append("import_job_id=?")
        args.append(job_id)
    if active_only:
        clauses.append("active_event=1")
    return get_db().execute("SELECT COUNT(*) FROM case_events WHERE " + " AND ".join(clauses), args).fetchone()[0]


def cached_case_count(case_id, *, job_id=None, active_only=True):
    if not operational_mode() or not getattr(g, "case_count_read_snapshot", False) or not case_full_access(case_id):
        return None
    case = get_db().execute("SELECT c.version FROM incident_cases c JOIN autopsy_case_context x ON x.case_id=c.id WHERE c.id=?", (case_id,)).fetchone()
    if case is None:
        return None
    namespace = current_app.extensions.setdefault("case_counts_namespace", object())
    database = str(Path(current_app.config["DATABASE"]).resolve())
    return count_for_revision(namespace, database, case_id, case["version"], job_id, active_only)
