import logging
import sqlite3
import time
import uuid
from datetime import timedelta

from .db import database_is_busy, transaction
from .ingestion import _process_job
from .timeutils import iso_now, utc_now

# One line per finished job: identifiers, counts, state and timing only. File names, record content and
# exception messages never enter the log; the job row keeps the reviewable detail.
log = logging.getLogger("socify.workers")


def _future(seconds: int) -> str:
    return (utc_now() + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def claim_import_job(connection: sqlite3.Connection, worker_id: str, lease_seconds: int = 60) -> int | None:
    try:
        return claim_import_job_locked(connection, worker_id, lease_seconds)
    except sqlite3.OperationalError as exc:
        if not database_is_busy(exc):
            raise
        return None


def claim_import_job_locked(connection: sqlite3.Connection, worker_id: str, lease_seconds: int) -> int | None:
    now = iso_now()
    with transaction(connection, wait=False):
        expired = connection.execute(
            "SELECT id, retry_count FROM ingestion_jobs WHERE status = 'processing' AND (lease_expires_at IS NULL OR lease_expires_at <= ?)",
            (now,),
        ).fetchall()
        for row in expired:
            retries = int(row["retry_count"]) + 1
            if retries > 3:
                connection.execute(
                    """UPDATE ingestion_jobs SET status = 'failed', retry_count = ?, worker_id = NULL,
                    lease_expires_at = NULL, last_error = 'worker lease repeatedly expired', updated_at = ? WHERE id = ?""",
                    (retries, now, row["id"]),
                )
            else:
                connection.execute(
                    """UPDATE ingestion_jobs SET status = 'interrupted', retry_count = ?, worker_id = NULL,
                    lease_expires_at = NULL, available_at = ?, last_error = 'worker lease expired before completion', updated_at = ? WHERE id = ?""",
                    (retries, _future(min(60, 2 ** (retries - 1))), now, row["id"]),
                )
        row = connection.execute(
            """SELECT id FROM ingestion_jobs WHERE status IN ('queued', 'interrupted')
            AND COALESCE(available_at, created_at) <= ? ORDER BY COALESCE(available_at, created_at), id LIMIT 1""",
            (now,),
        ).fetchone()
        if not row:
            return None
        updated = connection.execute(
            """UPDATE ingestion_jobs SET status = 'processing', worker_id = ?, lease_expires_at = ?,
            started_at = COALESCE(started_at, ?), last_error = NULL, updated_at = ?
            WHERE id = ? AND status IN ('queued', 'interrupted')""",
            (worker_id, _future(lease_seconds), now, now, row["id"]),
        )
        return int(row["id"]) if updated.rowcount == 1 else None


def run_import_worker_once(connection: sqlite3.Connection, worker_id: str | None = None, lease_seconds: int = 60) -> int | None:
    identity = worker_id or f"import-worker-{uuid.uuid4().hex}"
    job_id = claim_import_job(connection, identity, lease_seconds)
    if job_id is None:
        return None
    started = time.perf_counter()
    try:
        job = _process_job(job_id, identity, lease_seconds)
    except Exception as exc:
        status, retries = "missing", None
        with transaction(connection):
            row = connection.execute("SELECT retry_count FROM ingestion_jobs WHERE id = ?", (job_id,)).fetchone()
            if row:
                retries = int(row["retry_count"]) + 1
                status = "failed" if retries > 3 else "interrupted"
                connection.execute(
                    """UPDATE ingestion_jobs SET status = ?, retry_count = ?, available_at = ?, worker_id = NULL,
                    lease_expires_at = NULL, last_error = ?, updated_at = ? WHERE id = ?""",
                    (status, retries, _future(min(60, 2 ** max(0, retries - 1))), type(exc).__name__, iso_now(), job_id),
                )
        log.warning(
            "import_job_failed job_id=%s state=%s attempt=%s error_type=%s duration_ms=%.1f",
            job_id,
            status,
            retries,
            type(exc).__name__,
            (time.perf_counter() - started) * 1000,
        )
        if not isinstance(exc, (RuntimeError, sqlite3.Error)):
            raise
        return job_id
    log.info(
        "import_job_finished job_id=%s case_id=%s state=%s accepted=%s rejected=%s duration_ms=%.1f",
        job_id,
        job["case_id"],
        job["status"],
        job["accepted"],
        job["rejected"],
        (time.perf_counter() - started) * 1000,
    )
    return job_id
