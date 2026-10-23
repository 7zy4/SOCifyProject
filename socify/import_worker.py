import sqlite3
import uuid
from datetime import timedelta

from .db import transaction
from .ingestion import _process_job
from .timeutils import iso_now, utc_now


def _future(seconds: int) -> str:
    return (utc_now() + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def claim_import_job(connection: sqlite3.Connection, worker_id: str, lease_seconds: int = 60) -> int | None:
    now = iso_now()
    with transaction(connection):
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
    try:
        _process_job(job_id, identity, lease_seconds)
    except Exception as exc:
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
        if not isinstance(exc, (RuntimeError, sqlite3.Error)):
            raise
    return job_id
