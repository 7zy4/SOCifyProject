import json
import sqlite3
import time
import uuid
from datetime import timedelta

from .audit import record_audit, record_training_action
from .db import transaction
from .playbooks import _apply_action
from .schema import insert_outbox
from .timeutils import iso_now, utc_now


def _future(seconds: int) -> str:
    return (utc_now() + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def claim_playbook_run(connection: sqlite3.Connection, worker_id: str, lease_seconds: int = 60) -> int | None:
    now = iso_now()
    with transaction(connection):
        expired = connection.execute(
            "SELECT id FROM playbook_runs WHERE state = 'running' AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?",
            (now,),
        ).fetchall()
        for row in expired:
            connection.execute(
                "UPDATE playbook_step_runs SET status = 'pending', error = 'worker lease expired before completion' WHERE run_id = ? AND status = 'running'",
                (row["id"],),
            )
            connection.execute(
                "UPDATE playbook_runs SET state = 'pending', worker_id = NULL, lease_expires_at = NULL, available_at = ?, last_error = 'worker lease expired before completion', updated_at = ? WHERE id = ?",
                (now, now, row["id"]),
            )
        row = connection.execute(
            """SELECT id FROM playbook_runs
            WHERE state IN ('pending', 'approved', 'retry_wait') AND cancel_requested = 0
              AND COALESCE(available_at, created_at) <= ?
            ORDER BY COALESCE(available_at, created_at), id LIMIT 1""",
            (now,),
        ).fetchone()
        if not row:
            return None
        updated = connection.execute(
            """UPDATE playbook_runs SET state = 'running', worker_id = ?, lease_expires_at = ?,
            started_at = COALESCE(started_at, ?), updated_at = ?
            WHERE id = ? AND state IN ('pending', 'approved', 'retry_wait') AND cancel_requested = 0""",
            (worker_id, _future(lease_seconds), now, now, row["id"]),
        )
        return int(row["id"]) if updated.rowcount == 1 else None


def _finish_cancelled(connection: sqlite3.Connection, run: sqlite3.Row) -> str:
    now = iso_now()
    connection.execute(
        "UPDATE playbook_step_runs SET status = 'skipped', completed_at = ? WHERE run_id = ? AND status IN ('pending', 'running', 'retry_wait')",
        (now, run["id"]),
    )
    connection.execute(
        "UPDATE playbook_runs SET state = 'cancelled', worker_id = NULL, lease_expires_at = NULL, completed_at = ?, updated_at = ? WHERE id = ?",
        (now, now, run["id"]),
    )
    record_audit(
        connection,
        "cancel",
        "playbook_run",
        run["id"],
        actor=run["requested_by"],
        workspace=run["workspace_id"],
        details={"source": "worker"},
    )
    return "cancelled"


def _finish_run(connection: sqlite3.Connection, run: sqlite3.Row, state: str, error: str | None = None) -> str:
    now = iso_now()
    connection.execute(
        """UPDATE playbook_runs SET state = ?, worker_id = NULL, lease_expires_at = NULL,
        last_error = ?, completed_at = ?, updated_at = ? WHERE id = ?""",
        (state, error, now, now, run["id"]),
    )
    record_audit(
        connection,
        "execute",
        "playbook_run",
        run["id"],
        result="success" if state == "succeeded" else "failed",
        details={"state": state, "error": error},
        actor=run["requested_by"],
        workspace=run["workspace_id"],
    )
    record_training_action(
        connection,
        run["training_run_id"],
        run["requested_by"],
        "playbook_completed",
        "playbook_run",
        run["id"],
        {"state": state},
        f"playbook-complete:{run['id']}:{state}",
    )
    insert_outbox(connection, run["workspace_id"], "playbook_run.updated", {"id": run["id"], "state": state})
    return state


def process_playbook_run(connection: sqlite3.Connection, run_id: int, worker_id: str, lease_seconds: int = 60) -> str:
    run = connection.execute("SELECT * FROM playbook_runs WHERE id = ? AND state = 'running' AND worker_id = ?", (run_id, worker_id)).fetchone()
    if not run:
        raise ValueError("playbook run is not leased by this worker")
    steps = connection.execute(
        """SELECT psr.*, ps.position, ps.action_type, ps.retry_limit, ps.timeout_seconds
        FROM playbook_step_runs psr JOIN playbook_steps ps ON ps.id = psr.step_id
        WHERE psr.run_id = ? ORDER BY ps.position""",
        (run_id,),
    ).fetchall()
    for original_step in steps:
        if original_step["status"] in {"succeeded", "rolled_back", "skipped"}:
            continue
        with transaction(connection):
            run = connection.execute("SELECT * FROM playbook_runs WHERE id = ? AND worker_id = ?", (run_id, worker_id)).fetchone()
            if not run:
                raise ValueError("playbook worker lease was lost")
            if run["cancel_requested"]:
                return _finish_cancelled(connection, run)
            now = iso_now()
            connection.execute(
                "UPDATE playbook_runs SET lease_expires_at = ?, updated_at = ? WHERE id = ? AND worker_id = ?",
                (_future(max(lease_seconds, int(original_step["timeout_seconds"]) + 5)), now, run_id, worker_id),
            )
            connection.execute(
                """UPDATE playbook_step_runs SET status = 'running', attempt = attempt + 1,
                started_at = ?, completed_at = NULL, error = NULL, next_attempt_at = NULL WHERE id = ?""",
                (now, original_step["id"]),
            )
        with transaction(connection):
            run = connection.execute("SELECT * FROM playbook_runs WHERE id = ? AND worker_id = ?", (run_id, worker_id)).fetchone()
            step = connection.execute(
                """SELECT psr.*, ps.action_type, ps.retry_limit, ps.timeout_seconds
                FROM playbook_step_runs psr JOIN playbook_steps ps ON ps.id = psr.step_id WHERE psr.id = ?""",
                (original_step["id"],),
            ).fetchone()
            if not run or not step:
                raise ValueError("playbook run or step disappeared during execution")
            connection.execute("SAVEPOINT playbook_effect")
            started = time.monotonic()
            try:
                parameters = json.loads(step["input"])
                before, after = _apply_action(connection, run, step["action_type"], parameters)
                duration_ms = int((time.monotonic() - started) * 1000)
                if duration_ms > int(step["timeout_seconds"]) * 1000:
                    raise TimeoutError(f"step exceeded {step['timeout_seconds']} second timeout")
                output = {"before": before, "after": after, "simulated": True, "effect_key": step["effect_key"]}
                connection.execute("RELEASE SAVEPOINT playbook_effect")
                connection.execute(
                    """UPDATE playbook_step_runs SET status = 'succeeded', output = ?, impact = ?,
                    duration_ms = ?, completed_at = ? WHERE id = ?""",
                    (
                        json.dumps(output, ensure_ascii=False),
                        json.dumps(after, ensure_ascii=False),
                        duration_ms,
                        iso_now(),
                        step["id"],
                    ),
                )
            except (TimeoutError, ValueError, sqlite3.Error) as exc:
                duration_ms = int((time.monotonic() - started) * 1000)
                connection.execute("ROLLBACK TO SAVEPOINT playbook_effect")
                connection.execute("RELEASE SAVEPOINT playbook_effect")
                error = str(exc)[:500]
                if int(step["attempt"]) < int(step["retry_limit"]):
                    backoff = min(300, 2 ** max(0, int(step["attempt"]) - 1))
                    available_at = _future(backoff)
                    connection.execute(
                        """UPDATE playbook_step_runs SET status = 'retry_wait', error = ?, duration_ms = ?,
                        completed_at = ?, next_attempt_at = ? WHERE id = ?""",
                        (error, duration_ms, iso_now(), available_at, step["id"]),
                    )
                    connection.execute(
                        """UPDATE playbook_runs SET state = 'retry_wait', available_at = ?, worker_id = NULL,
                        lease_expires_at = NULL, last_error = ?, updated_at = ? WHERE id = ?""",
                        (available_at, error, iso_now(), run_id),
                    )
                    record_audit(
                        connection,
                        "retry_scheduled",
                        "playbook_run",
                        run_id,
                        result="failed",
                        details={"step_id": step["id"], "attempt": step["attempt"], "backoff_seconds": backoff, "error": error},
                        actor=run["requested_by"],
                        workspace=run["workspace_id"],
                    )
                    return "retry_wait"
                connection.execute(
                    "UPDATE playbook_step_runs SET status = 'failed', error = ?, duration_ms = ?, completed_at = ? WHERE id = ?",
                    (error, duration_ms, iso_now(), step["id"]),
                )
                return _finish_run(connection, run, "failed", error)
    with transaction(connection):
        run = connection.execute("SELECT * FROM playbook_runs WHERE id = ? AND worker_id = ?", (run_id, worker_id)).fetchone()
        if not run:
            raise ValueError("playbook worker lease was lost")
        if run["cancel_requested"]:
            return _finish_cancelled(connection, run)
        return _finish_run(connection, run, "succeeded")


def run_worker_once(connection: sqlite3.Connection, worker_id: str | None = None, lease_seconds: int = 60) -> int | None:
    identity = worker_id or f"worker-{uuid.uuid4().hex}"
    run_id = claim_playbook_run(connection, identity, lease_seconds)
    if run_id is None:
        return None
    process_playbook_run(connection, run_id, identity, lease_seconds)
    return run_id
