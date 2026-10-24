import hashlib
import json
import multiprocessing
import os
import resource
import socket
import tempfile
from datetime import timedelta
from pathlib import Path

from flask import current_app

from .autopsy_domain import canonical, custody
from .db import get_db, transaction
from .operational import case_visible
from .security import cipher, has_permission
from .timeutils import iso_now, utc_now


def deny_network(*args, **kwargs):
    raise PermissionError("Network access is disabled for SOCify local analysis")


def restricted_render(payload, directory):
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (40, 45))
        resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024 * 1024, 1536 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
        resource.setrlimit(resource.RLIMIT_FSIZE, (24 * 1024 * 1024, 24 * 1024 * 1024))
        for method in ("connect", "connect_ex", "sendto", "sendmsg"):
            if hasattr(socket.socket, method):
                setattr(socket.socket, method, deny_network)
        socket.create_connection = deny_network
        socket.getaddrinfo = deny_network
        os.environ["XDG_CACHE_HOME"] = str(Path(directory) / "cache")
        from .autopsy_report_render import render_files

        files = render_files(payload)
        for kind, content in files.items():
            if len(content) > 20 * 1024 * 1024:
                raise ValueError("Report artifact exceeds size limit")
            (Path(directory) / kind).write_bytes(content)
        (Path(directory) / "done").write_text("ok")
    except Exception as exc:
        (Path(directory) / "error").write_text(type(exc).__name__)


def compute_report(payload, timeout=50):
    from .autopsy_report_render import FORMATS

    with tempfile.TemporaryDirectory(prefix="socify-local-report-") as directory:
        worker = multiprocessing.get_context("spawn").Process(target=restricted_render, args=(payload, directory))
        worker.start()
        worker.join(timeout)
        if worker.is_alive():
            worker.terminate()
            worker.join(2)
            if worker.is_alive():
                worker.kill()
                worker.join(2)
            raise TimeoutError("Local report renderer exceeded its time limit")
        if worker.exitcode != 0 or not (Path(directory) / "done").exists():
            raise ValueError("Local report renderer failed within its isolation boundary")
        return {kind: (Path(directory) / kind).read_bytes() for kind in FORMATS}


def claim_job(identity):
    now = iso_now()
    with transaction():
        get_db().execute(
            "UPDATE autopsy_jobs SET state = CASE WHEN attempts >= 3 THEN 'failed' ELSE 'queued' END, worker_id = NULL, lease_expires_at = NULL, error_code = 'LEASE_EXPIRED' WHERE state = 'processing' AND lease_expires_at <= ?",
            (now,),
        )
        job = get_db().execute("SELECT * FROM autopsy_jobs WHERE state = 'queued' ORDER BY id LIMIT 1").fetchone()
        if not job:
            return None
        lease = (utc_now() + timedelta(seconds=120)).isoformat().replace("+00:00", "Z")
        get_db().execute(
            "UPDATE autopsy_jobs SET state = 'processing', attempts = attempts + 1, worker_id = ?, lease_expires_at = ?, started_at = COALESCE(started_at, ?), error_code = NULL WHERE id = ?",
            (identity, lease, now, job["id"]),
        )
        return dict(job)


def job_authorized(job):
    user = get_db().execute("SELECT id, workspace_id, role FROM users WHERE id = ? AND is_active = 1", (job["created_by"],)).fetchone()
    if not user or not case_visible(job["case_id"], dict(user)):
        return False
    return job["kind"] == "report" and has_permission(dict(user), "cases.read")


def run_autopsy_worker_once(identity="local-autopsy-worker"):
    job = claim_job(identity)
    if not job:
        return None
    error, files = None, None
    try:
        if not job_authorized(job):
            raise PermissionError("Job creator no longer has access")
        parameters = json.loads(job["parameters"])
        report = get_db().execute("SELECT * FROM autopsy_reports WHERE id = ? AND case_id = ?", (parameters["report_id"], job["case_id"])).fetchone()
        if not report or hashlib.sha256(report["payload"].encode()).hexdigest() != report["sha256"]:
            raise ValueError("Report snapshot integrity failed")
        payload = json.loads(report["payload"])
        if payload["profile"] == "full":
            user = get_db().execute("SELECT id, role, workspace_id FROM users WHERE id = ?", (job["created_by"],)).fetchone()
            if not has_permission(dict(user), "evidence.download"):
                raise PermissionError("Job creator cannot download full evidence")
        files = compute_report(payload)
    except Exception as exc:
        current_app.logger.error("autopsy_job_failed id=%s error_type=%s", job["id"], type(exc).__name__)
        error = "ACCESS_REVOKED" if isinstance(exc, PermissionError) else "RESOURCE_LIMIT" if isinstance(exc, TimeoutError) else "LOCAL_RENDER_FAILED"
    with transaction():
        current = get_db().execute("SELECT * FROM autopsy_jobs WHERE id = ? AND worker_id = ? AND state = 'processing'", (job["id"], identity)).fetchone()
        if not current:
            return job["id"]
        if not job_authorized(job):
            error = "ACCESS_REVOKED"
        if error is None and files is not None:
            for kind, content in files.items():
                get_db().execute(
                    "INSERT OR IGNORE INTO autopsy_report_files(report_id, format, content, sha256) VALUES (?, ?, ?, ?)",
                    (parameters["report_id"], kind, cipher().encrypt(content), hashlib.sha256(content).hexdigest()),
                )
            custody(job["case_id"], "report_rendered", {"report_id": parameters["report_id"], "formats": sorted(files)}, actor=job["created_by"])
        get_db().execute(
            "UPDATE autopsy_jobs SET state = ?, result = ?, error_code = ?, completed_at = ?, worker_id = NULL, lease_expires_at = NULL WHERE id = ?",
            ("failed" if error else "completed", canonical({"report_id": json.loads(job["parameters"]).get("report_id")}), error, iso_now(), job["id"]),
        )
    return job["id"]
