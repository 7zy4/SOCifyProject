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


def restricted_render(payload, directory, operation="report"):
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
        if operation == "report":
            from .autopsy_report_render import render_files

            files = render_files(payload)
        elif operation == "sample":
            from .autopsy_static_analysis import analyze_sample

            files = {"analysis": canonical(analyze_sample(payload)).encode()}
        else:
            raise ValueError("Unknown local worker operation")
        for kind, content in files.items():
            if len(content) > 20 * 1024 * 1024:
                raise ValueError("Report artifact exceeds size limit")
            (Path(directory) / kind).write_bytes(content)
        (Path(directory) / "done").write_text("ok")
    except Exception as exc:
        (Path(directory) / "error").write_text(type(exc).__name__)


def compute_artifacts(payload, operation, formats, timeout):
    with tempfile.TemporaryDirectory(prefix="socify-local-report-") as directory:
        worker = multiprocessing.get_context("spawn").Process(target=restricted_render, args=(payload, directory, operation))
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
        return {kind: (Path(directory) / kind).read_bytes() for kind in formats}


def compute_report(payload, timeout=50):
    from .autopsy_report_render import FORMATS

    return compute_artifacts(payload, "report", FORMATS, timeout)


def compute_sample(payload, timeout=30):
    return json.loads(compute_artifacts(payload, "sample", ["analysis"], timeout)["analysis"])


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
    principal = dict(user)
    policy = (
        get_db().execute("SELECT permissions FROM team_role_permissions WHERE workspace_id = ? AND role = ?", (user["workspace_id"], user["role"])).fetchone()
    )
    if policy:
        principal["role_permissions"] = json.loads(policy[0])
    if job["kind"] == "sample":
        return has_permission(principal, "cases.update")
    report = (
        get_db()
        .execute("SELECT payload FROM autopsy_reports WHERE id = ? AND case_id = ?", (json.loads(job["parameters"]).get("report_id"), job["case_id"]))
        .fetchone()
    )
    return (
        job["kind"] == "report"
        and bool(report)
        and has_permission(principal, "cases.read")
        and (json.loads(report["payload"])["profile"] != "full" or has_permission(principal, "evidence.download"))
    )


def run_autopsy_worker_once(identity="local-autopsy-worker"):
    job = claim_job(identity)
    if not job:
        return None
    error, files, analysis = None, None, None
    try:
        if not job_authorized(job):
            raise PermissionError("Job creator no longer has access")
        parameters = json.loads(job["parameters"])
        if job["kind"] == "report":
            report = get_db().execute("SELECT * FROM autopsy_reports WHERE id = ? AND case_id = ?", (parameters["report_id"], job["case_id"])).fetchone()
            if not report or hashlib.sha256(report["payload"].encode()).hexdigest() != report["sha256"]:
                raise ValueError("Report snapshot integrity failed")
            files = compute_report(json.loads(report["payload"]))
        elif job["kind"] == "sample":
            import base64

            sample = get_db().execute("SELECT * FROM autopsy_samples WHERE id = ? AND case_id = ?", (parameters["sample_id"], job["case_id"])).fetchone()
            if not sample:
                raise ValueError("Quarantined sample is missing")
            content = cipher().decrypt(sample["ciphertext"])
            analysis = compute_sample(
                {"sample_id": sample["id"], "evidence_id": sample["evidence_id"], "sha256": sample["sha256"], "content": base64.b64encode(content).decode()}
            )
        else:
            raise ValueError("Unknown local analysis job")
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
        result = {"report_id": json.loads(job["parameters"]).get("report_id")}
        if error is None and analysis is not None:
            from .autopsy_api import insert_record

            result = {"record_id": insert_record(job["case_id"], "analysis", analysis, actor=job["created_by"])}
        get_db().execute(
            "UPDATE autopsy_jobs SET state = ?, result = ?, error_code = ?, completed_at = ?, worker_id = NULL, lease_expires_at = NULL WHERE id = ?",
            ("failed" if error else "completed", canonical(result), error, iso_now(), job["id"]),
        )
    return job["id"]
