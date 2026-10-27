import hashlib
import json
import os
import sqlite3
import stat
import subprocess  # nosec B404
import sysconfig
import tempfile
from datetime import timedelta
from pathlib import Path

from flask import current_app

from .analysis_transport import AnalysisUnavailableError
from .autopsy_domain import canonical, custody
from .db import database_is_busy, get_db, transaction
from .operational import case_visible
from .security import cipher, has_permission
from .timeutils import iso_now, utc_now


def deny_network(*args, **kwargs):
    raise PermissionError("Network access is disabled for SOCify local analysis")


def read_artifact(path, maximum=20 * 1024 * 1024):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as content:
        metadata = os.fstat(content.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > maximum:
            raise ValueError("Analysis output must be a bounded regular file")
        result = content.read(maximum + 1)
        if len(result) > maximum:
            raise ValueError("Analysis output exceeds the configured limit")
        return result


def compute_artifacts(payload, operation, formats, timeout, isolated_container=False):
    if operation not in {"report", "sample", "probe", "yara_validation"} or set(formats) - {
        "json",
        "html",
        "md",
        "docx",
        "pdf",
        "analysis",
        "probe",
        "validation",
    }:
        raise ValueError("Unknown local analysis operation")
    if not isolated_container and os.environ.get("SOCIFY_ANALYSIS_SOCKET"):
        from .analysis_transport import remote_artifacts

        return remote_artifacts(os.environ["SOCIFY_ANALYSIS_SOCKET"], payload, operation, formats, timeout)
    encoded = canonical(payload).encode()
    if len(encoded) > 24 * 1024 * 1024:
        raise ValueError("Analysis request exceeds the configured limit")
    with tempfile.TemporaryDirectory(prefix="socify-local-report-") as directory:
        root = str(Path(__file__).resolve().parent.parent)
        environment = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONPATH": os.pathsep.join([root, sysconfig.get_path("purelib")]),
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "TMPDIR": directory,
            "XDG_CACHE_HOME": str(Path(directory) / "cache"),
            "SOCIFY_ANALYSIS_OPERATION": operation,
            "SOCIFY_ANALYSIS_OUTPUT": directory,
        }
        if isolated_container:
            environment["SOCIFY_ISOLATED_ANALYSIS_CONTAINER"] = "1"
        try:
            process = subprocess.run(  # nosec B603
                ["/proc/self/exe", "-m", "socify.analysis_sandbox"],
                input=encoded,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                env=environment,
                cwd=root,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("Local analysis exceeded its time limit") from exc
        if process.returncode != 0 or not (Path(directory) / "done").exists():
            raise ValueError("Local analysis failed to enforce its operating-system boundary or compute the result")
        return {kind: read_artifact(Path(directory) / kind) for kind in formats}


def compute_report(payload, timeout=50):
    from .autopsy_report_render import FORMATS

    return compute_artifacts(payload, "report", FORMATS, timeout)


def compute_sample(payload, timeout=30):
    return json.loads(compute_artifacts(payload, "sample", ["analysis"], timeout)["analysis"])


def claim_job(identity):
    try:
        return claim_job_locked(identity)
    except sqlite3.OperationalError as exc:
        if not database_is_busy(exc):
            raise
        return None


def claim_job_locked(identity):
    now = iso_now()
    with transaction(wait=False):
        get_db().execute(
            "UPDATE autopsy_jobs SET state = CASE WHEN attempts >= 3 THEN 'failed' ELSE 'queued' END, worker_id = NULL, lease_expires_at = NULL, error_code = 'LEASE_EXPIRED' WHERE state = 'processing' AND lease_expires_at <= ?",
            (now,),
        )
        job = (
            get_db()
            .execute("SELECT * FROM autopsy_jobs WHERE state = 'queued' AND COALESCE(available_at,created_at)<=? ORDER BY id LIMIT 1", (now,))
            .fetchone()
        )
        if not job:
            return None
        lease = (utc_now() + timedelta(seconds=120)).isoformat().replace("+00:00", "Z")
        get_db().execute(
            "UPDATE autopsy_jobs SET state = 'processing', attempts = attempts + 1, worker_id = ?, lease_expires_at = ?, started_at = COALESCE(started_at, ?), error_code = NULL WHERE id = ?",
            (identity, lease, now, job["id"]),
        )
        return dict(job)


def job_authorized(job):
    from .autopsy_workspace import case_approved

    if not case_approved(job["case_id"]):
        return False
    user = get_db().execute("SELECT id, workspace_id, role FROM users WHERE id = ? AND is_active = 1", (job["created_by"],)).fetchone()
    if not user or not case_visible(job["case_id"], dict(user)):
        return False
    principal = dict(user)
    policy = (
        get_db().execute("SELECT permissions FROM team_role_permissions WHERE workspace_id = ? AND role = ?", (user["workspace_id"], user["role"])).fetchone()
    )
    if policy:
        principal["role_permissions"] = json.loads(policy[0])
    from .autopsy_pipeline import case_full_access

    if not case_full_access(job["case_id"], principal):
        return False
    if job["kind"] == "sample":
        return has_permission(principal, "cases.update")
    if job["kind"] == "detection":
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
            payload = {
                "sample_id": sample["id"],
                "evidence_id": sample["evidence_id"],
                "sha256": sample["sha256"],
                "content": base64.b64encode(content).decode(),
            }
            if parameters.get("yara_pack_id") is not None:
                pack = (
                    get_db()
                    .execute(
                        "SELECT p.* FROM autopsy_yara_packs p JOIN incident_cases c ON c.workspace_id=p.workspace_id WHERE p.id=? AND c.id=?",
                        (parameters["yara_pack_id"], job["case_id"]),
                    )
                    .fetchone()
                )
                if not pack or hashlib.sha256(pack["source"].encode()).hexdigest() != parameters.get("yara_pack_sha256"):
                    raise ValueError("YARA snapshot integrity failed")
                payload.update(
                    rules=pack["source"],
                    rules_source=pack["origin"],
                    yara_pack={key: pack[key] for key in ("id", "name", "version", "license", "origin", "sha256")},
                )
            analysis = compute_sample(payload)
        elif job["kind"] == "detection":
            from .autopsy_detection import run_detection_job

            analysis = run_detection_job(job)
        else:
            raise ValueError("Unknown local analysis job")
    except Exception as exc:
        current_app.logger.error("autopsy_job_failed id=%s error_type=%s", job["id"], type(exc).__name__)
        error = (
            "ANALYSIS_UNAVAILABLE"
            if isinstance(exc, AnalysisUnavailableError)
            else "ACCESS_REVOKED"
            if isinstance(exc, PermissionError)
            else "RESOURCE_LIMIT"
            if isinstance(exc, TimeoutError)
            else "LOCAL_RENDER_FAILED"
        )
    with transaction():
        current = get_db().execute("SELECT * FROM autopsy_jobs WHERE id = ? AND worker_id = ? AND state = 'processing'", (job["id"], identity)).fetchone()
        if not current:
            return job["id"]
        if not job_authorized(job):
            error = "ACCESS_REVOKED"
        if error == "ANALYSIS_UNAVAILABLE" and current["attempts"] < 3:
            available = (utc_now() + timedelta(seconds=5 * 2 ** (current["attempts"] - 1))).isoformat().replace("+00:00", "Z")
            get_db().execute(
                "UPDATE autopsy_jobs SET state='queued',error_code=?,available_at=?,worker_id=NULL,lease_expires_at=NULL WHERE id=?",
                (error, available, job["id"]),
            )
            return job["id"]
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
