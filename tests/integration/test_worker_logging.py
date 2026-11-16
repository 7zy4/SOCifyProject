"""Background workers log one line per finished job without evidence, uploaded names or raw exception text."""

import io
import logging

from socify import autopsy_worker, import_worker
from socify.autopsy_worker import run_autopsy_worker_once
from socify.db import get_db
from socify.import_worker import run_import_worker_once

UPLOADED_NAME = "Quarterly-Payroll-Ahmed-Alharbi.jsonl"
EVIDENCE = "EVIDENCE-CONTENT-7c1e9a"
EXCEPTION_TEXT = "RAW-EXCEPTION-TEXT /srv/private/path token=5f2b"
SECRETS = (UPLOADED_NAME, "Quarterly-Payroll", "Ahmed-Alharbi", EVIDENCE, EXCEPTION_TEXT, "5f2b", "/srv/private")


def _worker_lines(caplog):
    return [record.getMessage() for record in caplog.records if record.name == "socify.workers"]


def _assert_private_values_absent(caplog):
    text = "\n".join(f"{record.name} {record.getMessage()}" for record in caplog.records)
    leaked = [value for value in SECRETS if value in text]
    assert not leaked, leaked


def _queue_case_import(client, case_id):
    queued = client.post(
        f"/api/cases/{case_id}/imports?defer=1",
        json={"filename": UPLOADED_NAME, "content": f'{{"title":"{EVIDENCE}","username":"ahmed.alharbi"}}\n'},
    )
    assert queued.status_code == 202, queued.json
    return queued.json["id"]


def test_finished_import_logs_counts_and_state_only(autopsy_case, app, client, caplog):
    job_id = _queue_case_import(client, autopsy_case)
    with caplog.at_level(logging.INFO), app.app_context():
        assert run_import_worker_once(get_db(), "import-log-test") == job_id
    lines = _worker_lines(caplog)
    assert len(lines) == 1, lines
    assert lines[0].startswith(f"import_job_finished job_id={job_id} case_id={autopsy_case} state=completed accepted=1 rejected=0 duration_ms=")
    _assert_private_values_absent(caplog)


def test_failed_import_logs_the_exception_type_not_its_message(autopsy_case, app, client, caplog, monkeypatch):
    job_id = _queue_case_import(client, autopsy_case)

    def fail(*_args, **_kwargs):
        raise RuntimeError(EXCEPTION_TEXT)

    monkeypatch.setattr(import_worker, "_process_job", fail)
    with caplog.at_level(logging.INFO), app.app_context():
        assert run_import_worker_once(get_db(), "import-log-test") == job_id
    lines = _worker_lines(caplog)
    assert len(lines) == 1, lines
    assert lines[0].startswith(f"import_job_failed job_id={job_id} state=interrupted attempt=1 error_type=RuntimeError duration_ms=")
    assert client.get(f"/api/cases/{autopsy_case}/imports/{job_id}").json["status"] == "interrupted"
    _assert_private_values_absent(caplog)


def _queue_sample_analysis(client, case_id):
    sample = client.post(f"/api/cases/{case_id}/samples", data={"file": (io.BytesIO(EVIDENCE.encode()), UPLOADED_NAME)})
    assert sample.status_code == 201, sample.json
    queued = client.post(f"/api/cases/{case_id}/samples/{sample.json['id']}/analyze", json={})
    assert queued.status_code == 202, queued.json
    return queued.json["id"]


def test_finished_analysis_job_logs_state_without_sample_details(autopsy_case, app, client, caplog, monkeypatch):
    job_id = _queue_sample_analysis(client, autopsy_case)
    monkeypatch.setattr(autopsy_worker, "compute_sample", lambda payload: {"sha256": payload["sha256"], "execution": "never executed", "verdict": "clean"})
    with caplog.at_level(logging.INFO), app.app_context():
        assert run_autopsy_worker_once("analysis-log-test") == job_id
    lines = _worker_lines(caplog)
    assert len(lines) == 1, lines
    assert lines[0].startswith(f"autopsy_job_finished job_id={job_id} kind=sample case_id={autopsy_case} state=completed error_code=- attempt=1 duration_ms=")
    _assert_private_values_absent(caplog)


def test_failed_analysis_job_logs_the_error_code_not_the_exception_text(autopsy_case, app, client, caplog, monkeypatch):
    job_id = _queue_sample_analysis(client, autopsy_case)

    def fail(_payload):
        raise ValueError(EXCEPTION_TEXT)

    monkeypatch.setattr(autopsy_worker, "compute_sample", fail)
    with caplog.at_level(logging.INFO), app.app_context():
        assert run_autopsy_worker_once("analysis-log-test") == job_id
    lines = _worker_lines(caplog)
    assert len(lines) == 1, lines
    assert lines[0].startswith(f"autopsy_job_finished job_id={job_id} kind=sample case_id={autopsy_case} state=failed error_code=LOCAL_RENDER_FAILED attempt=1")
    _assert_private_values_absent(caplog)
