import logging
import multiprocessing
import os
import signal
import uuid
from contextlib import contextmanager
from typing import Any

from socify import create_app
from socify.autopsy_worker import run_autopsy_worker_once
from socify.db import get_db
from socify.import_worker import run_import_worker_once


def worker_loop(configuration: dict[str, Any], stop, parent: int, kind: str) -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    application = create_app(configuration)
    identity = f"local-import-{uuid.uuid4().hex}"
    with application.app_context():
        while not stop.is_set() and os.getppid() == parent:
            try:
                job = run_import_worker_once(get_db(), identity, 120) if kind == "import" else run_autopsy_worker_once(identity)
            except Exception as exc:
                logging.getLogger("socify.worker").error("local_worker_failure kind=%s error_type=%s", kind, type(exc).__name__)
                job = None
            if job is None:
                stop.wait(0.5)


@contextmanager
def local_worker_services(configuration):
    context = multiprocessing.get_context("spawn")
    stop = context.Event()
    selected = {
        key: configuration[key]
        for key in (
            "DATABASE",
            "SECRET_KEY",
            "CREDENTIAL_KEY",
            "TESTING",
            "LEGACY_TRAINING_TESTS",
            "MAX_CONTENT_LENGTH",
            "MAX_IMPORT_ROWS",
            "TRUSTED_HOSTS",
            "REQUIRE_CASE_APPROVAL",
            "REQUIRE_INVESTIGATION_SELECTION",
        )
    }
    workers = [context.Process(target=worker_loop, args=(selected, stop, os.getpid(), kind), name=f"socify-local-{kind}") for kind in ("import", "autopsy")]
    for worker in workers:
        worker.start()
    try:
        yield workers
    finally:
        stop.set()
        for worker in workers:
            worker.join(3)
            if worker.is_alive():
                worker.terminate()
                worker.join(2)
            if worker.is_alive():
                worker.kill()
                worker.join(2)
