import argparse
import os
import socket
import time
import uuid
from pathlib import Path

from flask import Flask

from scripts.environment import load_environment
from socify import create_app
from socify.db import get_db
from socify.import_worker import run_import_worker_once
from socify.worker_health import Heartbeat


def serve(application: Flask, worker_id: str, lease_seconds: int, poll_seconds: float, once: bool = False) -> None:
    """Process import jobs until stopped, recording a heartbeat on start, after each job and every 30 seconds while idle."""
    heartbeat = Heartbeat("import-worker", worker_id)
    with application.app_context():
        heartbeat.beat(get_db(), "ready", force=True)
        while True:
            processed = run_import_worker_once(get_db(), worker_id, lease_seconds)
            heartbeat.beat(get_db(), "idle" if processed is None else "active", force=processed is not None)
            if once:
                break
            if processed is None:
                time.sleep(poll_seconds)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    parser.add_argument("--lease-seconds", type=int, default=60)
    arguments = parser.parse_args()
    if not 0.05 <= arguments.poll_seconds <= 60 or not 5 <= arguments.lease_seconds <= 3600:
        parser.error("poll seconds or lease seconds are outside the safe range")
    if os.environ.get("SOCIFY_ENV", "development") != "production":
        load_environment(Path(__file__).resolve().parent.parent)
    worker_id = f"{socket.gethostname()}-{uuid.uuid4().hex[:12]}"
    serve(create_app(), worker_id, arguments.lease_seconds, arguments.poll_seconds, arguments.once)


if __name__ == "__main__":
    main()
