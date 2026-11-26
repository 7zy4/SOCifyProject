import argparse
import os
import time
import uuid
from pathlib import Path

from flask import Flask

from scripts.environment import load_environment
from socify import create_app
from socify.autopsy_worker import run_autopsy_worker_once
from socify.db import get_db
from socify.worker_health import Heartbeat


def serve(application: Flask, identity: str, poll_seconds: float, once: bool = False) -> None:
    """Process case jobs until stopped, recording a heartbeat on start, after each job and every 30 seconds while idle."""
    heartbeat = Heartbeat("autopsy-worker", identity)
    with application.app_context():
        heartbeat.beat(get_db(), "ready", force=True)
        while True:
            job = run_autopsy_worker_once(identity)
            heartbeat.beat(get_db(), "idle" if job is None else "active", force=job is not None)
            if once:
                break
            if job is None:
                time.sleep(poll_seconds)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    arguments = parser.parse_args()
    if not 0.1 <= arguments.poll_seconds <= 60:
        parser.error("poll seconds must be between 0.1 and 60")
    if os.environ.get("SOCIFY_ENV", "development") != "production":
        load_environment(Path(__file__).resolve().parent.parent)
    serve(create_app(), f"autopsy-worker-{uuid.uuid4().hex}", arguments.poll_seconds, arguments.once)


if __name__ == "__main__":
    main()
