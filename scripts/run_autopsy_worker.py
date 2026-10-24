import argparse
import os
import time
import uuid
from pathlib import Path

from scripts.environment import load_environment
from socify import create_app
from socify.autopsy_worker import run_autopsy_worker_once


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    arguments = parser.parse_args()
    if not 0.1 <= arguments.poll_seconds <= 60:
        parser.error("poll seconds must be between 0.1 and 60")
    if os.environ.get("SOCIFY_ENV", "development") != "production":
        load_environment(Path(__file__).resolve().parent.parent)
    application = create_app()
    identity = f"autopsy-worker-{uuid.uuid4().hex}"
    with application.app_context():
        while True:
            job = run_autopsy_worker_once(identity)
            if arguments.once:
                break
            if job is None:
                time.sleep(arguments.poll_seconds)


if __name__ == "__main__":
    main()
