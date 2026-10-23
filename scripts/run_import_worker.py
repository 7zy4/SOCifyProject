import argparse
import socket
import time
import uuid

from socify import create_app
from socify.db import get_db
from socify.import_worker import run_import_worker_once


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    parser.add_argument("--lease-seconds", type=int, default=60)
    arguments = parser.parse_args()
    if not 0.05 <= arguments.poll_seconds <= 60 or not 5 <= arguments.lease_seconds <= 3600:
        parser.error("poll seconds or lease seconds are outside the safe range")
    worker_id = f"{socket.gethostname()}-{uuid.uuid4().hex[:12]}"
    application = create_app()
    with application.app_context():
        while True:
            processed = run_import_worker_once(get_db(), worker_id, arguments.lease_seconds)
            if arguments.once:
                break
            if processed is None:
                time.sleep(arguments.poll_seconds)


if __name__ == "__main__":
    main()
