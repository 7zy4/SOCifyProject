import argparse
import os
import socket
import time
import uuid

from socify.db import connect_path
from socify.playbook_worker import run_worker_once
from socify.schema import ensure_schema


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", default=os.environ.get("SOCIFY_DATABASE", "socify.db"))
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    parser.add_argument("--lease-seconds", type=int, default=60)
    arguments = parser.parse_args()
    if not 0.05 <= arguments.poll_seconds <= 60 or not 5 <= arguments.lease_seconds <= 3600:
        parser.error("poll seconds or lease seconds are outside the safe range")
    worker_id = f"{socket.gethostname()}-{uuid.uuid4().hex[:12]}"
    connection = connect_path(arguments.database)
    try:
        ensure_schema(connection)
        while True:
            processed = run_worker_once(connection, worker_id, arguments.lease_seconds)
            if arguments.once:
                break
            if processed is None:
                time.sleep(arguments.poll_seconds)
    finally:
        connection.close()


if __name__ == "__main__":
    main()
