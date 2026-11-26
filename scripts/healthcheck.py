"""Container health checks for the services that serve no HTTP.

    python -m scripts.healthcheck worker --name import-worker --max-age 120
    python -m scripts.healthcheck analysis

`worker` reads the worker's heartbeat from the database named by SOCIFY_DATABASE without writing anything; a worker
busy with a long job counts as healthy while it holds an unexpired lease on that job. `analysis` sends a ping to the
isolated analysis service, which answers with its version and does no work. Exit status 0 is healthy, 1 is not.
"""

import argparse
import os
import sqlite3
import sys

from socify.analysis_transport import ping
from socify.worker_health import WORKER_NAMES, worker_healthy

DEFAULT_ANALYSIS_SOCKET = "/analysis-ipc/analysis.sock"


def check_worker(database: str, name: str, max_age: float) -> bool:
    from socify.db import connect_readonly

    try:
        connection = connect_readonly(database)
    except sqlite3.Error:
        return False
    try:
        return worker_healthy(connection, name, max_age)
    except sqlite3.Error:
        return False
    finally:
        connection.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    checks = parser.add_subparsers(dest="check", required=True)
    worker = checks.add_parser("worker")
    worker.add_argument("--name", required=True, choices=WORKER_NAMES)
    worker.add_argument("--max-age", type=float, default=120.0)
    analysis = checks.add_parser("analysis")
    analysis.add_argument("--socket", default=os.environ.get("SOCIFY_ANALYSIS_SOCKET", DEFAULT_ANALYSIS_SOCKET))
    analysis.add_argument("--timeout", type=float, default=4.0)
    arguments = parser.parse_args(argv)
    if arguments.check == "worker":
        database = os.environ.get("SOCIFY_DATABASE", "")
        if not database or not 10 <= arguments.max_age <= 3600:
            parser.error("set SOCIFY_DATABASE and a --max-age between 10 and 3600 seconds")
        healthy = check_worker(database, arguments.name, arguments.max_age)
    else:
        healthy = ping(arguments.socket, arguments.timeout) is not None
    return 0 if healthy else 1


if __name__ == "__main__":
    sys.exit(main())
