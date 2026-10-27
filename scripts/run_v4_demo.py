"""Run an explicitly provisioned synthetic workspace without touching existing data."""

import argparse
import json
import os
from pathlib import Path

from scripts.local_services import local_worker_services
from socify import create_app


def main():
    if os.environ.get("SOCIFY_ENV", "development").lower() != "development":
        raise RuntimeError("Synthetic demo is restricted to development")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("instance/v4-demo"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    run(args.directory.resolve(), args.host, args.port)


def run(directory, host, port):
    if json.loads((directory / "manifest.json").read_text()).get("synthetic") is not True:
        raise RuntimeError("Only a provisioned synthetic workspace may run in demo mode")
    keys = dict(line.split("=", 1) for line in (directory / "runtime.env").read_text().splitlines() if "=" in line)
    app = create_app(
        {
            "DATABASE": str(directory / "socify.db"),
            "ENV_NAME": "development",
            "DEMO_MODE": True,
            "SECRET_KEY": keys["SOCIFY_SECRET_KEY"],
            "CREDENTIAL_KEY": keys["SOCIFY_CREDENTIAL_KEY"],
        }
    )
    with local_worker_services(app.config):
        app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
