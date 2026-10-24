import argparse
import os
import sys
from pathlib import Path

from gunicorn.app.wsgiapp import WSGIApplication

from create_db import create_database
from scripts.prepare_codespace import prepare


def load_environment(root: Path) -> None:
    if os.environ.get("SOCIFY_ENV", "development") == "production":
        raise RuntimeError("Use the production deployment configuration instead of the Codespaces launcher")
    destination = prepare(root / "instance" / "codespaces.env")
    saved = dict(line.split("=", 1) for line in destination.read_text().splitlines() if "=" in line)
    for key in ("SOCIFY_SECRET_KEY", "SOCIFY_CREDENTIAL_KEY"):
        if not os.environ.get(key):
            value = saved.get(key)
            if not value or len(value) < 32:
                raise RuntimeError(f"{key} is missing or invalid in {destination}; preserve existing encryption keys when repairing it")
            os.environ[key] = value
    os.environ.setdefault("SOCIFY_ENV", "development")
    os.environ.setdefault("SOCIFY_DATABASE", str(root / "instance" / "socify.db"))
    os.environ.setdefault("SOCIFY_PORT", "5000")


def main() -> None:
    parser = argparse.ArgumentParser(description="Start SOCify in Codespaces with persistent session and encryption keys")
    parser.add_argument("--check", action="store_true", help="Prepare and validate configuration without starting the server")
    options = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    load_environment(root)
    if options.check:
        print("Codespaces configuration ready; existing keys and database preserved")
        return
    os.chdir(root)
    create_database()
    sys.argv = ["gunicorn", "--config", str(root / "gunicorn.conf.py"), "app:app"]
    WSGIApplication().run()


if __name__ == "__main__":
    main()
