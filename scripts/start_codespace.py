import argparse
import os
import sys
from pathlib import Path

from gunicorn.app.wsgiapp import WSGIApplication

from scripts.environment import load_environment


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
    sys.argv = ["gunicorn", "--config", str(root / "gunicorn.conf.py"), "app:app"]
    from scripts.local_services import local_worker_services
    from socify import create_app

    with local_worker_services(create_app().config):
        WSGIApplication().run()


if __name__ == "__main__":
    main()
