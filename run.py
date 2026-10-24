import os
from pathlib import Path

from scripts.environment import load_environment
from scripts.local_services import local_worker_services
from socify import create_app


def main() -> None:
    if os.environ.get("SOCIFY_ENV", "development") == "production":
        raise RuntimeError("Use Gunicorn and the independently supervised workers for production")
    load_environment(Path(__file__).resolve().parent)
    app = create_app()
    host = os.environ.get("SOCIFY_HOST", "127.0.0.1")
    port = int(os.environ.get("SOCIFY_PORT", "5000"))
    debug = os.environ.get("SOCIFY_DEBUG", "0") == "1" and app.config["ENV_NAME"] == "development"
    with local_worker_services(app.config):
        app.run(host=host, port=port, debug=debug, use_reloader=False)


if __name__ == "__main__":
    main()
