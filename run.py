import os

from app import app


def main() -> None:
    host = os.environ.get("SOCIFY_HOST", "127.0.0.1")
    port = int(os.environ.get("SOCIFY_PORT", "5000"))
    debug = os.environ.get("SOCIFY_DEBUG", "0") == "1" and app.config["ENV_NAME"] == "development"
    app.run(host=host, port=port, debug=debug, use_reloader=debug)


if __name__ == "__main__":
    main()
