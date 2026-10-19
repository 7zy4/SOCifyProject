from socify import create_app
from socify.db import connect_path
from socify.schema import ensure_schema

app = create_app()


def get_db_connection():
    return connect_path(str(app.config["DATABASE"]), bool(app.config.get("TESTING")))


def ensure_phase1_schema() -> None:
    connection = get_db_connection()
    try:
        ensure_schema(connection)
    finally:
        connection.close()


def init_db() -> None:
    ensure_phase1_schema()
