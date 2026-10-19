import os

from socify.db import connect_path
from socify.schema import ensure_schema
from socify.seeding import seed_demo_data


def create_database(database: str | None = None, seed_demo: bool = False, demo_password: str | None = None) -> None:
    path = database or os.environ.get("SOCIFY_DATABASE", "socify.db")
    connection = connect_path(path)
    try:
        ensure_schema(connection)
        if seed_demo:
            if os.environ.get("SOCIFY_ENV", "development") == "production":
                raise RuntimeError("demo data cannot be seeded in production")
            if not demo_password or len(demo_password) < 12:
                raise ValueError("demo password must contain at least 12 characters")
            seed_demo_data(connection, demo_password)
    finally:
        connection.close()


if __name__ == "__main__":
    create_database(seed_demo=os.environ.get("SOCIFY_SEED_DEMO") == "1", demo_password=os.environ.get("SOCIFY_DEMO_PASSWORD"))
