import os

from create_db import create_database


def init_db() -> None:
    create_database(seed_demo=os.environ.get("SOCIFY_SEED_DEMO") == "1", demo_password=os.environ.get("SOCIFY_DEMO_PASSWORD"))


if __name__ == "__main__":
    init_db()
