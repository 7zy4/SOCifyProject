import argparse
import json
import os

from socify.db import connect_path
from socify.operations import migration_dry_run
from socify.schema import ensure_schema


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", default=os.environ.get("SOCIFY_DATABASE", "socify.db"))
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()
    if arguments.dry_run:
        print(json.dumps(migration_dry_run(arguments.database), sort_keys=True))
        return
    connection = connect_path(arguments.database)
    try:
        ensure_schema(connection)
    finally:
        connection.close()
    print(json.dumps({"status": "migrated", "database": arguments.database}, sort_keys=True))


if __name__ == "__main__":
    main()
