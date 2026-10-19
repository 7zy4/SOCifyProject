import argparse
import json
import os

from socify.attack_snapshot import load_stix_snapshot
from socify.db import connect_path
from socify.schema import ensure_schema


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("stix_bundle")
    parser.add_argument("--version", required=True)
    parser.add_argument("--database", default=os.environ.get("SOCIFY_DATABASE", "socify.db"))
    parser.add_argument("--allow-partial", action="store_true")
    arguments = parser.parse_args()
    connection = connect_path(arguments.database)
    try:
        ensure_schema(connection)
        count = load_stix_snapshot(connection, arguments.stix_bundle, arguments.version, arguments.allow_partial)
    finally:
        connection.close()
    print(json.dumps({"status": "loaded", "version": arguments.version, "techniques": count}, sort_keys=True))


if __name__ == "__main__":
    main()
