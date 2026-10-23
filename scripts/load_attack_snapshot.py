import argparse
import json
import os

from socify.attack_snapshot import activate_attack_version, load_stix_snapshot
from socify.db import connect_path
from socify.schema import ensure_schema


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("stix_bundle", nargs="?")
    parser.add_argument("--version")
    parser.add_argument("--activate-version")
    parser.add_argument("--database", default=os.environ.get("SOCIFY_DATABASE", "socify.db"))
    parser.add_argument("--allow-partial", action="store_true")
    arguments = parser.parse_args()
    connection = connect_path(arguments.database)
    try:
        ensure_schema(connection)
        if arguments.activate_version:
            changed = activate_attack_version(connection, arguments.activate_version)
            result = {"status": "activated", "version": arguments.activate_version, "changed": changed}
        else:
            if not arguments.stix_bundle or not arguments.version:
                parser.error("stix_bundle and --version are required unless --activate-version is used")
            count = load_stix_snapshot(connection, arguments.stix_bundle, arguments.version, arguments.allow_partial)
            result = {"status": "loaded", "version": arguments.version, "techniques": count}
    finally:
        connection.close()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
