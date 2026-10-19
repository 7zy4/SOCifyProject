import argparse
import json
import os

from socify.operations import backup_database


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("destination")
    parser.add_argument("--source", default=os.environ.get("SOCIFY_DATABASE", "socify.db"))
    arguments = parser.parse_args()
    print(json.dumps(backup_database(arguments.source, arguments.destination), sort_keys=True))


if __name__ == "__main__":
    main()
