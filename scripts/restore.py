import argparse
import json

from socify.operations import restore_database


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("backup")
    parser.add_argument("destination")
    parser.add_argument("--confirm", required=True, choices=["RESTORE"])
    arguments = parser.parse_args()
    print(json.dumps(restore_database(arguments.backup, arguments.destination), sort_keys=True))


if __name__ == "__main__":
    main()
