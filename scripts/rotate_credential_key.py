"""Re-encrypt stored secrets and evidence with SOCIFY_CREDENTIAL_KEY; see docs/operations.md before running.

Without --apply the command only reports how many values still depend on SOCIFY_CREDENTIAL_KEY_PREVIOUS.
"""

import argparse
import json

from socify.config import build_config
from socify.db import connect_path
from socify.key_rotation import rotate, survey


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="re-encrypt values held under the previous key")
    arguments = parser.parse_args(argv)
    config = build_config()
    current, previous = str(config["CREDENTIAL_KEY"]), config.get("CREDENTIAL_KEY_PREVIOUS")
    connection = connect_path(str(config["DATABASE"]))
    try:
        result: dict[str, object] = {}
        if arguments.apply:
            if not previous:
                parser.error("SOCIFY_CREDENTIAL_KEY_PREVIOUS is not set; there is no previous key to rotate from")
            result["rotated"] = rotate(connection, current, str(previous))
        remaining = survey(connection, current)
        result["remaining"] = remaining
        result["previous_key_still_needed"] = any(counts["previous"] for counts in remaining.values())
        print(json.dumps(result, indent=2, sort_keys=True))
        return 1 if arguments.apply and result["previous_key_still_needed"] else 0
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
