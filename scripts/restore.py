import argparse
import json
import os
import tempfile
from pathlib import Path

from socify.backup_crypto import decrypt_file
from socify.operations import restore_database


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("backup")
    parser.add_argument("destination")
    parser.add_argument("--confirm", required=True, choices=["RESTORE"])
    parser.add_argument("--decrypt", action="store_true", help="the backup is a .db.enc file; the key is read from SOCIFY_BACKUP_KEY")
    arguments = parser.parse_args()
    if not arguments.decrypt:
        print(json.dumps(restore_database(arguments.backup, arguments.destination), sort_keys=True))
        return
    key = os.environ.get("SOCIFY_BACKUP_KEY", "")
    if not key:
        parser.error("--decrypt reads the key from SOCIFY_BACKUP_KEY, which is not set")
    destination = Path(arguments.destination).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    # The decrypted copy is checked and restored like any backup, then removed.
    with tempfile.TemporaryDirectory(prefix="socify-decrypt-", dir=destination.parent) as staging:
        plain = Path(staging) / "backup.db"
        decrypt_file(arguments.backup, plain, key)
        print(json.dumps(restore_database(str(plain), str(destination)), sort_keys=True))


if __name__ == "__main__":
    main()
