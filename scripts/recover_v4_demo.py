"""Reset a synthetic demo account in its explicit database and refresh its accounts file."""

import argparse
import json
import os
import secrets
from pathlib import Path

from scripts.bootstrap_team import reset_password
from socify import create_app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("instance/v4-demo"))
    parser.add_argument("--email", default="manager@demo.socify.test")
    args = parser.parse_args()
    if os.environ.get("SOCIFY_ENV", "development") != "development":
        raise RuntimeError("Demo recovery is restricted to development")
    directory = args.directory.resolve()
    if json.loads((directory / "manifest.json").read_text()).get("synthetic") is not True:
        raise RuntimeError("Not a synthetic demo directory")
    accounts_path = directory / "accounts.json"
    accounts = json.loads(accounts_path.read_text())
    account = next(item for item in accounts if item["email"] == args.email)
    keys = dict(line.split("=", 1) for line in (directory / "runtime.env").read_text().splitlines())
    app = create_app({"DATABASE": str(directory / "socify.db"), "SECRET_KEY": keys["SOCIFY_SECRET_KEY"], "CREDENTIAL_KEY": keys["SOCIFY_CREDENTIAL_KEY"]})
    replacement = secrets.token_urlsafe(24) + "!7aA"
    reset_password(app, args.email, replacement)
    account["password"] = replacement
    temporary = directory / (".accounts-" + secrets.token_hex(8))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(accounts, output, ensure_ascii=False, indent=2)
        output.write("\n")
    os.replace(temporary, accounts_path)
    print(f"Account recovered: {args.email}\nDatabase: {directory / 'socify.db'}\nOpen updated credentials privately: {accounts_path}")


if __name__ == "__main__":
    main()
