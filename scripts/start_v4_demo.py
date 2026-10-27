"""One entry point for an isolated, verified V4 demo and its matching accounts."""

import argparse
import base64
import fcntl
import hashlib
import json
import os
import re
import secrets
import socket
import sqlite3
import subprocess  # nosec B404
import sys
from datetime import UTC, datetime
from pathlib import Path

from scripts.prepare_v4_demo import TEAM, provision
from socify import create_app
from socify.autopsy_worker import compute_artifacts

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "socify-v4-analysis"
LABEL = "io.socify.analysis-source"
# Fixed, validated service IPC; no application data is mounted in this backend.
SOCKET = "/tmp/socify-v4-dev-analysis-ipc/analysis.sock"  # noqa: S108 # nosec B108


def command(arguments, *, capture=False):
    return subprocess.run(arguments, cwd=ROOT, check=True, text=True, capture_output=capture)  # noqa: S603 # nosec B603


def image_fingerprint():
    paths = [ROOT / "Dockerfile", ROOT / ".dockerignore", ROOT / "requirements.txt", ROOT / "scripts/run_analysis_service.py", ROOT / "static/report.css"]
    paths += sorted((ROOT / "socify").glob("*.py"))
    paths += sorted(path for path in (ROOT / "static/fonts").rglob("*") if path.is_file())
    digest = hashlib.sha256()
    for path in paths:
        digest.update(str(path.relative_to(ROOT)).encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def build_analysis(fingerprint):
    options = ["--target", "analysis", "--label", f"{LABEL}={fingerprint}", "-t", IMAGE]
    if os.environ.get("SOCIFY_BUILD_CA"):
        options += ["--secret", "id=build_ca,src=" + os.environ["SOCIFY_BUILD_CA"]]
    # The daemon builder uses its configured registry proxy/CA trust. Only a
    # corrupt snapshot store triggers the independently stored Buildx fallback.
    lines: list[str] = []
    with subprocess.Popen(["docker", "build", *options, "."], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as process:  # nosec B603, B607 # noqa: S603,S607
        if process.stdout is None:
            raise RuntimeError("Docker build output is unavailable")
        for line in process.stdout:
            print(line, end="", flush=True)
            lines = [*lines[-99:], line]
        result = process.wait()
    if result == 0:
        return
    if "parent snapshot" not in "".join(lines) or "does not exist" not in "".join(lines):
        raise RuntimeError("Analysis image build failed; inspect the build output above")
    print("Detected a corrupt Docker snapshot cache; rebuilding with a separate Buildx store.", flush=True)
    builder = "socify-v4-builder"
    found = subprocess.run(["docker", "buildx", "inspect", builder], capture_output=True, check=False)  # nosec B603, B607 # noqa: S603,S607
    if found.returncode:
        command(["docker", "buildx", "create", "--name", builder, "--driver", "docker-container"])
    command(["docker", "buildx", "build", "--builder", builder, "--load", *options, "."])


def ensure_analysis():
    command(["docker", "info"], capture=True)
    fingerprint = image_fingerprint()
    inspected = subprocess.run(  # nosec B603, B607 # noqa: S603,S607
        ["docker", "image", "inspect", "--format", '{{index .Config.Labels "' + LABEL + '"}}', IMAGE],  # nosec B607 # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    if inspected.returncode or inspected.stdout.strip() != fingerprint:
        build_analysis(fingerprint)
    command(["bash", "scripts/start_v4_analysis.sh"])
    os.environ["SOCIFY_ANALYSIS_SOCKET"] = SOCKET
    preflight_analysis()


def preflight_analysis():
    """Verify real child computation before writing any demo credentials."""
    fixture = b"SOCIFY-STARTUP-PROBE"
    payload = {
        "rules": 'rule SOCify_Startup { strings: $a = "SOCIFY-STARTUP-PROBE" condition: $a }',
        "fixtures": {"positive": [base64.b64encode(fixture).decode()], "negative": [base64.b64encode(b"ordinary fixture").decode()]},
    }
    result = json.loads(compute_artifacts(payload, "yara_validation", ["validation"], 30)["validation"])
    if not result.get("valid"):
        raise RuntimeError("The isolated YARA startup fixture failed")
    print("Isolated YARA computation verified.", flush=True)


def incomplete_demo(directory):
    """Recognize the old failed synthetic seeder without claiming arbitrary data."""
    try:
        accounts = json.loads((directory / "accounts.json").read_text())
        expected = {f"{handle}@demo.socify.test" for handle, _name, _role in TEAM}
        if {account["email"] for account in accounts} != expected or not (directory / "runtime.env").is_file():
            return False
        with sqlite3.connect((directory / "socify.db").as_uri() + "?mode=ro", uri=True) as database:
            actual = {row[0] for row in database.execute("SELECT u.email FROM demo_accounts d JOIN users u ON u.id=d.user_id")}
            all_users = {row[0] for row in database.execute("SELECT email FROM users")}
        return actual == expected == all_users
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        return False


def prepare(directory):
    if directory.exists():
        if (directory / "manifest.json").is_file():
            if json.loads((directory / "manifest.json").read_text()).get("synthetic") is not True:
                raise RuntimeError("The existing directory is not a synthetic demo")
            return
        if not incomplete_demo(directory):
            raise RuntimeError(f"Unrecognized existing directory preserved: {directory}")
        backup = directory.with_name(directory.name + ".incomplete-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3))
        directory.rename(backup)
        print(f"Previous incomplete demo preserved: {backup}", flush=True)
    staging = directory.with_name("." + directory.name + ".preparing-" + secrets.token_hex(6))
    try:
        provision(staging)
        staging.rename(directory)
    except Exception:
        print(f"Incomplete setup preserved for diagnosis: {staging}", file=sys.stderr)
        raise


def verify_accounts(directory):
    keys = dict(line.split("=", 1) for line in (directory / "runtime.env").read_text().splitlines() if "=" in line)
    accounts = json.loads((directory / "accounts.json").read_text())
    app = create_app(
        {
            "DATABASE": str(directory / "socify.db"),
            "ENV_NAME": "development",
            "DEMO_MODE": True,
            "SECRET_KEY": keys["SOCIFY_SECRET_KEY"],
            "CREDENTIAL_KEY": keys["SOCIFY_CREDENTIAL_KEY"],
        }
    )
    for account in accounts:
        client = app.test_client()
        page = client.get("/login")
        token = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        if not token:
            raise RuntimeError("Login page did not provide a CSRF token")
        response = client.post("/login", data={"email": account["email"], "password": account["password"], "csrf_token": token[1]})
        if response.status_code != 302 or response.location != "/dashboard" or client.get("/api/auth/me").status_code != 200:
            raise RuntimeError(f"Saved credentials did not pass real login: {account['email']}. Use scripts.recover_v4_demo for this directory.")
        token = client.get("/api/auth/csrf").get_json()["csrf_token"]
        client.post("/api/auth/logout", headers={"X-CSRFToken": token})
    print(f"Verified real login for {len(accounts)} saved demo accounts.", flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("instance/v4-codespace-login"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("SOCIFY_PORT", "5001")))
    args = parser.parse_args(argv)
    if os.environ.get("SOCIFY_ENV", "development").strip().lower() != "development":
        raise RuntimeError("Synthetic demos are restricted to development")
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535")
    with socket.socket() as probe:
        if probe.connect_ex(("127.0.0.1", args.port)) == 0:
            raise RuntimeError(f"Port {args.port} is in use. Stop its existing server with Ctrl+C first.")
    directory = args.directory.resolve()
    directory.parent.mkdir(parents=True, exist_ok=True)
    os.environ["SOCIFY_PORT"] = str(args.port)
    lock = directory.with_name("." + directory.name + ".startup.lock")
    with lock.open("a") as guard:
        fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            ensure_analysis()
        except Exception:
            subprocess.run(["docker", "logs", "--tail", "20", "socify-v4-dev-analysis"], check=False)  # nosec B603, B607 # noqa: S603,S607
            raise
        prepare(directory)
        verify_accounts(directory)
    public = os.environ.get("CODESPACE_NAME")
    url = f"https://{public}-{args.port}.app.github.dev/login" if public else f"http://127.0.0.1:{args.port}/login"
    print(
        f"\nLogin URL: {url}\nAccounts: {directory / 'accounts.json'}\nOpen credentials in the Codespaces editor: code {directory / 'accounts.json'}\nKeep this terminal open. Ctrl+C stops the app.\n",
        flush=True,
    )
    from scripts.run_v4_demo import run

    run(directory, os.environ.get("SOCIFY_HOST", "127.0.0.1"), args.port)


if __name__ == "__main__":
    main()
