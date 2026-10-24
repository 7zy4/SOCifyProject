import os
from pathlib import Path

from scripts.prepare_codespace import prepare


def load_environment(root: Path) -> None:
    if os.environ.get("SOCIFY_ENV", "development") == "production":
        raise RuntimeError("Production requires explicitly provisioned environment and encryption keys")
    destination = prepare(root / "instance" / "codespaces.env")
    saved = dict(line.split("=", 1) for line in destination.read_text().splitlines() if "=" in line)
    for key in ("SOCIFY_SECRET_KEY", "SOCIFY_CREDENTIAL_KEY"):
        if not os.environ.get(key):
            value = saved.get(key)
            if not value or len(value) < 32:
                raise RuntimeError(f"{key} is missing or invalid in {destination}; preserve existing encryption keys when repairing it")
            os.environ[key] = value
    os.environ.setdefault("SOCIFY_ENV", "development")
    legacy_database = root / "socify.db"
    os.environ.setdefault("SOCIFY_DATABASE", str(legacy_database if legacy_database.exists() else root / "instance" / "socify.db"))
    os.environ.setdefault("SOCIFY_PORT", "5000")
