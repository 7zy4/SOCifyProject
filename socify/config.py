import os
import secrets
from pathlib import Path


def _boolean(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _integer(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def build_config() -> dict[str, object]:
    environment = os.environ.get("SOCIFY_ENV", "development").strip().lower()
    secret_key = os.environ.get("SOCIFY_SECRET_KEY")
    if environment == "production" and not secret_key:
        raise RuntimeError("SOCIFY_SECRET_KEY is required in production")
    effective_secret = secret_key or secrets.token_bytes(32)
    database = os.environ.get("SOCIFY_DATABASE", str(Path.cwd() / "socify.db"))
    trusted_hosts = [item.strip() for item in os.environ.get("SOCIFY_TRUSTED_HOSTS", "localhost,127.0.0.1").split(",") if item.strip()]
    return {
        "ENV_NAME": environment,
        "SECRET_KEY": effective_secret,
        "DATABASE": database,
        "TESTING": False,
        "WTF_CSRF_ENABLED": True,
        "WTF_CSRF_TIME_LIMIT": 3600,
        "MAX_CONTENT_LENGTH": _integer("SOCIFY_MAX_UPLOAD_BYTES", 10 * 1024 * 1024),
        "MAX_IMPORT_ROWS": _integer("SOCIFY_MAX_IMPORT_ROWS", 100000),
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        "SESSION_COOKIE_SECURE": _boolean("SOCIFY_HTTPS"),
        "PERMANENT_SESSION_LIFETIME": _integer("SOCIFY_SESSION_SECONDS", 28800),
        "ALLOW_REGISTRATION": _boolean("SOCIFY_ALLOW_REGISTRATION", environment != "production"),
        "CREDENTIAL_KEY": os.environ.get("SOCIFY_CREDENTIAL_KEY") or effective_secret,
        "TRUSTED_HOSTS": trusted_hosts,
        "RATE_LIMIT_LOGIN_ATTEMPTS": _integer("SOCIFY_LOGIN_ATTEMPTS", 5),
        "RATE_LIMIT_LOGIN_WINDOW_SECONDS": _integer("SOCIFY_LOGIN_WINDOW_SECONDS", 900),
        "SSE_POLL_SECONDS": 1.0,
        "SSE_HEARTBEAT_SECONDS": 15.0,
    }
