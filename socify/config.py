import os
import secrets
from dataclasses import dataclass
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
    credential_key = os.environ.get("SOCIFY_CREDENTIAL_KEY")
    if environment == "production" and not credential_key:
        raise RuntimeError("SOCIFY_CREDENTIAL_KEY is required in production; reuse the previous SOCIFY_SECRET_KEY value if data was encrypted without it")
    previous_credential_key = os.environ.get("SOCIFY_CREDENTIAL_KEY_PREVIOUS") or None
    metrics_token = os.environ.get("SOCIFY_METRICS_TOKEN", "").strip() or None
    if metrics_token is not None and len(metrics_token) < 32:
        raise RuntimeError("SOCIFY_METRICS_TOKEN must be at least 32 characters; leave it unset to keep /health/metrics disabled")
    session_idle = _integer("SOCIFY_SESSION_IDLE_SECONDS", 3600)
    if session_idle != 0 and session_idle < 300:
        raise RuntimeError("SOCIFY_SESSION_IDLE_SECONDS must be 0 (no idle limit) or at least 300 seconds")
    database = os.environ.get("SOCIFY_DATABASE", str(Path.cwd() / "socify.db"))
    trusted_hosts = [item.strip() for item in os.environ.get("SOCIFY_TRUSTED_HOSTS", "localhost,127.0.0.1").split(",") if item.strip()]
    codespace_name = os.environ.get("CODESPACE_NAME", "").strip()
    codespace_port = _integer("SOCIFY_PORT", 5000)
    codespace_host = None
    if codespace_name and all(char in "abcdefghijklmnopqrstuvwxyz0123456789-" for char in codespace_name) and 1 <= codespace_port <= 65535:
        codespace_host = f"{codespace_name}-{codespace_port}.app.github.dev"
        trusted_hosts.append(codespace_host)
    return {
        "ENV_NAME": environment,
        "CODESPACE_PUBLIC_HOST": codespace_host,
        "PRODUCT_NAME": "SOCify",
        "REQUIRE_CASE_APPROVAL": _boolean("SOCIFY_REQUIRE_CASE_APPROVAL", False),
        "REQUIRE_INVESTIGATION_SELECTION": _boolean("SOCIFY_REQUIRE_INVESTIGATION_SELECTION", False),
        "DEMO_MODE": _boolean("SOCIFY_DEMO_MODE", False),
        "SECRET_KEY": effective_secret,
        "DATABASE": database,
        "TESTING": False,
        "WTF_CSRF_ENABLED": True,
        "WTF_CSRF_TIME_LIMIT": 3600,
        "MAX_CONTENT_LENGTH": _integer("SOCIFY_MAX_UPLOAD_BYTES", 10 * 1024 * 1024),
        "MAX_IMPORT_ROWS": _integer("SOCIFY_MAX_IMPORT_ROWS", 100000),
        "IMPORT_INLINE_EXECUTION": _boolean("SOCIFY_IMPORT_INLINE_EXECUTION", environment != "production"),
        "MAX_PENDING_IMPORT_JOBS": _integer("SOCIFY_MAX_PENDING_IMPORT_JOBS", 100),
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        "SESSION_COOKIE_SECURE": _boolean("SOCIFY_HTTPS"),
        "PERMANENT_SESSION_LIFETIME": _integer("SOCIFY_SESSION_SECONDS", 28800),
        "SESSION_IDLE_SECONDS": session_idle,
        "CREDENTIAL_KEY": credential_key or effective_secret,
        "CREDENTIAL_KEY_PREVIOUS": previous_credential_key,
        "METRICS_TOKEN": metrics_token,
        "TRUSTED_HOSTS": trusted_hosts,
        "TRUSTED_PROXY_HOPS": min(max(_integer("SOCIFY_TRUSTED_PROXIES", 0), 0), 5),
        "RATE_LIMIT_LOGIN_ATTEMPTS": _integer("SOCIFY_LOGIN_ATTEMPTS", 5),
        "RATE_LIMIT_LOGIN_IP_ATTEMPTS": _integer("SOCIFY_LOGIN_IP_ATTEMPTS", 50),
        "RATE_LIMIT_LOGIN_ACCOUNT_ATTEMPTS": _integer("SOCIFY_LOGIN_ACCOUNT_ATTEMPTS", 20),
        "RATE_LIMIT_REGISTER_ATTEMPTS": _integer("SOCIFY_REGISTER_ATTEMPTS", 20),
        "RATE_LIMIT_SOURCE_KEY_ATTEMPTS": _integer("SOCIFY_SOURCE_KEY_ATTEMPTS", 20),
        "RATE_LIMIT_LOGIN_WINDOW_SECONDS": _integer("SOCIFY_LOGIN_WINDOW_SECONDS", 900),
        "RATE_LIMIT_REAUTH_ATTEMPTS": _integer("SOCIFY_REAUTH_ATTEMPTS", 5),
        "EGRESS_ENABLED": _boolean("SOCIFY_EGRESS_ENABLED", False),
        "INTAKE_GROUP_SECONDS": min(max(_integer("SOCIFY_INTAKE_GROUP_SECONDS", 3600), 0), 86400),
        "OUTBOX_DATABASE": os.environ.get("SOCIFY_OUTBOX_DATABASE", str(Path(database).with_name("outbox.db"))),
        "REAUTH_REVOKE_SESSION": _boolean("SOCIFY_REAUTH_REVOKE_SESSION", True),
    }


@dataclass(frozen=True)
class BackupSettings:
    database: str
    directory: str
    interval_hours: float
    keep: int
    key: str | None


def backup_settings() -> BackupSettings:
    """Settings for the backup service (scripts/backup_scheduler.py), validated when it starts.

    The backup key is separate from the credential key: losing one never exposes or locks the other.
    """
    try:
        interval = float(os.environ.get("SOCIFY_BACKUP_INTERVAL_HOURS", "24"))
    except ValueError:
        interval = -1.0
    if not 1 <= interval <= 720:
        raise RuntimeError("SOCIFY_BACKUP_INTERVAL_HOURS must be between 1 and 720")
    keep = _integer("SOCIFY_BACKUP_KEEP", 14)
    if not 1 <= keep <= 1000:
        raise RuntimeError("SOCIFY_BACKUP_KEEP must be between 1 and 1000")
    key = os.environ.get("SOCIFY_BACKUP_KEY", "").strip() or None
    if key is not None and len(key) < 32:
        raise RuntimeError("SOCIFY_BACKUP_KEY must be at least 32 characters; leave it unset to keep backups unencrypted")
    return BackupSettings(
        database=os.environ.get("SOCIFY_DATABASE", str(Path.cwd() / "socify.db")),
        directory=os.environ.get("SOCIFY_BACKUP_DIR", "/backups"),
        interval_hours=interval,
        keep=keep,
        key=key,
    )


@dataclass(frozen=True)
class EgressSettings:
    outbox: str
    allowlist: frozenset[str]
    webhooks: dict[str, str]
    webhook_secrets: dict[str, str]
    max_attempts: int
    smtp: dict[str, object]
    relay_token: str | None
    relay_port: int


def egress_settings() -> EgressSettings:
    """Settings for the egress service only; the app never sees destination URLs, secrets or SMTP credentials."""
    allowlist = frozenset(host.strip().lower().rstrip(".") for host in os.environ.get("SOCIFY_EGRESS_ALLOWLIST", "").split(",") if host.strip())
    webhooks: dict[str, str] = {}
    for item in os.environ.get("SOCIFY_EGRESS_WEBHOOKS", "").split(","):
        if not item.strip():
            continue
        name, separator, url = item.strip().partition("=")
        if not separator or not name.strip() or not url.strip().startswith("https://"):
            raise RuntimeError("SOCIFY_EGRESS_WEBHOOKS must list name=https://... pairs separated by commas")
        webhooks[name.strip().lower()] = url.strip()
    secrets_by_name = {
        name: value for name in webhooks if (value := os.environ.get(f"SOCIFY_EGRESS_WEBHOOK_SECRET_{name.upper().replace('-', '_')}", "").strip())
    }
    max_attempts = _integer("SOCIFY_EGRESS_MAX_ATTEMPTS", 8)
    if not 1 <= max_attempts <= 50:
        raise RuntimeError("SOCIFY_EGRESS_MAX_ATTEMPTS must be between 1 and 50")
    tls = os.environ.get("SOCIFY_SMTP_TLS", "starttls").strip().lower()
    if tls not in {"starttls", "ssl"}:
        raise RuntimeError("SOCIFY_SMTP_TLS must be starttls or ssl; unencrypted SMTP is not supported")
    smtp: dict[str, object] = {
        "host": os.environ.get("SOCIFY_SMTP_HOST", "").strip().lower(),
        "port": _integer("SOCIFY_SMTP_PORT", 465 if tls == "ssl" else 587),
        "username": os.environ.get("SOCIFY_SMTP_USERNAME", ""),
        "password": os.environ.get("SOCIFY_SMTP_PASSWORD", ""),
        "sender": os.environ.get("SOCIFY_SMTP_FROM", "").strip(),
        "tls": tls,
    }
    relay_token = os.environ.get("SOCIFY_EGRESS_TOKEN", "").strip() or None
    if relay_token is not None and len(relay_token) < 32:
        raise RuntimeError("SOCIFY_EGRESS_TOKEN must be at least 32 characters; leave it unset to keep the relay off")
    return EgressSettings(
        outbox=os.environ.get("SOCIFY_OUTBOX_DATABASE", "/outbox/outbox.db"),
        allowlist=allowlist,
        webhooks=webhooks,
        webhook_secrets=secrets_by_name,
        max_attempts=max_attempts,
        smtp=smtp,
        relay_token=relay_token,
        relay_port=_integer("SOCIFY_EGRESS_RELAY_PORT", 8081),
    )
