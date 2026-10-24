import secrets
from pathlib import Path


def prepare(destination: Path = Path("instance/codespaces.env")) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        values = {
            "SOCIFY_SECRET_KEY": secrets.token_urlsafe(48),
            "SOCIFY_CREDENTIAL_KEY": secrets.token_urlsafe(48),
        }
        destination.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")
        destination.chmod(0o600)
    return destination


if __name__ == "__main__":
    prepare()
