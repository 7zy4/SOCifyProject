import os
import secrets
import tempfile
from contextlib import suppress
from pathlib import Path


def prepare(destination: Path = Path("instance/codespaces.env")) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        values = {
            "SOCIFY_SECRET_KEY": secrets.token_urlsafe(48),
            "SOCIFY_CREDENTIAL_KEY": secrets.token_urlsafe(48),
        }
        # Publish a complete private file without replacing another startup's keys.
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent, delete=False) as pending:
            temporary = Path(pending.name)
            try:
                pending.write("".join(f"{key}={value}\n" for key, value in values.items()))
                pending.flush()
                os.fsync(pending.fileno())
                with suppress(FileExistsError):
                    os.link(temporary, destination)
            finally:
                temporary.unlink()
    return destination


if __name__ == "__main__":
    prepare()
