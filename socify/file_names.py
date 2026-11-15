"""Safe display names; evidence bytes never use client names as storage paths."""

import hashlib
import re
import unicodedata
from pathlib import PurePosixPath
from urllib.parse import quote

from werkzeug.utils import secure_filename


def evidence_filename(value: str, content: bytes, prefix: str = "evidence") -> str:
    original = PurePosixPath(value.replace("\\", "/")).name
    suffix = PurePosixPath(original).suffix
    if not re.fullmatch(r"\.[A-Za-z0-9]{1,12}", suffix):
        suffix = ""
    stem = secure_filename(original[: -len(suffix)] if suffix else original)
    if not stem:
        stem = f"{prefix}-{hashlib.sha256(content).hexdigest()[:16]}"
    # Sanitize the complete name as well (including platform-reserved stems).
    return secure_filename(stem[: 255 - len(suffix)] + suffix)


def attachment_disposition(filename: str) -> str:
    """Content-Disposition for a download: a quoted ASCII name, plus the RFC 5987 UTF-8 form when they differ.

    Quotes, backslashes and control characters cannot reach the header, whatever the stored name contains.
    """
    plain = unicodedata.normalize("NFKD", filename).encode("ascii", "ignore").decode("ascii")
    plain = re.sub(r"[^A-Za-z0-9._ -]", "_", plain).strip(" .") or "download"
    value = f'attachment; filename="{plain}"'
    if plain != filename:
        value += f"; filename*=UTF-8''{quote(filename, safe='')}"
    return value
