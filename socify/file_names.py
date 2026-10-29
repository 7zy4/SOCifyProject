"""Safe display names; evidence bytes never use client names as storage paths."""

import hashlib
import re
from pathlib import PurePosixPath

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
