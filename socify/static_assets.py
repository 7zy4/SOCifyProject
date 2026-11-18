"""Content fingerprints on static file links, so a browser keeps each version for a year and fetches a file again only
when its content changes.

``url_for("static", filename=...)`` gains ``?v=<first 16 hex digits of the file's SHA-256>``. A request carrying the
fingerprint of the file as it is now is answered as immutable for a year; a request without one, or with the fingerprint
of an older version, keeps the default of revalidating with the ETag, so a stale copy is never pinned in a browser.
"""

import hashlib
from pathlib import Path

from flask import Flask, Response, request

ONE_YEAR = 31536000


def register_static_fingerprints(app: Flask) -> None:
    root = Path(str(app.static_folder)).resolve()
    known: dict[Path, tuple[int, int, str]] = {}

    def fingerprint(filename: str) -> str | None:
        path = (root / filename).resolve()
        if root not in path.parents:
            return None
        try:
            stat = path.stat()
        except OSError:
            return None
        cached = known.get(path)
        if cached is None or cached[:2] != (stat.st_mtime_ns, stat.st_size):
            cached = (stat.st_mtime_ns, stat.st_size, hashlib.sha256(path.read_bytes()).hexdigest()[:16])
            known[path] = cached
        return cached[2]

    @app.url_defaults
    def add_fingerprint(endpoint: str, values: dict[str, object]) -> None:
        filename = values.get("filename")
        if endpoint == "static" and "v" not in values and isinstance(filename, str):
            digest = fingerprint(filename)
            if digest:
                values["v"] = digest

    @app.after_request
    def cache_fingerprinted(response: Response) -> Response:
        if request.endpoint == "static" and response.status_code in {200, 304}:
            filename = (request.view_args or {}).get("filename")
            version = request.args.get("v")
            if version and isinstance(filename, str) and version == fingerprint(filename):
                response.headers["Cache-Control"] = f"public, max-age={ONE_YEAR}, immutable"
            else:
                response.headers["Cache-Control"] = "no-cache"
        return response
