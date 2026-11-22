"""Content fingerprints on static file links, so a browser keeps each version for a year and fetches a file again only
when its content changes.

``url_for("static", filename=...)`` gains ``?v=<first 16 hex digits of the file's SHA-256>``. A request carrying the
fingerprint of the file as it is now is answered as immutable for a year; a request without one, or with the fingerprint
of an older version, keeps the default of revalidating with the ETag, so a stale copy is never pinned in a browser.
"""

import hashlib
import os

from flask import Flask, Response, request
from flask.sessions import SecureCookieSessionInterface

ONE_YEAR = 31536000


class _NoCookieOnStaticFiles(SecureCookieSessionInterface):
    """Never refresh the session cookie on a static file: such a response may be cached publicly for a year, and a
    shared cache that stored it with Set-Cookie would hand the signed-in user's session to everyone it serves."""

    def should_set_cookie(self, app: Flask, session) -> bool:
        return request.endpoint != "static" and super().should_set_cookie(app, session)


def register_static_fingerprints(app: Flask) -> None:
    app.session_interface = _NoCookieOnStaticFiles()
    root = os.path.realpath(str(app.static_folder))
    # The trailing separator keeps a sibling such as "static-other" from passing as part of "static".
    inside_root = os.path.join(root, "")
    known: dict[str, tuple[int, int, str]] = {}

    def fingerprint(filename: str) -> str | None:
        # The name can come from the request path: resolve "..", absolute paths and symbolic links first, then
        # accept only a file that is still inside the static folder.
        path = os.path.realpath(os.path.join(root, filename))
        if not path.startswith(inside_root):
            return None
        try:
            stat = os.stat(path)
            cached = known.get(path)
            if cached is None or cached[:2] != (stat.st_mtime_ns, stat.st_size):
                with open(path, "rb") as file:
                    cached = (stat.st_mtime_ns, stat.st_size, hashlib.sha256(file.read()).hexdigest()[:16])
                known[path] = cached
        except OSError:
            return None
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
