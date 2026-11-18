"""Static links carry a content fingerprint; only a request for the current fingerprint may be cached for a year."""

import os
import re
from pathlib import Path

from flask import Flask

from socify.static_assets import register_static_fingerprints

ROOT = Path(__file__).resolve().parents[2]
IMMUTABLE = "public, max-age=31536000, immutable"


def test_every_page_link_to_a_static_file_is_fingerprinted_and_long_lived(client):
    page = client.get("/login").get_data(as_text=True)
    links = re.findall(r'(?:href|src)="(/static/[^"]+)"', page)
    assert links
    for link in links:
        assert re.search(r"\?v=[0-9a-f]{16}$", link), link
        response = client.get(link)
        assert response.status_code == 200 and response.headers["Cache-Control"] == IMMUTABLE, link


def test_unversioned_and_stale_requests_revalidate(client):
    for path in ("/static/app.js", "/static/app.js?v=0000000000000000", "/static/app.js?v="):
        response = client.get(path)
        assert response.status_code == 200 and response.headers["Cache-Control"] == "no-cache", path
    assert client.get("/static/missing.js").status_code == 404


def test_a_revalidated_current_version_stays_long_lived(app, client):
    with app.test_request_context():
        from flask import url_for

        link = url_for("static", filename="app.js")
    first = client.get(link)
    again = client.get(link, headers={"If-None-Match": first.headers["ETag"]})
    assert again.status_code == 304 and again.headers["Cache-Control"] == IMMUTABLE


def test_fingerprint_follows_the_content_and_never_leaves_the_static_folder(tmp_path):
    static = tmp_path / "static"
    static.mkdir()
    (tmp_path / "secret.txt").write_text("outside", encoding="utf-8")
    asset = static / "a.js"
    asset.write_text("one", encoding="utf-8")
    app = Flask(__name__, static_folder=str(static))
    register_static_fingerprints(app)
    with app.test_request_context():
        from flask import url_for

        before = url_for("static", filename="a.js")
        asset.write_text("two!", encoding="utf-8")
        os.utime(asset, ns=(asset.stat().st_atime_ns, asset.stat().st_mtime_ns + 10_000_000))
        after = url_for("static", filename="a.js")
        outside = url_for("static", filename="../secret.txt")
    assert before != after and "?v=" in after
    assert "v=" not in outside
    client = app.test_client()
    assert client.get(before).headers["Cache-Control"] == "no-cache"
    assert client.get(after).headers["Cache-Control"] == IMMUTABLE


def test_templates_link_static_files_only_through_url_for():
    hardcoded = {path.name: re.findall(r'(?:href|src)="/static/', path.read_text(encoding="utf-8")) for path in (ROOT / "templates").glob("*.html")}
    assert not {name: found for name, found in hardcoded.items() if found}


def test_ingress_marks_compressed_static_files_as_varying_by_encoding():
    config = (ROOT / "deploy" / "nginx.conf").read_text(encoding="utf-8")
    block = config[config.index("location ^~ /static/") : config.index("location / {")]
    assert "gzip on;" in block and "gzip_vary on;" in block


def test_a_signed_in_static_response_never_carries_the_session_cookie(app, client, login_as):
    # A long-lived public response with Set-Cookie would let a shared cache hand this user's session to others.
    login_as("analyst")
    with app.test_request_context():
        from flask import url_for

        link = url_for("static", filename="app.js")
    static = client.get(link)
    assert static.headers["Cache-Control"] == IMMUTABLE
    assert "Set-Cookie" not in static.headers
    page = client.get("/cases")
    assert page.status_code == 200 and "Set-Cookie" in page.headers  # pages still refresh the session as before
