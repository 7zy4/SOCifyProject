"""The version reported by the running application is the newest release the changelog describes."""

import re
from pathlib import Path

from socify.version import VERSION

ROOT = Path(__file__).resolve().parents[2]


def test_version_is_semantic_and_is_the_newest_changelog_release():
    assert re.fullmatch(r"\d+\.\d+\.\d+", VERSION)
    releases = re.findall(r"^## \[(\d+\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}$", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), re.MULTILINE)
    assert releases and releases[0] == VERSION, releases


def test_liveness_reports_the_version(client):
    assert client.get("/health/live").json["version"] == VERSION
