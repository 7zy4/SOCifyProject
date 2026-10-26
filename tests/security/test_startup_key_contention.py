import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from scripts.prepare_codespace import prepare


def test_concurrent_startups_observe_complete_identical_private_keys(tmp_path):
    destination = tmp_path / "instance" / "codespaces.env"

    def startup(_):
        return prepare(destination).read_text()

    with ThreadPoolExecutor(max_workers=8) as workers:
        contents = list(workers.map(startup, range(32)))
    assert len(set(contents)) == 1
    values = dict(line.split("=", 1) for line in contents[0].splitlines())
    assert set(values) == {"SOCIFY_SECRET_KEY", "SOCIFY_CREDENTIAL_KEY"}
    assert all(len(value) >= 32 for value in values.values())
    assert destination.stat().st_mode & 0o777 == 0o600
    assert list(destination.parent.iterdir()) == [destination]


def test_startup_preserves_file_created_before_publication(tmp_path, monkeypatch):
    destination = tmp_path / "codespaces.env"
    link = os.link

    def competing_startup(source, target):
        Path(target).write_text("existing keys must survive\n")
        link(source, target)

    monkeypatch.setattr(os, "link", competing_startup)
    assert prepare(destination).read_text() == "existing keys must survive\n"
    assert list(tmp_path.iterdir()) == [destination]
