"""Internal Prometheus metrics: counts and ages read from SQLite, with labels from fixed sets only."""

import re
from pathlib import Path

LINE = re.compile(r'^(?:# (?:HELP|TYPE) socify_[a-z_]+ .+|socify_[a-z_]+(?:\{(?:state|queue)="[a-z_]+"\})? -?[0-9.e+]+)$')


def _metrics(client):
    response = client.get("/health/metrics")
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "text/plain; version=0.0.4; charset=utf-8"
    assert response.headers["Cache-Control"] == "no-store"
    return response.get_data(as_text=True)


def _value(text, sample):
    return float(next(line.rsplit(" ", 1)[1] for line in text.splitlines() if line.startswith(sample + " ")))


def test_metrics_are_well_formed_counts_without_sign_in(client):
    text = _metrics(client)
    assert all(LINE.match(line) for line in text.splitlines()), [line for line in text.splitlines() if not LINE.match(line)]
    assert _value(text, "socify_schema_version") >= 1
    assert _value(text, "socify_database_bytes") > 0
    for family in ("socify_import_jobs", "socify_analysis_jobs", "socify_expired_leases", "socify_active_sessions"):
        assert f"# TYPE {family} gauge" in text


def test_stored_text_never_becomes_a_label(app, client, database, login_as):
    login_as("analyst")
    queued = client.post("/api/imports", json={"filename": "metrics.jsonl", "content": '{"title":"metrics probe"}\n'})
    assert queued.status_code in {201, 202}
    database.execute("UPDATE ingestion_jobs SET status = ? WHERE id = ?", ('state"} 1\nsocify_injected 9 #', queued.json["id"]))
    text = _metrics(client)
    assert "socify_injected" not in text and "metrics.jsonl" not in text and "metrics probe" not in text
    assert _value(text, 'socify_import_jobs{state="other"}') == 1
    assert _value(text, "socify_active_sessions") >= 1


def test_metrics_are_refused_by_the_ingress():
    config = (Path(__file__).parents[2] / "deploy" / "nginx.conf").read_text(encoding="utf-8")
    block = re.search(r"location \^~ /health/metrics \{\s*return 404;\s*\}", config)
    assert block and block.start() < config.index("location / {")
