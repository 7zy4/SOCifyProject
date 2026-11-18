"""Internal Prometheus metrics: counts and ages read from SQLite, with labels from fixed sets only."""

import re
import secrets
from pathlib import Path

import pytest

from socify.config import build_config

LINE = re.compile(r'^(?:# (?:HELP|TYPE) socify_[a-z_]+ .+|socify_[a-z_]+(?:\{(?:state|queue)="[a-z_]+"\})? -?[0-9.e+]+)$')


@pytest.fixture
def metrics_token(app):
    token = secrets.token_urlsafe(32)
    app.config["METRICS_TOKEN"] = token
    return token


def _metrics(client, token):
    response = client.get("/health/metrics", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "text/plain; version=0.0.4; charset=utf-8"
    assert response.headers["Cache-Control"] == "no-store"
    return response.get_data(as_text=True)


def _value(text, sample):
    return float(next(line.rsplit(" ", 1)[1] for line in text.splitlines() if line.startswith(sample + " ")))


def test_metrics_are_well_formed_counts_with_the_token_and_no_sign_in(client, metrics_token):
    text = _metrics(client, metrics_token)
    assert all(LINE.match(line) for line in text.splitlines()), [line for line in text.splitlines() if not LINE.match(line)]
    assert _value(text, "socify_schema_version") >= 1
    assert _value(text, "socify_database_bytes") > 0
    for family in ("socify_import_jobs", "socify_analysis_jobs", "socify_expired_leases", "socify_active_sessions"):
        assert f"# TYPE {family} gauge" in text


def test_stored_text_never_becomes_a_label(autopsy_case, client, database, metrics_token):
    queued = client.post(f"/api/cases/{autopsy_case}/imports", json={"filename": "metrics.jsonl", "content": '{"title":"metrics probe"}\n'})
    assert queued.status_code in {201, 202}
    database.execute("UPDATE ingestion_jobs SET status = ? WHERE id = ?", ('state"} 1\nsocify_injected 9 #', queued.json["id"]))
    text = _metrics(client, metrics_token)
    assert "socify_injected" not in text and "metrics.jsonl" not in text and "metrics probe" not in text
    assert _value(text, 'socify_import_jobs{state="other"}') == 1
    assert _value(text, "socify_active_sessions") >= 1


def test_metrics_are_refused_by_the_ingress():
    config = (Path(__file__).parents[2] / "deploy" / "nginx.conf").read_text(encoding="utf-8")
    block = re.search(r"location \^~ /health/metrics \{\s*return 404;\s*\}", config)
    assert block and block.start() < config.index("location / {")


def test_metrics_do_not_exist_until_a_token_is_configured(app, client):
    assert app.config["METRICS_TOKEN"] is None
    for headers in ({}, {"Authorization": "Bearer anything"}):
        response = client.get("/health/metrics", headers=headers)
        assert response.status_code == 404
        assert response.get_data(as_text=True) == client.get("/health/no-such-path").get_data(as_text=True)


@pytest.mark.parametrize(
    "header",
    [None, "", "Bearer", "Bearer ", "Basic {token}", "Bearer {token}x", "Bearer x{token}", "Token {token}", "bearer{token}"],
)
def test_metrics_refuse_a_missing_or_wrong_token_without_counts(client, metrics_token, header):
    headers = {} if header is None else {"Authorization": header.format(token=metrics_token)}
    response = client.get("/health/metrics", headers=headers)
    assert response.status_code == 401
    assert response.json["error"]["code"] == "METRICS_TOKEN_REQUIRED"
    assert response.headers["WWW-Authenticate"].startswith("Bearer")
    assert "socify_" not in response.get_data(as_text=True) and metrics_token not in response.get_data(as_text=True)


def test_metrics_accept_the_scheme_in_any_case(client, metrics_token):
    assert client.get("/health/metrics", headers={"Authorization": f"bearer {metrics_token}"}).status_code == 200


@pytest.mark.parametrize("value, expected", [("", None), ("   ", None), ("x" * 32, "x" * 32)])
def test_metrics_token_setting(monkeypatch, value, expected):
    monkeypatch.setenv("SOCIFY_METRICS_TOKEN", value)
    assert build_config()["METRICS_TOKEN"] == expected


def test_short_metrics_token_stops_start_up(monkeypatch):
    monkeypatch.setenv("SOCIFY_METRICS_TOKEN", "x" * 31)
    with pytest.raises(RuntimeError, match="at least 32"):
        build_config()
