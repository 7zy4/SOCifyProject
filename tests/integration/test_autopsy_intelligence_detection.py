import json
import sqlite3
from datetime import timedelta

import pytest

from socify.autopsy_intel import convert_intelligence, lookup_local, normalize_entry
from socify.autopsy_worker import run_autopsy_worker_once
from socify.sigma_subset import compile_sigma, validate_fixtures
from socify.timeutils import utc_now

SIGMA = """title: Local suspicious log
description: Synthetic fixture rule, not threat coverage
logsource:
  category: socify_normalized
detection:
  selected:
    title|contains: Synthetic suspicious
  condition: selected
level: high
tags: [attack.t1059]
"""
FIXTURES = {"positive": [{"title": "Synthetic suspicious log"}], "negative": [{"title": "Synthetic routine log"}]}


def bundle(client, content, **options):
    return client.post(
        "/api/autopsy/intelligence",
        json={
            "name": "Synthetic internal feed",
            "version": "1",
            "source": "Internal synthetic acceptance",
            "license": "Synthetic test license",
            "expires_at": "2030-01-01T00:00:00Z",
            "format": "flat",
            "content": content,
            **options,
        },
    )


def test_local_intelligence_versioning_expiry_geoip_and_case_linkage(autopsy_case, app, client, login_as, database):
    login_as("soc_manager")
    content = [{"type": "ip", "value": "192.0.2.8", "verdict": "malicious", "confidence": 80}]
    created = bundle(client, content)
    assert created.status_code == 201, created.json
    identifier = created.json["id"]
    assert bundle(client, content).status_code == 409
    with app.app_context():
        assert lookup_local(1, "ip", "192.0.2.8")["status"] == "not_configured"
    assert client.post(f"/api/autopsy/intelligence/{identifier}/activate").status_code == 200
    geo = bundle(client, [{"type": "cidr", "value": "192.0.2.0/24", "country": "SA", "asn": 64500}], name="Synthetic GeoIP", format="geoip")
    assert geo.status_code == 201
    assert client.post(f"/api/autopsy/intelligence/{geo.json['id']}/activate").status_code == 200
    with app.app_context():
        result = lookup_local(1, "ip", "192.0.2.8")
        assert result["verdict"] == "malicious"
        assert {row["type"] for row in result["matches"]} == {"cidr", "ip"}
        assert all(row["license"] and row["source"] and row["sha256"] for row in result["matches"])
        assert lookup_local(1, "ip", "198.51.100.1")["status"] == "no_match"
        assert lookup_local(2, "ip", "192.0.2.8")["status"] == "not_configured"
    imported = client.post(
        f"/api/cases/{autopsy_case}/imports",
        json={"filename": "internal.json", "content": json.dumps([{"title": "Local finding", "source_ip": "192.0.2.8", "hostname": "host.example.test"}])},
    )
    assert imported.status_code == 201
    values = client.get(f"/api/cases/{autopsy_case}/observables").json["items"]
    ip = next(row for row in values if row["type"] == "ip")
    assert ip["enrichment"]["verdict"] == "malicious"
    assert ip["occurrences"] == 1
    enriched = client.post(f"/api/cases/{autopsy_case}/observables/{ip['id']}/enrich")
    assert enriched.status_code == 200
    assert enriched.json["payload"]["network"] == "offline-only"
    assert client.get("/api/autopsy/intelligence").json["items"][0]["active"] == 1
    for table in ("autopsy_intel_bundles", "autopsy_intel_entries"):
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            database.execute(f"DELETE FROM {table}")
    login_as("auditor")
    assert bundle(client, content).status_code == 403
    assert client.get(f"/api/cases/{autopsy_case}/observables").status_code == 404


@pytest.mark.parametrize(
    "entry",
    [
        {"type": "ip", "value": "invalid"},
        {"type": "domain", "value": "https://example.test"},
        {"type": "ip", "value": "192.0.2.1", "confidence": True},
        {"type": "ip", "value": "192.0.2.1", "country": "sa"},
        {"type": "cidr", "value": "192.0.2.0/24", "asn": 0},
        {"type": "ip", "value": "192.0.2.1", "valid_from": "2030-01-01"},
        {"type": "ip", "value": "192.0.2.1", "valid_from": "2030-01-01T00:00:00Z", "valid_until": "2026-01-01T00:00:00Z"},
        {"type": "unknown", "value": "test"},
        {"type": "sha256", "value": "invalid"},
        {"type": "ip", "value": "192.0.2.1", "verdict": []},
    ],
)
def test_intelligence_rejects_invalid_entries(entry):
    with pytest.raises(ValueError):
        normalize_entry(entry)


def test_stix_misp_bounded_import_and_validity(autopsy_case, app, client, login_as):
    login_as("soc_manager")
    stix = {
        "type": "bundle",
        "objects": [
            {"type": "identity"},
            {
                "type": "indicator",
                "pattern_type": "stix",
                "pattern": "[ipv4-addr:value = '192.0.2.8']",
                "valid_from": "2020-01-01T00:00:00Z",
                "valid_until": "2021-01-01T00:00:00Z",
            },
        ],
    }
    imported = bundle(client, stix, format="stix21")
    assert imported.status_code == 201
    client.post(f"/api/autopsy/intelligence/{imported.json['id']}/activate")
    with app.app_context():
        assert lookup_local(1, "ip", "192.0.2.8")["status"] == "no_match"
    misp = {"Event": {"Attribute": [{"type": "domain", "value": "EXAMPLE.TEST", "to_ids": True}]}}
    assert convert_intelligence(misp, "misp")[0]["value"] == "example.test"
    assert (
        convert_intelligence(
            {"type": "bundle", "objects": [{"type": "file", "hashes": {"MD5": "a" * 32}}, {"type": "domain-name", "value": "example.test"}]}, "stix21"
        )[0]["type"]
        == "md5"
    )
    for content, format_name in (
        ([], "flat"),
        ([{"type": "ip", "value": "192.0.2.1"}] * 2, "flat"),
        (misp, "geoip"),
        ({"type": "bundle", "objects": [{"type": "malware"}]}, "stix21"),
        ({"Event": {"Attribute": [{"type": "unsupported"}]}}, "misp"),
    ):
        with pytest.raises(ValueError):
            convert_intelligence(content, format_name)
    assert bundle(client, [], expires_at="2020-01-01T00:00:00Z").status_code == 422
    assert bundle(client, [], expires_at="2030-01-01").status_code == 422
    assert client.get(f"/api/cases/{autopsy_case}/observables?page=0").status_code == 422
    assert client.post("/api/autopsy/intelligence/999999/activate").status_code == 404


def test_sigma_publication_fixture_proof_backfill_and_alert_review(autopsy_case, app, client, login_as, database):
    base = f"/api/cases/{autopsy_case}"
    client.post(
        base + "/imports", json={"filename": "events.json", "content": json.dumps([{"title": "Synthetic suspicious log"}, {"title": "Synthetic routine log"}])}
    )
    login_as("soc_manager")
    prepared = {"source": SIGMA, "fixtures": FIXTURES, "reason": "Synthetic local rule validation"}
    assert client.post("/api/autopsy/sigma/compile", json=prepared).json["fixtures_passed"] is True
    published = client.post("/api/autopsy/sigma/publish", json=prepared)
    assert published.status_code == 201, published.json
    identifier = published.json["id"]
    assert client.get("/api/autopsy/sigma/rules").json["items"][0]["sha256"] == published.json["compiled"]["source_sha256"]
    revised = client.post("/api/autopsy/sigma/publish", json={**prepared, "rule_id": identifier, "version": 1})
    assert revised.status_code == 201 and revised.json["version"] == 2
    assert client.post("/api/autopsy/sigma/publish", json={**prepared, "rule_id": identifier, "version": 1}).status_code == 409
    queued = client.post(base + "/detection", json={"version": client.get(base).json["version"], "mode": "rules"})
    assert queued.status_code == 202
    with app.app_context():
        assert run_autopsy_worker_once() == queued.json["id"]
    assert client.get(base + f"/jobs/{queued.json['id']}").json["state"] == "completed"
    alerts = client.get(base + "/alerts").json["items"]
    assert len(alerts) == 1
    assert alerts[0]["evidence"]["event_ids"]
    assert alerts[0]["historical_derivation"] is False
    assert alerts[0]["review"]["group"].startswith("auto-")
    patch = {
        "version": 0,
        "verdict": "false_positive",
        "attack_outcome": "blocked",
        "group": "Synthetic cluster",
        "suppressed_until": (utc_now() + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "reason": "Expected synthetic fixture in authorized case",
    }
    path = base + f"/alerts/{alerts[0]['id']}"
    assert client.patch(path, json=patch).status_code == 200
    assert client.patch(path, json=patch).status_code == 409
    visible = client.get(base + "/alerts").json["items"][0]
    assert visible["suppressed"] and visible["review"]["attack_outcome"] == "blocked"
    assert visible["review"]["verdict"] == "false_positive"
    assert client.patch(path, json={**patch, "version": 1, "group": "", "suppressed_until": None}).status_code == 200
    assert client.get(base + "/alerts").json["items"][0]["review"]["group"] == ""
    assert client.get(base + "/custody").json["integrity_valid"] is True
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        database.execute("DELETE FROM autopsy_sigma_sources")
    login_as("analyst")
    assert client.post("/api/autopsy/sigma/publish", json=prepared).status_code == 403


@pytest.mark.parametrize(
    "source",
    [
        SIGMA.replace("title|contains", "title|re"),
        SIGMA.replace("condition: selected", "condition: 1 of selected*"),
        SIGMA.replace("condition: selected", "condition: unknown"),
        SIGMA.replace("condition: selected", "condition: selected()"),
        SIGMA + "title: duplicate\n",
        SIGMA.replace("category: socify_normalized", "product: unknown"),
        SIGMA.replace("Synthetic suspicious\n", "&anchor Synthetic suspicious\n"),
        "!!python/object/apply:os.system ['false']",
        SIGMA.replace("title|contains", "CommandLine"),
        SIGMA.replace("Synthetic suspicious\n", "*malicious*internal*\n"),
        SIGMA.replace("level: high", "level: []"),
        SIGMA.replace("selected:\n", "selected: []\nignored:\n"),
    ],
)
def test_sigma_rejects_unsupported_or_unsafe_syntax(source):
    with pytest.raises(ValueError):
        compile_sigma(source)


def test_sigma_subset_modifiers_and_fixtures():
    source = SIGMA.replace("title|contains: Synthetic suspicious", "title|contains|all: [Synthetic, suspicious]")
    validate_fixtures(compile_sigma(source), FIXTURES)
    sysmon = SIGMA.replace("category: socify_normalized", "product: windows\n  service: sysmon").replace("title|contains: Synthetic suspicious", "EventID: 1")
    validate_fixtures(
        compile_sigma(sysmon),
        {"positive": [{"source_type": "sysmon", "event_type": "sysmon_1"}], "negative": [{"source_type": "sysmon", "event_type": "sysmon_2"}]},
    )
    with pytest.raises(ValueError):
        validate_fixtures(compile_sigma(SIGMA), {"positive": FIXTURES["negative"], "negative": FIXTURES["positive"]})


def test_anomaly_reports_cold_start_and_evidenced_baseline(autopsy_case, app, client, database):
    base = f"/api/cases/{autopsy_case}"
    client.post(
        base + "/imports",
        json={"filename": "baseline.json", "content": json.dumps([{"title": "Routine", "source_ip": "192.0.2.1", "hostname": "host.example.test"}] * 20)},
    )
    original_ids = [
        row[0] for row in database.execute("SELECT id FROM security_events WHERE owner_case_id=? AND source!='rules_engine' ORDER BY id", (autopsy_case,))
    ]
    client.post(
        base + "/imports",
        json={"filename": "candidate.json", "content": '[{"title":"New observed pair","source_ip":"198.51.100.2","hostname":"host.example.test"}]'},
    )
    for after, expected in ((0, "insufficient_baseline"), (original_ids[-1], "evaluated")):
        queued = client.post(base + "/detection", json={"version": client.get(base).json["version"], "mode": "anomaly", "after_id": after})
        with app.app_context():
            run_autopsy_worker_once()
        job = database.execute("SELECT result,state FROM autopsy_jobs WHERE id=?", (queued.json["id"],)).fetchone()
        assert job["state"] == "completed"
        record = database.execute("SELECT payload FROM autopsy_records WHERE id=?", (json.loads(job["result"])["record_id"],)).fetchone()
        payload = json.loads(record[0])
        assert payload["status"] == expected
        assert len(payload["baseline_version"]) == 64
        if after:
            assert payload["baseline_events"] == 20 and len(payload["findings"]) == 1
