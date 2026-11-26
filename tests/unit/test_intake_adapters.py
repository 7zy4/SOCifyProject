"""Each intake adapter maps its vendor's documented alert shape onto the normalised alert, and drops what does not fit."""

import json
from pathlib import Path

import pytest

from socify.intake import ADAPTERS

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "intake"
EMPTY_FILE_MD5 = "d41d8cd98f00b204e9800998ecf8427e"  # pragma: allowlist secret - the public MD5 of an empty file


def _normalized(kind):
    adapter = ADAPTERS[kind]
    return [adapter.normalize(item) for item in adapter.items(json.loads((FIXTURES / f"{kind}.json").read_text(encoding="utf-8")))]


def test_wazuh():
    [alert] = _normalized("wazuh")
    assert alert["external_id"] == "1763626502.1234567" and alert["severity"] == "medium" and alert["rule_id"] == "5712"
    assert alert["time"] == "2026-11-20T08:15:02.123000Z" and alert["mitre"] == ["T1110"]
    assert alert["entities"]["hosts"] == ["web-01"] and alert["entities"]["users"] == ["admin"]
    assert alert["entities"]["ips"] == ["192.0.2.10", "198.51.100.23"]


def test_elastic():
    [alert] = _normalized("elastic")
    assert alert["title"] == "Suspicious PowerShell encoded command" and alert["severity"] == "high"
    assert alert["time"] == "2026-11-20T08:59:41Z" and alert["mitre"] == ["T1059.001"]
    assert alert["entities"]["hosts"] == ["WS-07"] and alert["entities"]["ips"] == ["203.0.113.50", "192.0.2.77"]
    assert alert["entities"]["domains"] == ["update.example.net"] and len(alert["entities"]["hashes"]) == 1


def test_splunk():
    [alert] = _normalized("splunk")
    assert alert["title"] == "Excessive failed logins" and alert["severity"] == "critical" and alert["external_id"].startswith("scheduler__")
    assert (
        alert["entities"]["ips"] == ["198.51.100.77", "192.0.2.20"] and alert["entities"]["users"] == ["svc-backup"] and alert["entities"]["hosts"] == ["dc-01"]
    )


def test_sentinel():
    [alert] = _normalized("sentinel")
    assert alert["title"] == "Sign-in from an unfamiliar location" and alert["severity"] == "medium" and alert["time"] == "2026-11-20T10:01:00Z"
    assert alert["entities"] == {
        "hosts": ["LAPTOP-12"],
        "users": ["m.smith"],
        "ips": ["203.0.113.9"],
        "domains": ["login.example.org"],
        "urls": [],
        "hashes": [],
    }
    assert alert["mitre"] == ["T1078"]


def test_generic_validates_every_entity():
    [alert] = _normalized("generic")
    assert alert["severity"] == "critical" and alert["rule_name"] == "Mass file encryption" and alert["mitre"] == ["T1486"]
    assert alert["entities"]["ips"] == ["192.0.2.44"] and alert["entities"]["domains"] == ["pay.example.com"]
    assert alert["entities"]["urls"] == ["https://pay.example.com/ransom"] and alert["entities"]["hashes"] == [EMPTY_FILE_MD5]


@pytest.mark.parametrize("kind", list(ADAPTERS))
def test_hostile_or_empty_alerts_stay_bounded(kind):
    adapter = ADAPTERS[kind]
    alert = adapter.normalize({"title": "x" * 5000, "description": "\u0000<script>" * 2000, "rule": {"level": "high"}, "severity": {"nested": True}})
    assert len(alert["title"]) <= 255 and len(alert["description"]) <= 4000 and "\u0000" not in alert["description"]
    assert alert["severity"] in {"critical", "high", "medium", "low", "info"}
    empty = adapter.normalize({})
    assert empty["title"] == "Untitled alert" and empty["time"] is None and all(not values for values in empty["entities"].values())


def test_batch_wrappers_and_odd_shapes():
    assert len(ADAPTERS["elastic"].items([{"a": 1}, {"b": 2}])) == 2
    assert len(ADAPTERS["wazuh"].items([{"id": "1"}])) == 1 and len(ADAPTERS["wazuh"].items({"alerts": [{}, {}]})) == 2
    assert len(ADAPTERS["generic"].items([{"id": "1"}])) == 1
    assert len(ADAPTERS["splunk"].items([{"sid": "1"}, {"sid": "2"}])) == 2
    assert len(ADAPTERS["sentinel"].items({"value": [{}, {}, {}]})) == 3
    broken = ADAPTERS["sentinel"].normalize({"properties": {"title": "Incident", "severity": "High", "relatedEntities": "{not json"}})
    assert broken["title"] == "Incident" and broken["severity"] == "high" and broken["entities"]["hosts"] == []
    listed = ADAPTERS["sentinel"].normalize(
        {"AlertName": "A", "Entities": [{"Type": "url", "Url": "https://x.example/a"}, {"Type": "filehash", "Value": "a" * 64}, "skip"]}
    )
    assert listed["entities"]["urls"] == ["https://x.example/a"] and listed["entities"]["hashes"] == ["a" * 64]
