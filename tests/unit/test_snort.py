import json

import pytest

from socify.events import normalize_event
from socify.ingestion import _mapped_records, _record_from_mapping
from socify.telemetry import profile


def snort(**changes):
    return {
        "timestamp": "11/02-02:21:00.153899",
        "seconds": 1793586060,
        "pkt_num": 5,
        "proto": "TCP",
        "src_ap": "192.0.2.10:50284",
        "dst_ap": "198.51.100.20:443",
        "rule": "1:1000000:2",
        "priority": 1,
        "action": "would_drop",
        "msg": "Suspicious request to application endpoint",
        "class": "Attempted User Privilege Gain",
        **changes,
    }


def test_native_network_alert_normalization_and_unchanged_evidence():
    original = snort()
    parsed = _record_from_mapping(original, 1, "alert_json.txt", "fingerprint")
    event = normalize_event(parsed)
    assert parsed["raw_payload"] == original
    assert json.loads(event["raw_data"]) == original
    assert event["source_type"] == "snort" and event["severity"] == "high"
    assert event["source_ip"] == "192.0.2.10" and event["destination_ip"] == "198.51.100.20"
    assert event["hostname"] is None and event["action"] == "would_drop"
    assert parsed["normalized_fields"]["destination_port"] == 443
    assert parsed["normalized_fields"]["event_time_known"] is True


@pytest.mark.parametrize("priority,severity", [(None, "medium"), (0, "medium"), (1, "high"), (2, "medium"), (3, "low"), (4, "low")])
def test_priorities_and_unclassified_alerts(priority, severity):
    assert profile(snort(priority=priority))["severity"] == severity


def test_default_yearless_time_is_not_presented_as_observed_time():
    record = snort()
    del record["seconds"]
    parsed = _record_from_mapping(record, 1, "snort.json", "hash")
    mapped = next(_mapped_records([parsed], {"source_timezone": "UTC"}, "Snort"))
    assert mapped["normalized_fields"]["event_time_known"] is False
    assert mapped["normalized_fields"]["source_timestamp"] == record["timestamp"]
    exact = profile(snort(seconds=None, timestamp="2026-11-02T02:21:00Z"))
    assert exact["normalized_fields"]["event_time_known"] is True


def test_ipv6_and_separate_endpoint_fields():
    parsed = profile(snort(src_ap="2001:db8::1:1234", dst_ap="[2001:db8::2]:443"))
    assert parsed["source_ip"] == "2001:db8::1" and parsed["destination_ip"] == "2001:db8::2"
    parsed = profile(snort(src_addr="192.0.2.2", src_port=80))
    assert parsed["source_ip"] == "192.0.2.2" and parsed["normalized_fields"]["source_port"] == 80


@pytest.mark.parametrize(
    "changes",
    [
        {"rule": "not-a-rule"},
        {"rule": "1:4294967296:1"},
        {"rule": {}},
        {"src_ap": "evil.example:80"},
        {"src_ap": "192.0.2.1:"},
        {"dst_ap": "192.0.2.1:65536"},
        {"src_port": True},
        {"priority": -1},
        {"priority": 1.5},
        {"pkt_num": -1},
        {"proto": "x" * 21},
        {"msg": "x" * 4001},
        {"seconds": float("inf")},
        {"seconds": -1},
        {"timestamp": "2026-99-99T02:21:00Z", "seconds": None},
    ],
)
def test_invalid_sensor_fields_are_rejected(changes):
    with pytest.raises(ValueError):
        profile(snort(**changes))
