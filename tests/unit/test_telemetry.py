import json

import pytest

from socify.ingestion import _detect_format, _record_from_mapping, _structured_records, _zeek_records, parse_records
from socify.network_insights import summarize_connections
from socify.telemetry import number, osquery_rows, profile


def zeek(index=0, **extra):
    return {
        "ts": 1790000000 + index * 60,
        "uid": f"C{index}",
        "id.orig_h": "10.0.0.2",
        "id.resp_h": "203.0.113.9",
        "id.orig_p": 50000 + index,
        "id.resp_p": 443,
        "proto": "tcp",
        "orig_bytes": 120,
        "resp_bytes": 30,
        "duration": 2,
        **extra,
    }


def test_zeek_eve_and_osquery_normalization_preserves_original(app):
    with app.app_context():
        raw = zeek(0, query="example.test")
        parsed = _record_from_mapping(raw, 1, "sensor-west", "hash")
        assert parsed["raw_payload"] == raw
        assert parsed["normalized_fields"]["bytes_sent"] == 120
        assert parsed["normalized_fields"]["flow_id"] == "C0"
        assert parsed["event_time"].endswith("Z") and parsed["source_type"] == "zeek"
        dns = profile({"ts": 1790000000, "uid": "D1", "id.orig_h": "10.0.0.2", "id.resp_h": "10.0.0.1", "query": "example.test"})
        assert dns["event_type"] == "zeek_dns" and dns["normalized_fields"]["connection_summary"] is False
        http = profile({"uid": "H", "id.orig_h": "10.0.0.2", "id.resp_h": "203.0.113.1", "method": "GET", "host": "site.test"})
        assert http["event_type"] == "zeek_http" and http["hostname"] == ""
        tls = profile({"uid": "T", "id.orig_h": "10.0.0.2", "id.resp_h": "203.0.113.1", "server_name": "site.test"})
        assert tls["event_type"] == "zeek_tls"
        eve = profile(
            {
                "flow_id": 2**58 + 11,
                "src_ip": "10.0.0.2",
                "dest_ip": "203.0.113.9",
                "event_type": "alert",
                "timestamp": "2026-01-01T00:00:00Z",
                "alert": {"signature": "Signature", "severity": 1, "signature_id": 42},
            }
        )
        assert eve["title"] == "Signature" and eve["severity"] == "high"
        assert eve["normalized_fields"]["flow_id"] == str(2**58 + 11)
        flow = profile(
            {
                "flow_id": 1,
                "src_ip": "10.0.0.2",
                "dest_ip": "203.0.113.9",
                "event_type": "flow",
                "timestamp": "2026-01-01T01:00:00Z",
                "flow": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T01:00:00Z", "bytes_toserver": 500},
            }
        )
        assert flow["event_time"] == "2026-01-01T00:00:00Z" and flow["normalized_fields"]["duration_seconds"] == 3600
        assert profile({"message": "ordinary log"}) == {}


@pytest.mark.parametrize("value", [True, -1, float("nan"), float("inf"), 1.2, 65536, {}, 10**400])
def test_invalid_ports_rejected(value):
    with pytest.raises(ValueError):
        profile(zeek(**{"id.resp_p": value}))


def test_numeric_missing_values_are_not_zero():
    assert number(None) is None and number("-") is None
    assert number("0", integral=True) == 0


@pytest.mark.parametrize("extra", [{"uid": "x" * 257}, {"proto": "x" * 33}, {"query": "x" * 513}, {"server_name": []}])
def test_network_grouping_fields_have_explicit_bounds(extra):
    with pytest.raises(ValueError, match="telemetry field"):
        profile(zeek(**extra))


@pytest.mark.parametrize("identifier", [None, True, {}, "", -1])
def test_invalid_flow_identifiers_cannot_correlate_unrelated_records(identifier):
    with pytest.raises(ValueError):
        profile(zeek(uid=identifier))
    with pytest.raises(ValueError):
        profile({"flow_id": identifier, "src_ip": "10.0.0.2", "dest_ip": "203.0.113.9", "event_type": "flow"})


def test_utf8_bom_does_not_hide_native_log_format():
    assert _detect_format("conn.log", b"\xef\xbb\xbf#separator \\x09\n") == "zeek_tsv"
    assert _detect_format("eve.log", b'\xef\xbb\xbf{"event_type":"flow"}\n') == "json"


def test_osquery_expansion_has_distinct_ids_and_source_pointers(app):
    original = {
        "hostIdentifier": "host-1",
        "name": "processes",
        "unixTime": 1790000000,
        "diffResults": {"added": [{"name": "shell", "pid": "12", "path": "/bin/sh", "cmdline": "sh -c echo"}], "removed": [{"pid": "11"}]},
    }
    with app.app_context():
        records = list(_structured_records(original, 5, "fleet-results", "digest"))
    assert len({row["idempotency_key"] for row in records}) == 2
    assert records[0]["provenance"]["row_pointer"] == "diffResults/added/0"
    assert records[0]["normalized_fields"]["query_name"] == "processes"
    assert records[0]["process_name"] == "shell" and records[0]["hostname"] == "host-1"
    assert records[1]["action"] == "removed"
    assert "diffResults" not in records[0]["raw_payload"]
    assert "columns" not in original
    snapshot = list(osquery_rows({"hostIdentifier": "h", "name": "q", "snapshot": []}))
    assert snapshot[0][0]["columns"] == {} and snapshot[0][0]["action"] == "snapshot"
    assert osquery_rows({"name": "q"}) is None
    assert osquery_rows({"name": "q", "hostIdentifier": "h"}) is None
    assert osquery_rows({"name": "q", "hostIdentifier": "h", "diffResults": {}})[0][0]["action"] == "unchanged"


@pytest.mark.parametrize(
    "body",
    [
        {"snapshot": {}},
        {"snapshot": [None]},
        {"snapshot": [{"nested": {}}]},
        {"snapshot": [{str(i): i for i in range(201)}]},
        {"diffResults": []},
        {"diffResults": {"bogus": []}},
        {"diffResults": {"added": {}}},
        {"columns": {}, "action": "other"},
        {"snapshot": [{}] * 10001},
    ],
)
def test_invalid_osquery_shapes_fail(body):
    with pytest.raises(ValueError):
        osquery_rows({"name": "q", "hostIdentifier": "h", **body})


def test_native_jsonl_log_autodetection_and_observed_times(app):
    body = "\n".join(json.dumps(zeek(index)) for index in range(2)).encode()
    with app.app_context():
        assert _detect_format("conn.log", body) == "jsonl"
        kind, stream = parse_records("conn.log", body, None, "sensor", {"source_timezone": "UTC"})
        rows = list(stream)
    assert kind == "jsonl" and len(rows) == 2
    assert all(row["normalized_fields"]["event_time_known"] for row in rows)


def test_zeek_tsv_header_types_and_escapes(app):
    body = "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.resp_h\tid.resp_p\torig_bytes\tlocal_orig\tservice\n#types\ttime\tstring\taddr\taddr\tport\tcount\tbool\tstring\n1790000000\tC1\t10.0.0.2\t203.0.113.9\t443\t0\tT\tssl\\x20tls\n"
    with app.app_context():
        kind, stream = parse_records("conn.log", body.encode(), None, "sensor", {"source_timezone": "UTC"})
        rows = list(stream)
    assert kind == "zeek_tsv" and rows[0]["raw_payload"]["service"] == "ssl tls"
    assert rows[0]["raw_payload"]["local_orig"] is True
    assert rows[0]["provenance"]["row"] == 4 and rows[0]["normalized_fields"]["bytes_sent"] == 0


@pytest.mark.parametrize("body", ["#separator xx\n", "#fields\ta\ta\n", "a\tb", "#fields\ta\n#types\tbool\nX\n"])
def test_malformed_zeek_headers_fail(body):
    with pytest.raises(ValueError):
        list(_zeek_records(body, "sensor", "digest"))


def connections(stamps=None):
    stamps = stamps or list(range(0, 600, 60))
    return [
        {
            "id": index + 1,
            "source": "sensor",
            "source_type": "zeek",
            "source_ip": "10.0.0.2",
            "destination_ip": "203.0.113.9",
            "event_time": f"2026-01-01T00:{stamp // 60:02d}:{stamp % 60:02d}Z",
            "fields": {
                "flow_id": str(index),
                "event_time_known": True,
                "connection_summary": True,
                "destination_port": 443,
                "protocol": "tcp",
                "bytes_sent": 100,
                "bytes_received": 50,
                "duration_seconds": 2,
            },
        }
        for index, stamp in enumerate(stamps)
    ]


def test_periodic_metrics_deduplicate_exported_flows_and_exclude_protocol_records():
    events = connections()
    events.append({**events[0], "id": 100})
    events.append(
        {**events[0], "id": 101, "fields": {"flow_id": "0", "connection_summary": False, "protocol": "tcp", "destination_port": 443, "tls_sni": "service.test"}}
    )
    result = summarize_connections(events)[0]
    assert result["connection_count"] == 10 and result["event_count"] == 12
    assert result["periodic"] and result["regularity_percent"] == 100 and result["median_interval_seconds"] == 60
    assert result["bytes_sent"] == 1000 and result["names"] == ["service.test"]
    assert result["interval_mad_seconds"] == 0


def test_irregular_short_missing_times_and_different_sensors_do_not_become_beacons():
    assert not summarize_connections(connections([0, 3, 80, 170, 300, 540]))[0]["periodic"]
    assert not summarize_connections(connections([0, 1, 2, 3, 4, 5]))[0]["periodic"]
    events = connections()
    for event in events:
        event["fields"]["event_time_known"] = False
        event["fields"].pop("bytes_sent")
        event["fields"].pop("bytes_received")
    result = summarize_connections(events)[0]
    assert not result["periodic"] and result["first_seen"] is None and result["bytes_sent"] is None
    assert len(summarize_connections([connections()[0], {**connections()[0], "source": "other-sensor"}])) == 2
    assert summarize_connections([{**connections()[0], "source_ip": "not-an-ip"}]) == []


def test_no_flow_summary_and_evidence_bounds():
    events = connections() * 6
    for event in events:
        event["fields"]["connection_summary"] = False
    result = summarize_connections(events)[0]
    assert result["events_truncated"] and len(result["event_ids"]) == 50
    assert result["connection_count"] == 0 and result["regularity_percent"] is None


def test_connection_time_bounds_use_instants_not_lexical_precision():
    events = connections()[:3]
    events[0]["event_time"] = "2026-01-01T00:00:00Z"
    events[1]["event_time"] = "2026-01-01T00:00:00.100000Z"
    events[2] = {**events[0], "id": 3, "event_time": "2026-01-01T00:00:00.000000Z"}
    result = summarize_connections(events)[0]
    assert result["connection_count"] == 2
    assert result["first_seen"] == events[0]["event_time"] and result["last_seen"] == events[1]["event_time"]
