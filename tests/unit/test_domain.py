import json
import socket
from datetime import UTC, datetime

import pytest

from socify.detection import RuleValidationError, _condition_matches, _leaf_matches, validate_dsl
from socify.hunting import QueryError, _ioc_type, compile_query
from socify.ingestion import _decode, _depth, _detect_format, _priority_severity, parse_records
from socify.security import password_error, redact, safe_external_endpoint, totp_code, verify_totp
from socify.timeutils import iso_timestamp, parse_timestamp


@pytest.mark.parametrize(
    ("operator", "actual", "expected", "matched"),
    [
        ("equals", "FAILED_LOGIN", "failed_login", True),
        ("not_equals", "success", "failed", True),
        ("contains", "Synthetic PowerShell", "powershell", True),
        ("not_contains", "safe process", "malware", True),
        ("starts_with", "powershell.exe", "power", True),
        ("ends_with", "invoice.docm", ".docm", True),
        ("in", "high", ["high", "critical"], True),
        ("gt", 91, 90, True),
        ("gte", "0.8", 0.8, True),
        ("lt", 1, 2, True),
        ("lte", 2, 2, True),
        ("cidr", "198.51.100.20", "198.51.100.0/24", True),
        ("exists", "value", True, True),
        ("boolean", True, True, True),
    ],
)
def test_detection_leaf_operators(operator: str, actual: object, expected: object, matched: bool) -> None:
    result, trace = _leaf_matches({"field": "source", "operator": operator, "value": expected}, {"source": actual})
    assert result is matched
    assert trace["actual"] == actual
    assert trace["matched"] is matched


def test_detection_nested_logic_and_normalized_field_lookup() -> None:
    event = {"severity": "high", "normalized_fields": json.dumps({"anomaly_score": 0.91})}
    condition = {
        "logic": "and",
        "conditions": [
            {"field": "severity", "operator": "equals", "value": "high"},
            {"logic": "not", "conditions": [{"field": "anomaly_score", "operator": "lt", "value": 0.8}]},
        ],
    }
    matched, trace = _condition_matches(condition, event)
    assert matched is True
    assert len(trace["children"]) == 2


def test_rule_validation_normalizes_dsl() -> None:
    dsl = validate_dsl(
        {
            "logic": "and",
            "conditions": [{"field": "event_type", "operator": "equals", "value": "failed_login"}],
            "window": {"seconds": 600, "threshold": 5, "group_by": ["source_ip"], "mode": "count"},
            "mitre_ids": ["T1110"],
        }
    )
    assert dsl["condition"]["logic"] == "and"
    assert "logic" not in dsl


@pytest.mark.parametrize(
    "dsl",
    [
        {"condition": {"field": "unsupported", "operator": "equals", "value": "x"}},
        {"condition": {"field": "source_ip", "operator": "cidr", "value": "not-a-network"}},
        {"condition": {"field": "event_type", "operator": "sql", "value": "x"}},
        {"condition": {"logic": "not", "conditions": []}},
        {"condition": {"field": "event_type", "operator": "equals", "value": "x"}, "window": {"seconds": 0, "threshold": 0}},
    ],
)
def test_rule_validation_rejects_unsafe_or_invalid_dsl(dsl: dict[str, object]) -> None:
    with pytest.raises(RuleValidationError):
        validate_dsl(dsl)


def test_hunt_query_compiler_is_parameterized() -> None:
    compiled = compile_query('source_ip=198.51.100.20 AND event_type="failed_login"')
    assert compiled.sql.count("?") == 2
    assert compiled.parameters == ["198.51.100.20", "failed_login"]
    assert "198.51.100.20" not in compiled.sql


@pytest.mark.parametrize(
    "query",
    [
        "unknown=value",
        "source_ip=198.51.100.20;DELETE",
        "source_ip = ' OR 1=1",
        "http_status=not-a-number",
        "(" * 7 + "source=x" + ")" * 7,
    ],
)
def test_hunt_query_rejects_invalid_tokens(query: str) -> None:
    with pytest.raises(QueryError):
        compile_query(query)


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        ("198.51.100.20", ("ip", "198.51.100.20")),
        ("2001:db8::1", ("ip", "2001:db8::1")),
        ("HTTPS://PHISH-TRAINING.TEST/path", ("url", "https://phish-training.test/path")),
        ("phish-training.test", ("domain", "phish-training.test")),
        ("a" * 64, ("sha256", "a" * 64)),
        ("not an indicator", None),
    ],
)
def test_ioc_normalization(candidate: str, expected: tuple[str, str] | None) -> None:
    assert _ioc_type(candidate) == expected


def test_timestamp_normalization_requires_timezone() -> None:
    assert iso_timestamp("2026-10-19T10:00:00+03:00") == "2026-10-19T07:00:00Z"
    assert parse_timestamp(0) == datetime(1970, 1, 1, tzinfo=UTC)
    with pytest.raises(ValueError):
        parse_timestamp("2026-10-19T10:00:00")


def test_totp_validation_and_password_policy() -> None:
    totp_seed = "JBSWY3DPEHPK3PXP"
    code = totp_code(totp_seed, 1700000000)
    assert verify_totp(totp_seed, code, 1700000000)
    assert not verify_totp(totp_seed, "000000", 1700000000)
    assert password_error("short")
    assert password_error("password1234")
    assert password_error("Long-Unique-Training-Password-2026") is None


def test_redaction_recurses_without_mutating_shape() -> None:
    value = {"credential": "private", "nested": [{"token": "secret", "label": "safe"}]}
    assert redact(value) == {"credential": "[REDACTED]", "nested": [{"token": "[REDACTED]", "label": "safe"}]}


def test_safe_external_endpoint_enforces_https_allowlist_and_public_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])
    assert safe_external_endpoint("https://sandbox.example/path", {"sandbox.example"}) == (True, "ok")
    assert safe_external_endpoint("http://sandbox.example", {"sandbox.example"})[0] is False
    assert safe_external_endpoint("https://other.example", {"sandbox.example"})[0] is False
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))])
    assert safe_external_endpoint("https://sandbox.example", {"sandbox.example"})[0] is False


def test_import_detection_and_parser_boundaries(app) -> None:
    with app.app_context():
        assert _detect_format("events.csv", b"source,event_type\nlab,test") == "csv"
        assert _detect_format("events.jsonl", b'{"event_type":"test"}\n') == "jsonl"
        assert _detect_format("events.xml", b"<Event />") == "sysmon_xml"
        assert _priority_severity(2) == "critical"
        assert _priority_severity(5) == "low"
        assert _depth({"a": [{"b": 1}]}) == 3
        format_name, records = parse_records("events.json", b'[{"event_type":"test","source":"fixture"}]', "auto", "fixture")
        parsed = list(records)
    assert format_name == "json"
    assert parsed[0]["event_type"] == "test"
    assert parsed[0]["provenance"]["format"] == "structured"


def test_xml_entity_declaration_is_rejected(app) -> None:
    content = b'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><Event>&xxe;</Event>'
    with app.app_context(), pytest.raises(ValueError, match="entities are not allowed"):
        _, records = parse_records("event.xml", content, "sysmon_xml", "fixture")
        list(records)


@pytest.mark.parametrize(
    ("filename", "content", "selected_format", "expected_format", "expected_type"),
    [
        ("events.csv", b"source,event_type,title\nfixture,test,CSV event\n", "csv", "csv", "test"),
        ("events.jsonl", b'\n{"event_type":"json_line","source":"fixture"}\n', "jsonl", "jsonl", "json_line"),
        ("events.json", b'{"event_type":"json_object","source":"fixture"}', "json", "json", "json_object"),
        ("events.log", b"<34>1 2026-10-19T10:00:00Z host app 1 ID47 - message", "syslog", "syslog", "syslog"),
        ("legacy.log", b"<34>Oct 19 10:00:00 host sshd[1]: Accepted publickey for analyst from 198.51.100.2", "syslog", "syslog", "syslog"),
        ("access.log", b'198.51.100.2 - analyst [19/Oct/2026:10:00:00 +0000] "GET /training HTTP/1.1" 200 12', "web", "web", "web_request"),
        ("auth.log", b"Oct 19 10:00:00 host sshd[1]: Failed password for analyst from 198.51.100.2", "linux_auth", "linux_auth", "failed_login"),
        (
            "event.xml",
            b'<Event><System><EventID>1</EventID><Computer>host</Computer><TimeCreated SystemTime="2026-10-19T10:00:00Z"/></System><EventData><Data Name="Image">cmd.exe</Data></EventData></Event>',
            "sysmon_xml",
            "sysmon_xml",
            "sysmon_1",
        ),
    ],
)
def test_supported_import_parsers(app, filename: str, content: bytes, selected_format: str, expected_format: str, expected_type: str) -> None:
    with app.app_context():
        format_name, records = parse_records(filename, content, selected_format, "fixture")
        parsed = list(records)
    assert format_name == expected_format
    assert parsed[0]["event_type"] == expected_type


def test_import_parser_negative_boundaries(app) -> None:
    with pytest.raises(ValueError, match="binary"):
        _decode(b"bad\x00text")
    with pytest.raises(ValueError, match="UTF-8"):
        _decode(b"\xff\xfe")
    with app.app_context():
        for filename, content, selected_format in (
            ("bad.csv", b"", "csv"),
            ("bad.json", b"[1]", "json"),
            ("bad.jsonl", b"[]", "jsonl"),
            ("bad.log", b"not syslog", "syslog"),
            ("bad.access", b"not a web log", "web"),
            ("bad.auth", b"not an auth log", "linux_auth"),
            ("bad.data", b"content", "unsupported"),
        ):
            with pytest.raises((ValueError, json.JSONDecodeError, StopIteration)):
                _, records = parse_records(filename, content, selected_format, "fixture")
                list(records)
        nested: object = {"value": 1}
        for _ in range(14):
            nested = {"next": nested}
        with pytest.raises(ValueError, match="nesting"):
            _, records = parse_records("deep.json", json.dumps(nested).encode(), "json", "fixture")
            list(records)
