import json

import pytest

from socify.detection import RuleValidationError, _condition_matches, _event_dict, _event_value, _leaf_matches, legacy_dsl, validate_dsl
from socify.events import normalize_event
from socify.hunting import QueryError, _ioc_type, compile_query
from socify.ingestion import _depth, _detect_format, _priority_severity, parse_records
from socify.timeutils import parse_timestamp

LEAF = {"field": "source", "operator": "equals", "value": "lab"}


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        {"condition": "bad"},
        {"condition": {"field": "source", "operator": "equals"}},
        {"condition": {"field": "source", "operator": "in", "value": "bad"}},
        {"condition": {"logic": "xor", "conditions": [LEAF]}},
        {"condition": {"logic": "not", "conditions": [LEAF, LEAF]}},
        {"condition": {"logic": "and", "conditions": [LEAF] * 21}},
        {"condition": {"logic": "and", "conditions": [{"logic": "or", "conditions": [LEAF] * 20}] * 2}},
        {"condition": LEAF, "window": []},
        {"condition": LEAF, "window": {"seconds": 1, "threshold": 1, "group_by": ["bad"]}},
        {"condition": LEAF, "window": {"seconds": 1, "threshold": 1, "mode": "bad"}},
        {"condition": LEAF, "window": {"seconds": 1, "threshold": 1, "mode": "distinct_count"}},
        {"condition": LEAF, "window": {"seconds": 1, "threshold": 1, "allowed_lateness_seconds": -1}},
        {"condition": LEAF, "sequence": []},
        {"condition": LEAF, "sequence": [LEAF, LEAF]},
        {"condition": LEAF, "mitre_ids": [123]},
    ],
)
def test_rule_budgets_and_schema_reject_invalid_definitions(value):
    with pytest.raises(RuleValidationError) as error:
        validate_dsl(value)
    assert error.value.errors


def test_rule_depth_budget_and_legacy_migration():
    nested = LEAF
    for _ in range(7):
        nested = {"logic": "and", "conditions": [nested]}
    with pytest.raises(RuleValidationError, match="nesting"):
        validate_dsl({"condition": nested})
    assert legacy_dsl({"condition_type": "failed_login_count", "condition_value": {"timeframe": "bad"}})["window"]["seconds"] == 600
    assert legacy_dsl({"condition_type": "network_anomaly", "condition_value": {"threshold": 0.9}})["condition"]["value"] == 0.9
    assert legacy_dsl({"condition_type": "error_level"})["condition"]["value"] == "critical"
    with pytest.raises(RuleValidationError, match="unsupported legacy"):
        legacy_dsl({"condition_type": "bad"})


@pytest.mark.parametrize(
    "operator,actual,expected,matched",
    [
        ("gt", True, 0, False),
        ("gt", "bad", 0, False),
        ("gt", "nan", 0, False),
        ("gt", 2, "inf", False),
        ("cidr", "bad", "192.0.2.0/24", False),
        ("contains", ["lab"], "lab", True),
        ("not_contains", ["lab"], "lab", False),
        ("boolean", "true", True, False),
        ("exists", None, False, True),
        ("in", "lab", [], False),
        ("equals", "lab", "other", False),
    ],
)
def test_detection_never_coerces_invalid_numbers_or_booleans(operator, actual, expected, matched):
    result, trace = _leaf_matches({"field": "source", "operator": operator, "value": expected}, {"source": actual})
    assert result is matched
    assert trace["matched"] is matched


def test_normalized_fields_fallback_is_safe():
    assert _event_value({"process_name": "cmd.exe"}, "process") == "cmd.exe"
    assert _event_value({"normalized_fields": "invalid"}, "source") is None
    assert _event_value({"normalized_fields": None}, "source") is None
    assert _condition_matches({"logic": "and", "conditions": None}, {})[0] is False
    row = _event_dict({"normalized_fields": "invalid", "tags": "invalid", "mitre_ids": "invalid"})
    assert row == {"normalized_fields": {}, "tags": [], "mitre_ids": []}


@pytest.mark.parametrize(
    "query",
    [
        "x" * 2001,
        " OR ".join(["source=x"] * 30),
        "source",
        "source =",
        "source = x source = y",
        "NOT",
        "(source=x source=y)",
        "source AND x",
        "source = AND",
        'source="\\q"',
        "mitre_id != T1110",
    ],
)
def test_hunt_grammar_limits_fail_closed(query):
    with pytest.raises(QueryError):
        compile_query(query)


def test_hunt_operators_preserve_parameterization():
    query = compile_query('NOT (source~"a%_" OR http_status>=500) AND mitre_id=T1110')
    assert query.parameters == ["%a\\%\\_%", 500, '%"T1110"%']
    assert query.sql.count("?") == 3
    assert _ioc_type("a" * 32) == ("md5", "a" * 32)
    assert _ioc_type("b" * 40) == ("sha1", "b" * 40)


@pytest.mark.parametrize(
    "patch",
    [
        {"source": None},
        {"source": 1},
        {"source": " "},
        {"source": "x" * 101},
        {"severity": "bad"},
        {"http_status": "bad"},
        {"tags": [1]},
        {"mitre_ids": [1]},
        {"event_time": "invalid"},
        {"event_time": None},
    ],
)
def test_event_normalization_rejects_invalid_input(patch):
    with pytest.raises(ValueError):
        normalize_event({"source": "lab", **patch})


@pytest.mark.parametrize(
    "raw,expected", [("not json", {"message": "not json"}), ('{"src_ip":"192.0.2.1"}', {"src_ip": "192.0.2.1"}), (None, {}), ([], {"value": "[]"})]
)
def test_raw_payload_preservation(raw, expected):
    result = normalize_event({"source": "lab", "raw_payload": raw})
    assert json.loads(result["raw_data"]) == expected


def test_parser_resource_budgets_and_auto_detection(app):
    nested = {}
    for _ in range(25):
        nested = {"nested": nested}
    assert _depth(nested) > 20
    with app.app_context():
        for filename, content, fmt, error in [
            ("large.json", b"x" * (app.config["MAX_CONTENT_LENGTH"] + 1), "json", "limit"),
            ("nested.json", json.dumps(nested).encode(), "json", "nesting"),
            ("line.jsonl", b"x" * 1048577, "jsonl", "1 MiB"),
        ]:
            with pytest.raises(ValueError, match=error):
                _, records = parse_records(filename, content, fmt, "lab")
                list(records)
    assert _detect_format("events.evtx", b"ElfFile\x00") == "evtx"
    assert _detect_format("events.evtx", b'{"event_type":"test"}') == "json"
    assert _detect_format("unknown", b"") == "syslog"
    assert _detect_format("access.log", b'192.0.2.1 - - [19/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1') == "web"
    assert _detect_format("auth.log", b"Oct 19 10:00:00 host sshd: Failed password") == "linux_auth"
    assert _priority_severity(3) == "high"
    assert _priority_severity(4) == "medium"
    with pytest.raises(ValueError):
        parse_timestamp([])


def test_codespaces_trusted_host_exact_match(monkeypatch):
    from socify.config import build_config

    monkeypatch.setenv("CODESPACE_NAME", "socify-test-abc123")
    monkeypatch.setenv("SOCIFY_PORT", "5000")
    monkeypatch.delenv("SOCIFY_TRUSTED_HOSTS", raising=False)
    hosts = build_config()["TRUSTED_HOSTS"]
    assert "socify-test-abc123-5000.app.github.dev" in hosts
    assert "localhost" in hosts
    assert "127.0.0.1" in hosts
    assert "*.app.github.dev" not in hosts
    monkeypatch.setenv("CODESPACE_NAME", "../unsafe")
    assert "unsafe-5000.app.github.dev" not in build_config()["TRUSTED_HOSTS"]
