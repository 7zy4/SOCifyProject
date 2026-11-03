"""Reject hostile text without losing valid log, indicator or decoding behavior."""

import base64
import json
import re
import subprocess
import sys

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from socify.autopsy_domain import normalize_indicator
from socify.content_inspection import decode_layer, inspect_content
from socify.hunting import QueryError, _tokens
from socify.ingestion import SYSLOG_5424, WEB_LOG, _cef_extension


def test_adversarial_text_finishes_within_a_bounded_process_budget():
    program = r"""
from socify.ingestion import WEB_LOG, _cef_extension
from socify.content_inspection import inspect_content
from socify.autopsy_domain import normalize_indicator
assert WEB_LOG.match('! ! ! [\\] "! ! ' + ' ' * 131072) is None
assert _cef_extension('A=' + ' ' * 131072 + '!') == {'A': '!'}
inspect_content({'command': 'pwsh' + 'pwsha' * 16384})
try:
    normalize_indicator('email', 'a@' + '.' * 131072 + '@')
except ValueError:
    pass
else:
    raise AssertionError('Invalid indicator accepted')
"""
    subprocess.run([sys.executable, "-c", program], check=True, timeout=8, capture_output=True, text=True)  # noqa: S603


@given(st.text(alphabet="abAZ19 _.=-\\\t", max_size=100))
@settings(max_examples=200, deadline=None)
def test_cef_key_scanner_preserves_bounded_extension_semantics(value):
    reference = re.compile(r"(?:^|\s+)([A-Za-z][A-Za-z0-9_.-]*)=(.*?)(?=\s+[A-Za-z][A-Za-z0-9_.-]*=|$)")
    expected = {match.group(1): match.group(2).replace("\\=", "=").strip() for match in reference.finditer(value)}
    assert _cef_extension(value) == expected


def test_cef_values_keep_spaces_escaped_equals_and_last_duplicate():
    assert _cef_extension(r"msg=Identity evidence reviewed request=/a?x\=1 src=192.0.2.8 msg=New decision") == {
        "msg": "New decision",
        "request": "/a?x=1",
        "src": "192.0.2.8",
    }


@given(st.text(alphabet="abAZ19@. _-\t\n\u00a0", max_size=100))
@settings(max_examples=200, deadline=None)
def test_email_indicator_grammar_remains_equivalent_on_bounded_inputs(value):
    expected = re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value) is not None
    try:
        actual = normalize_indicator("email", value)
    except ValueError:
        assert not expected
    else:
        assert expected and actual == value


def test_valid_web_and_syslog_fields_remain_available():
    web = WEB_LOG.fullmatch('192.0.2.5 - alice [03/Nov/2026:12:00:00 +0000] "GET /case?id=2 HTTP/1.1" 200 512 "https://example.test/" "Analyst browser 1"')
    assert web and web.group("protocol") == "HTTP/1.1" and web.group("agent") == "Analyst browser 1"
    syslog = SYSLOG_5424.fullmatch("<34>1 2026-11-03T12:00:00Z host app 12 EVT -   Evidence retained")
    assert syslog and syslog.group("message") == "Evidence retained"


@pytest.mark.parametrize("option", ["e", "en", "enc", "enco", "encodedcommand", "ENCODEDCOMMAND"])
def test_encoded_powershell_command_still_decodes(option):
    source = "Write-Output 'Retained evidence'"
    encoded = base64.b64encode(source.encode("utf-16le")).decode()
    result = inspect_content({"command": f'powershell.exe -NoProfile -{option} "{encoded}"'})
    assert source in json.dumps(result, ensure_ascii=False)


@pytest.mark.parametrize("encoder", [base64.b32encode, base64.b64encode, base64.urlsafe_b64encode])
def test_valid_encoded_text_is_preserved(encoder):
    plain = b"Retained investigation evidence: 12345"
    result = decode_layer(encoder(plain).decode())
    assert result and result[1] == plain.decode()


def test_quoted_hunt_tokens_keep_escaped_quotes_and_reject_unterminated_strings():
    assert _tokens(r'hostname = "host\"name" AND severity = high') == ["hostname", "=", '"host\\"name"', "AND", "severity", "=", "high"]
    with pytest.raises(QueryError):
        _tokens('"' + '\\"' * 500)


@pytest.mark.parametrize(
    "key,value",
    [
        ("sort", "event_time DESC; DROP TABLE users;--"),
        ("direction", "DESC LIMIT 1"),
        ("sort", "(SELECT password_hash FROM users)"),
        ("sort", "event_time\x00"),
        ("direction", "desc/**/"),
    ],
)
def test_event_ordering_rejects_sql_fragments(client, login_as, key, value):
    login_as("analyst")
    response = client.get("/api/events", query_string={key: value})
    assert response.status_code == 422 and response.json["error"]["code"] == "INVALID_SORT"


@pytest.mark.parametrize("sort", ["event_time", "ingested_at", "severity", "source", "event_type", "id"])
@pytest.mark.parametrize("direction", ["asc", "desc", "ASC", "DESC"])
def test_event_ordering_keeps_supported_choices(client, login_as, sort, direction):
    login_as("analyst")
    assert client.get("/api/events", query_string={"sort": sort, "direction": direction}).status_code == 200
