"""Controlled DNS and transport adversaries; never contact an external host."""

import importlib
import socket
from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from socify import outbound
from socify.security import safe_external_endpoint

sources = importlib.import_module("socify.sources")


@pytest.mark.parametrize("url", ["https://siem.example:bad/events", "https://siem.example:65536/events", "https://[broken/events"])
def test_invalid_source_authorities_are_rejected_without_raising(url):
    assert safe_external_endpoint(url, {"siem.example"})[0] is False


@pytest.mark.parametrize("address", ["100.64.0.1", "127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1", "224.0.0.1"])
def test_non_global_source_addresses_are_blocked(monkeypatch, address):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))])
    assert safe_external_endpoint("https://siem.example/events", {"siem.example"})[0] is False


@pytest.mark.parametrize("addresses", [[], ["8.8.8.8", "127.0.0.1"], ["8.8.8.8", "100.64.0.1"]])
def test_empty_or_mixed_dns_answers_fail_closed(monkeypatch, addresses):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443)) for address in addresses])
    assert safe_external_endpoint("https://siem.example/events", {"siem.example"})[0] is False


def test_global_ipv6_answer_remains_supported(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:4860:4860::8888", 443, 0, 0))])
    assert safe_external_endpoint("https://siem.example/events", {"siem.example"}) == (True, "ok")


def test_changed_dns_cannot_connect_to_a_private_address(monkeypatch):
    lookups, attempts = [], []

    def resolve(host, port, *args, **kwargs):
        lookups.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8" if len(lookups) == 1 else "127.0.0.1", port))]

    def connect(address):
        attempts.append(address)
        raise OSError("Controlled transport termination before any network call")

    fake_socket = MagicMock()
    fake_socket.connect.side_effect = connect
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv("SOCIFY_SOURCE_ALLOWLIST", "siem.example")
    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: fake_socket)
    assert safe_external_endpoint("https://siem.example/events", {"siem.example"})[0]
    with pytest.raises((ValueError, OSError)):
        sources._fetch_remote_events_bytes("https://siem.example/events", {})
    assert ("127.0.0.1", 443) not in attempts


def test_connect_preserves_remaining_budget_after_tcp_and_tls(monkeypatch):
    clock = [100.0]
    fake_socket = MagicMock()

    def connect(_address):
        clock[0] += 2

    def handshake(connection, **kwargs):
        assert kwargs["server_hostname"] == "siem.example"
        clock[0] += 2
        return connection

    target = outbound.ExternalTarget("siem.example", 443, "/events", ((socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),))
    connection = outbound._PinnedHTTPSConnection(target, deadline=105.0)
    context = MagicMock()
    context.wrap_socket.side_effect = handshake
    connection._context = context
    fake_socket.connect.side_effect = connect
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: fake_socket)
    monkeypatch.setattr(outbound.time, "monotonic", lambda: clock[0])
    try:
        connection.connect()
        assert [call.args[0] for call in fake_socket.settimeout.call_args_list] == [5.0, 3.0, 1.0]
    finally:
        connection.close()


@given(st.text(max_size=512))
@settings(max_examples=400, deadline=None)
def test_arbitrary_url_text_fails_closed_without_dns_for_unlisted_hosts(value):
    # Empty allowlist also proves malformed input cannot trigger DNS/network work.
    from unittest.mock import patch

    with patch("socket.getaddrinfo", side_effect=AssertionError("Unexpected DNS query")):
        assert safe_external_endpoint(value, set())[0] is False
