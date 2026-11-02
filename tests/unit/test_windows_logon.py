from xml.sax.saxutils import escape

import pytest

from socify.windows_logon import logon_context


def logon_xml(number=0, event_id=4625, *, host="APP-SRV01", domain="CORP", user="noura", ip="192.0.2.42", kind="10", minute=None):
    data = {
        "TargetUserName": user,
        "TargetDomainName": domain,
        "SubjectUserName": "SYSTEM",
        "IpAddress": ip,
        "IpPort": "50120",
        "LogonType": kind,
        "AuthenticationPackageName": "Negotiate",
        "WorkstationName": "FINANCE-07",
        **({"Status": "0xc000006d", "SubStatus": "0xc000006a"} if event_id == 4625 else {"TargetLogonId": "0x98c1"}),
    }
    minute = number if minute is None else minute
    fields = "".join(f'<Data Name="{key}">{escape(value)}</Data>' for key, value in data.items())
    return f'<Event><System><Channel>Security</Channel><EventID>{event_id}</EventID><TimeCreated SystemTime="2026-11-02T02:{minute:02d}:00Z"/><Computer>{escape(host)}</Computer></System><EventData>{fields}</EventData></Event>'


def test_authentication_uses_target_identity_preserves_casing_and_normalizes_mapped_ipv4():
    data = {"TargetUserName": "Noura", "TargetDomainName": "CORP", "LogonType": "10", "IpAddress": "::ffff:192.0.2.42", "IpPort": "50120"}
    parsed = logon_context("4625", data, "APP-SRV01")
    assert parsed["source_ip"] == "192.0.2.42" and parsed["username"] == "Noura"
    assert parsed["normalized_fields"]["source_port"] == 50120
    other = logon_context("4624", {**data, "TargetUserName": "noura", "TargetDomainName": "corp"}, "app-srv01")
    assert parsed["normalized_fields"]["auth_target"] == other["normalized_fields"]["auth_target"]
    assert data["IpAddress"] == "::ffff:192.0.2.42"


@pytest.mark.parametrize(
    "field,value",
    [
        ("TargetUserName", "-"),
        ("TargetDomainName", ""),
        ("LogonType", "2"),
        ("LogonType", "999"),
        ("IpAddress", "-"),
        ("IpAddress", "127.0.0.1"),
        ("IpAddress", "::"),
        ("IpAddress", "ff02::1"),
        ("IpAddress", "fe80::1%eth0"),
    ],
)
def test_incomplete_or_local_context_cannot_be_correlated(field, value):
    data = {"TargetUserName": "noura", "TargetDomainName": "CORP", "LogonType": "10", "IpAddress": "192.0.2.42", "SubjectUserName": "SYSTEM"}
    parsed = logon_context("4625", {**data, field: value}, "APP-SRV01")
    assert "auth_target" not in parsed["normalized_fields"]
    if field == "TargetUserName":
        assert parsed["username"] is None


@pytest.mark.parametrize("port", ["-1", "65536", "x", "1e3", "9999999999999999999999"])
def test_invalid_ports_are_not_invented(port):
    assert "source_port" not in logon_context("4624", {"IpPort": port}, "host")["normalized_fields"]
