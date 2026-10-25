import base64
import hashlib
import io
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "filename,kind,content,event_type",
    [
        ("rfc5424.log", "syslog", b"<34>1 2026-10-19T10:00:00Z host app 1 ID47 - Retained syslog evidence", "syslog"),
        ("rfc3164.log", "syslog", b"<34>Oct 19 10:00:00 host sshd[1]: Accepted publickey for analyst from 198.51.100.2", "syslog"),
        ("auth.log", "linux_auth", b"Oct 19 10:00:00 host sshd[1]: Failed password for analyst from 198.51.100.2", "failed_login"),
        ("access.log", "web", b'198.51.100.2 - analyst [19/Oct/2026:10:00:00 +0000] "GET /internal HTTP/1.1" 200 12', "web_request"),
        (
            "events.xml",
            "sysmon_xml",
            b'<Event><System><EventID>1</EventID><Computer>host</Computer><TimeCreated SystemTime="2026-10-19T10:00:00Z"/></System><EventData><Data Name="Image">cmd.exe</Data></EventData></Event>',
            "sysmon_1",
        ),
    ],
)
def test_real_case_parser_import_search_timeline_original_and_custody(autopsy_case, client, filename, kind, content, event_type):
    base = f"/api/cases/{autopsy_case}"
    result = client.post(base + "/imports", data={"file": (io.BytesIO(content), filename), "format": kind, "source_timezone": "UTC"})
    assert result.status_code == 201, result.json
    assert result.json["accepted"] == 1 and result.json["rejected"] == 0
    original = client.get(base + f"/imports/{result.json['id']}/original")
    assert original.data == content
    assert original.headers["X-Evidence-SHA256"] == hashlib.sha256(content).hexdigest()
    events = client.get(base + "/logs").json
    assert events["total"] == 1 and events["items"][0]["event_type"] == event_type
    assert client.get(base + "/timeline").json["items"][0]["id"] == events["items"][0]["id"]
    assert client.get(base + "/custody").json["integrity_valid"] is True


def test_real_evtx_case_roundtrip_keeps_binary_original_and_parsed_evidence(autopsy_case, client):
    base = f"/api/cases/{autopsy_case}"
    content = base64.b64decode(Path("fixtures/windows/sysmon-sample.evtx.b64").read_bytes())
    result = client.post(base + "/imports", data={"file": (io.BytesIO(content), "retained.evtx"), "format": "evtx", "source_timezone": "UTC"})
    assert result.status_code == 201, result.json
    assert result.json["accepted"] > 0
    assert client.get(base + f"/imports/{result.json['id']}/original").data == content
    assert client.get(base + "/logs").json["total"] == result.json["accepted"]
    assert client.get(base + "/custody").json["integrity_valid"] is True
