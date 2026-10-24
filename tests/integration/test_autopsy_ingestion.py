import csv
import hashlib
import io
import json
import secrets
import socket
import ssl
import struct

import dpkt
import pytest

from socify.db import get_db
from socify.import_worker import run_import_worker_once


def upload(client, case_id, content, **options):
    return client.post(f"/api/cases/{case_id}/imports", json={"filename": "case.jsonl", "content": content, **options})


def test_case_bound_csv_mapping_timezone_original_and_versioned_reprocessing(autopsy_case, client):
    raw = "when;remote;caption\n2026-10-24T12:00:00;192.0.2.20;Case mapped row\n"
    options = {
        "filename": "mapped.csv",
        "delimiter": ";",
        "source_timezone": "Asia/Riyadh",
        "mapping": {"when": "event_time", "remote": "source_ip", "caption": "title"},
        "source_label": "Internal collector",
    }
    preview = client.post(f"/api/cases/{autopsy_case}/imports/preview", json={"content": raw, **options})
    assert preview.status_code == 200, preview.json
    assert preview.json["preview"][0]["event_time"] == "2026-10-24T09:00:00Z"
    created = upload(client, autopsy_case, raw, **options)
    assert created.status_code == 201, created.json
    assert created.json["accepted"] == 1
    job_id = created.json["id"]
    log = client.get(f"/api/cases/{autopsy_case}/logs?q=caption").json
    assert log["total"] == 1
    assert log["items"][0]["source_ip"] == "192.0.2.20"
    assert log["items"][0]["title"] == "Case mapped row"
    assert log["items"][0]["normalized_fields"]["event_time_known"] is True
    event_id = log["items"][0]["id"]
    exhibit = client.post(f"/api/cases/{autopsy_case}/logs/{event_id}/exhibit", json={})
    assert exhibit.status_code == 201
    assert client.post(f"/api/cases/{autopsy_case}/logs/{event_id}/exhibit", json={}).json["duplicate"] is True
    original = client.get(f"/api/cases/{autopsy_case}/imports/{job_id}/original")
    assert original.data == raw.encode()
    assert original.headers["X-Evidence-SHA256"] == hashlib.sha256(raw.encode()).hexdigest()
    repeated = upload(client, autopsy_case, raw, **options)
    assert repeated.json["duplicate"] is True
    assert repeated.json["id"] == job_id
    changed = upload(client, autopsy_case, raw, **{**options, "source_timezone": "UTC"})
    assert changed.status_code == 201
    assert changed.json["id"] != job_id
    assert client.get(f"/api/cases/{autopsy_case}/logs").json["total"] == 2
    assert client.get(f"/api/cases/{autopsy_case}/custody").json["integrity_valid"] is True


def test_jsonl_quarantine_continues_after_invalid_row_and_marks_unknown_time(autopsy_case, client):
    raw = '{"title":"First preserved row"}\nnot valid JSON\n{"title":"Last preserved row"}\n'
    response = upload(client, autopsy_case, raw)
    assert response.status_code == 201, response.json
    assert response.json["accepted"] == 2
    assert response.json["rejected"] == 1
    assert response.json["status"] == "completed_with_errors"
    detail = client.get(f"/api/cases/{autopsy_case}/imports/{response.json['id']}").json
    assert detail["errors_total"] == 1
    items = client.get(f"/api/cases/{autopsy_case}/logs").json["items"]
    assert {item["title"] for item in items} == {"First preserved row", "Last preserved row"}
    assert all(item["normalized_fields"]["event_time_known"] is False for item in items)


@pytest.mark.parametrize(
    "options",
    [
        {"mapping": {"a": "password_hash"}},
        {"mapping": {"a": "title", "b": "title"}},
        {"mapping": []},
        {"encoding": "unicode_escape"},
        {"delimiter": "\n"},
        {"source_timezone": "../../etc/passwd"},
        {"source_timezone": "Unknown/Zone"},
        {"training_run_id": 1},
        {"source_id": True},
        {"source_id": 2**100},
    ],
)
def test_import_configuration_is_validated_before_use(autopsy_case, client, options):
    response = upload(client, autopsy_case, '{"title":"Validation fixture"}\n', **options)
    assert response.status_code == 422, response.json


def test_import_case_context_isolation_including_duplicate_content(autopsy_case, client, login_as):
    raw = '{"title":"Confidential retained log","source_ip":"192.0.2.5"}\n'
    first = upload(client, autopsy_case, raw).json
    login_as("soc_manager")
    second_case = client.post("/api/cases", json={"title": "Manager private review", "reason": "alert_review", "objective": "Check private evidence"}).json[
        "id"
    ]
    second = upload(client, second_case, raw).json
    assert second["id"] != first["id"]
    assert client.get(f"/api/cases/{autopsy_case}/imports/{second['id']}").status_code == 404
    assert client.get(f"/api/cases/{autopsy_case}/imports/{second['id']}/original").status_code == 404
    secret_event = client.get(f"/api/cases/{second_case}/logs").json["items"][0]["id"]
    login_as("analyst")
    for suffix in ["", "/original", "/cancel", "/resume"]:
        path = f"/api/cases/{second_case}/imports/{second['id']}{suffix}"
        response = client.post(path, json={}) if suffix in {"/cancel", "/resume"} else client.get(path)
        assert response.status_code == 404
    assert client.get(f"/api/cases/{autopsy_case}/logs/{secret_event}").status_code == 404
    assert (
        client.post(
            "/api/cases", json={"title": "Hidden ID reuse", "reason": "alert_review", "objective": "Cannot attach unseen event", "event_ids": [secret_event]}
        ).status_code
        == 404
    )
    assert client.get(f"/api/cases/{autopsy_case}/logs").json["total"] == 1


def test_export_preserves_filters_blocks_formulas_and_supports_redaction(autopsy_case, client, database):
    raw = json.dumps({"title": "=1+1", "source_ip": "192.0.2.66", "username": "private-user", "description": "Sensitive retained evidence"}) + "\n"
    assert upload(client, autopsy_case, raw).status_code == 201
    base = f"/api/cases/{autopsy_case}/logs/export"
    exported = client.get(base + "?format=csv&redacted=0")
    rows = list(csv.DictReader(io.StringIO(exported.data.decode("utf-8-sig"))))
    assert rows[0]["title"] == "'=1+1"
    assert client.get(base + "?format=json&redacted=0").json[0]["source_ip"] == "192.0.2.66"
    redacted = client.get(base + "?format=jsonl")
    assert "192.0.2.66" not in redacted.text
    assert "private-user" not in redacted.text
    assert "Sensitive retained evidence" not in redacted.text
    assert redacted.headers["X-Redaction-Policy"] == "metadata_only_v1"
    assert client.get(base + "?format=json&q=notpresent").json == []
    database.execute(
        "INSERT INTO team_role_permissions(workspace_id, role, permissions) VALUES (1, 'analyst', ?)", (json.dumps(["cases.read", "cases.export"]),)
    )
    assert client.get(base + "?format=json&redacted=0").status_code == 403
    assert client.get(base + "?format=json&redacted=1").status_code == 200
    assert client.get(base + "?format=html").status_code == 422
    assert client.get(f"/api/cases/{autopsy_case}/logs?page={2**100}").status_code == 422
    assert client.get(f"/api/cases/{2**100}/logs").status_code == 404


def _capture(pcapng=False):
    dns = struct.pack("!HHHHHH", 1, 0x100, 1, 0, 0, 0) + b"\x07example\x04test\x00\x00\x01\x00\x01"
    udp = dpkt.udp.UDP(sport=54000, dport=53, data=dns)
    udp.ulen = len(udp)
    network = dpkt.ip.IP(src=socket.inet_aton("192.0.2.1"), dst=socket.inet_aton("198.51.100.53"), p=17, data=udp)
    network.len = len(network)
    ethernet = dpkt.ethernet.Ethernet(src=b"\x01" * 6, dst=b"\x02" * 6, type=0x800, data=network)
    stream = io.BytesIO()
    writer = dpkt.pcapng.Writer(stream) if pcapng else dpkt.pcap.Writer(stream)
    writer.writepkt(bytes(ethernet), ts=1700000000)
    return stream.getvalue()


@pytest.mark.parametrize("pcapng", [False, True])
def test_packet_capture_is_processed_by_worker_without_network_access(autopsy_case, app, client, monkeypatch, pcapng):
    original = _capture(pcapng)

    def forbidden(*args, **kwargs):
        raise AssertionError("capture parsing must not access the network")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    response = client.post(f"/api/cases/{autopsy_case}/imports", data={"file": (io.BytesIO(original), "network.pcapng" if pcapng else "network.pcap")})
    assert response.status_code == 202, response.json
    with app.app_context():
        assert run_import_worker_once(get_db(), "packet-test-worker") == response.json["id"]
    job = client.get(f"/api/cases/{autopsy_case}/imports/{response.json['id']}").json
    assert job["accepted"] == 1, job
    assert job["rejected"] == 0
    event = client.get(f"/api/cases/{autopsy_case}/logs").json["items"][0]
    assert event["normalized_fields"]["dns_question"] == "example.test"
    assert event["source_ip"] == "192.0.2.1"
    assert event["normalized_fields"]["analysis_scope"] == "metadata_only_no_reassembly_no_decryption"
    assert client.get(f"/api/cases/{autopsy_case}/imports/{job['id']}/original").data == original


def test_worker_stops_if_import_creator_loses_permission(autopsy_case, app, client, database, user_ids):
    response = client.post(f"/api/cases/{autopsy_case}/imports?defer=1", json={"filename": "deferred.jsonl", "content": '{"title":"Queued evidence"}\n'})
    assert response.status_code == 202
    database.execute("UPDATE users SET role = 'auditor' WHERE id = ?", (user_ids["analyst"],))
    with app.app_context():
        run_import_worker_once(get_db(), "revocation-test-worker")
    assert client.get(f"/api/cases/{autopsy_case}/imports/{response.json['id']}").json["status"] == "failed"
    assert client.get(f"/api/cases/{autopsy_case}/logs").json["total"] == 0


def test_dst_ambiguity_is_quarantined_not_silently_retimed(autopsy_case, client):
    response = upload(client, autopsy_case, '{"title":"Ambiguous event","event_time":"2026-04-05T02:30:00"}\n', source_timezone="Australia/Sydney")
    assert response.status_code == 201
    assert response.json["accepted"] == 0
    assert response.json["rejected"] == 1


def test_detection_windows_cannot_mix_private_case_events(autopsy_case, client, database, user_ids):
    dsl = {
        "condition": {"field": "event_type", "operator": "equals", "value": "case_scope_detector"},
        "window": {"seconds": 600, "threshold": 2, "group_by": ["source_ip"], "mode": "count", "allowed_lateness_seconds": 60},
    }
    rule_id = database.execute(
        "INSERT INTO rules(name, dsl_json, is_active, deployment_state, workspace_id, created_by, created_at) VALUES ('Case scope detector', ?, 1, 'published', 1, ?, '2026-10-24T00:00:00Z') RETURNING id",
        (json.dumps(dsl), user_ids["soc_manager"]),
    ).fetchone()[0]
    second = client.post("/api/cases", json={"title": "Independent second case", "reason": "alert_review", "objective": "Do not mix detection evidence"}).json[
        "id"
    ]

    def content(title, timestamp):
        return json.dumps({"title": title, "event_type": "case_scope_detector", "source_ip": "192.0.2.40", "event_time": timestamp}) + "\n"

    assert upload(client, autopsy_case, content("First case only", "2026-10-24T12:00:00Z")).json["accepted"] == 1
    assert upload(client, second, content("Other case only", "2026-10-24T12:00:10Z")).json["accepted"] == 1
    assert database.execute("SELECT COUNT(*) FROM alerts WHERE rule_id = ?", (rule_id,)).fetchone()[0] == 0
    assert upload(client, autopsy_case, content("First case completes threshold", "2026-10-24T12:00:20Z")).json["accepted"] == 1
    alert = database.execute("SELECT id, owner_case_id FROM alerts WHERE rule_id = ?", (rule_id,)).fetchone()
    assert alert["owner_case_id"] == autopsy_case
    owners = database.execute(
        "SELECT DISTINCT e.owner_case_id FROM alert_events ae JOIN security_events e ON e.id = ae.event_id WHERE ae.alert_id = ?", (alert["id"],)
    ).fetchall()
    assert [row[0] for row in owners] == [autopsy_case]


def test_offline_ipv6_tls_clienthello_and_http_metadata(autopsy_case, app, client):
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    channel = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).wrap_bio(incoming, outgoing, server_hostname="sni.example.test")
    with pytest.raises(ssl.SSLWantReadError):
        channel.do_handshake()
    hello = outgoing.read()
    packets = []
    private_value = secrets.token_urlsafe(16)
    for port, payload in [(443, hello), (80, f"GET /incident?private_key={private_value} HTTP/1.1\r\nHost: local.example.test\r\n\r\n".encode())]:
        tcp = dpkt.tcp.TCP(sport=55000, dport=port, data=payload, flags=dpkt.tcp.TH_ACK)
        network = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, "2001:db8::1"), dst=socket.inet_pton(socket.AF_INET6, "2001:db8::2"), nxt=6, data=tcp)
        network.plen = len(tcp)
        packets.append(bytes(dpkt.ethernet.Ethernet(src=b"\x01" * 6, dst=b"\x02" * 6, type=0x86DD, data=network)))
    stream = io.BytesIO()
    writer = dpkt.pcap.Writer(stream)
    for packet in packets:
        writer.writepkt(packet, ts=1700000000)
    response = client.post(f"/api/cases/{autopsy_case}/imports", data={"file": (io.BytesIO(stream.getvalue()), "ipv6.pcap")})
    with app.app_context():
        run_import_worker_once(get_db(), "ipv6-packet-worker")
    job = client.get(f"/api/cases/{autopsy_case}/imports/{response.json['id']}").json
    assert job["accepted"] == 2, job
    events = client.get(f"/api/cases/{autopsy_case}/logs").json["items"]
    assert events[0]["source_ip"] == "2001:db8::1"
    assert events[0]["normalized_fields"]["tls_sni"] == "sni.example.test"
    assert events[1]["normalized_fields"]["http_path"] == "/incident"
    assert private_value not in json.dumps(events[1]["normalized_fields"])


def test_explicit_utf16_and_unicode_filename_preserve_original(autopsy_case, client):
    original = "title,event_time\nUnicode source,2026-10-24T00:00:00Z\n".encode("utf-16")
    result = client.post(f"/api/cases/{autopsy_case}/imports", data={"file": (io.BytesIO(original), "سجلات.csv"), "encoding": "utf-16"})
    assert result.status_code == 201, result.json
    assert result.json["accepted"] == 1
    assert result.json["original_filename"] == "سجلات.csv"
    assert client.get(f"/api/cases/{autopsy_case}/imports/{result.json['id']}/original").data == original
    textual = upload(client, autopsy_case, "title,event_time\nArabic filename,2026-10-24T00:00:00Z\n", filename="سجل.csv")
    assert textual.status_code == 201, textual.json
    assert textual.json["format"] == "csv"
