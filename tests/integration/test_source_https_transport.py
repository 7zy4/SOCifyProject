"""Real TLS/HTTP against a local test peer with controlled DNS/address routing."""

import socket
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from socify import outbound
from socify.outbound import fetch_source_bytes
from socify.validation import ValidationError


@pytest.fixture
def tls_source(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "siem.example")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("siem.example")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = tmp_path / "peer.pem", tmp_path / "peer-key.pem"
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    requests, attempted_addresses, dns_queries, server_names = [], [], [], []
    responses = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append({"path": self.path, "host": self.headers["Host"], "authorization": self.headers.get("Authorization")})
            if self.path == "/provider-status" and responses.get("status", 200) != 200:
                body = responses.get("error_body", b'{"title":"Provider error document"}')
                self.send_response(responses["status"])
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                if responses["status"] == 302:
                    self.send_header("Location", f"https://siem.example:{self.server.server_port}/events")
                if responses["status"] == 429:
                    self.send_header("Retry-After", "1")
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path in {"/slow-headers", "/slow-chunk-header"}:
                prefix = (
                    b"HTTP/1.1 200 OK\r\nX-Source: " if self.path == "/slow-headers" else b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;extension="
                )
                suffix = b"\r\nContent-Length: 1\r\n\r\nx" if self.path == "/slow-headers" else b"\r\nx\r\n0\r\n\r\n"
                try:
                    self.wfile.write(prefix)
                    for _ in range(50):
                        self.wfile.write(b"a")
                        self.wfile.flush()
                        threading.Event().wait(0.05)
                    self.wfile.write(suffix)
                except OSError:
                    pass
                return
            if self.path == "/malformed":
                self.wfile.write(b"NOT AN HTTP RESPONSE\r\n\r\n")
                return
            if self.path == "/many-headers":
                self.send_response(200)
                for index in range(110):
                    self.send_header(f"X-Source-{index}", "value")
                self.end_headers()
                return
            if self.path == "/bad-chunk":
                self.send_response(200)
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                self.wfile.write(b"invalid-size\r\nbody\r\n")
                return
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "https://127.0.0.1/private")
                self.end_headers()
                return
            if self.path == "/denied":
                self.send_response(403)
                self.end_headers()
                return
            body = b"x" * 4096 if self.path == "/large" else responses.get("body", b'{"title":"Retained source event"}\n')
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.send_header("Content-Length", str(len(body) + 100 if self.path == "/truncated" else len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.load_cert_chain(cert_file, key_file)
    server_context.set_servername_callback(lambda _socket, hostname, _context: server_names.append(hostname))
    server.socket = server_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client_context = ssl.create_default_context(cafile=str(cert_file))
    real_socket = socket.socket

    class RoutedSocket(real_socket):
        def connect(self, address):
            attempted_addresses.append(address)
            assert address == ("8.8.8.8", server.server_port), address
            # The production code supplies the approved public address. Only this
            # test socket routes it to the owned local TLS peer; no external traffic.
            return super().connect(("127.0.0.1", server.server_port))

    def resolve(host, port, *args, **kwargs):
        dns_queries.append(host)
        assert host in {"siem.example", "other.example"}
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(ssl, "_create_default_https_context", lambda: client_context)
    monkeypatch.setattr(
        outbound,
        "socket",
        SimpleNamespace(socket=RoutedSocket, getaddrinfo=resolve, SOCK_STREAM=socket.SOCK_STREAM, AF_INET=socket.AF_INET, AF_INET6=socket.AF_INET6),
    )
    monkeypatch.setenv("HTTPS_PROXY", "https://unapproved-proxy.example:8443")
    try:
        yield {
            "url": f"https://siem.example:{server.server_port}",
            "requests": requests,
            "attempted_addresses": attempted_addresses,
            "dns_queries": dns_queries,
            "server_names": server_names,
            "context": client_context,
            "responses": responses,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_real_https_keeps_hostname_validation_sni_credentials_and_approved_address(tls_source):
    body, content_type = fetch_source_bytes(
        tls_source["url"] + "/events?after=1", {"Authorization": "Bearer synthetic-transport-value"}, {"siem.example"}, 1024
    )
    assert body == b'{"title":"Retained source event"}\n'
    assert content_type == "application/x-ndjson"
    assert tls_source["dns_queries"] == ["siem.example"]
    assert tls_source["server_names"] == ["siem.example"]
    assert tls_source["requests"][0]["path"] == "/events?after=1"
    assert tls_source["requests"][0]["host"].startswith("siem.example:")
    assert tls_source["requests"][0]["authorization"] == "Bearer synthetic-transport-value"
    assert tls_source["context"].verify_mode == ssl.CERT_REQUIRED and tls_source["context"].check_hostname


@pytest.mark.parametrize("path", ["/redirect", "/denied", "/large", "/malformed", "/many-headers", "/bad-chunk"])
def test_remote_redirect_errors_and_oversized_bodies_are_not_ingested(tls_source, path):
    with pytest.raises(ValidationError):
        fetch_source_bytes(tls_source["url"] + path, {}, {"siem.example"}, 1024)
    assert len(tls_source["requests"]) == 1
    assert tls_source["dns_queries"] == ["siem.example"]


def test_wrong_certificate_hostname_is_rejected_before_credentials_are_sent(tls_source):
    with pytest.raises(ssl.SSLCertVerificationError):
        fetch_source_bytes(
            tls_source["url"].replace("siem.example", "other.example") + "/events",
            {"Authorization": "Bearer synthetic-transport-value"},
            {"other.example"},
            1024,
        )
    assert tls_source["requests"] == []


def test_truncated_response_does_not_masquerade_as_a_complete_event_batch(tls_source):
    with pytest.raises(ValidationError):
        fetch_source_bytes(tls_source["url"] + "/truncated", {}, {"siem.example"}, 1024)
    assert len(tls_source["requests"]) == 1


@pytest.mark.parametrize(
    ("status", "message"),
    [(302, "رابط المصدر يعيد التوجيه"), (429, "المصدر يقيّد معدل الطلبات")],
)
def test_provider_status_explains_recovery_without_accepting_its_json(tls_source, status, message):
    tls_source["responses"].update(status=status, error_body=b'{"title":"Importable-looking provider error"}')
    with pytest.raises(ValidationError, match=message):
        fetch_source_bytes(tls_source["url"] + "/provider-status", {}, {"siem.example"}, 1024)
    assert len(tls_source["requests"]) == 1


@pytest.mark.parametrize("path", ["/slow-headers", "/slow-chunk-header"])
def test_drip_fed_headers_cannot_restart_the_request_deadline(tls_source, monkeypatch, path):
    original = outbound._PinnedHTTPSConnection

    class ShortDeadlineConnection(original):
        def __init__(self, target, deadline):
            super().__init__(target, time.monotonic() + 0.75)

    monkeypatch.setattr(outbound, "_PinnedHTTPSConnection", ShortDeadlineConnection)
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        fetch_source_bytes(tls_source["url"] + path, {}, {"siem.example"}, 1024)
    assert time.monotonic() - started < 1.75
    assert len(tls_source["requests"]) == 1
