"""The outbox and the egress service: queueing, delivery, signatures, retries, failure, manager view and the relay."""

import base64
import dataclasses
import hashlib
import hmac
import json
import socket
import threading
import urllib.error
import urllib.request
from datetime import timedelta
from http.server import ThreadingHTTPServer

import pytest

from scripts import healthcheck
from scripts import run_egress_worker as egress
from socify.config import EgressSettings, egress_settings
from socify.outbound import OutboundResponse, send_https
from socify.outbox import backoff_seconds, claim, connect_outbox, enqueue, validate_message
from socify.timeutils import utc_now
from socify.validation import ValidationError

SECRET = "w" * 40


@pytest.fixture
def outbox(app, tmp_path):
    path = str(tmp_path / "outbox" / "outbox.db")
    app.config.update(EGRESS_ENABLED=True, OUTBOX_DATABASE=path)
    connection = connect_outbox(path)
    yield connection
    connection.close()


@pytest.fixture
def settings(outbox, app):
    return EgressSettings(
        outbox=app.config["OUTBOX_DATABASE"],
        allowlist=frozenset({"hooks.example.com", "smtp.example.com"}),
        webhooks={"ops": "https://hooks.example.com/socify"},
        webhook_secrets={"ops": SECRET},
        max_attempts=3,
        smtp={"host": "smtp.example.com", "port": 587, "username": "", "password": "", "sender": "soc@example.com", "tls": "starttls"},
        relay_token="r" * 40,
        relay_port=0,
    )


@pytest.fixture
def sent(monkeypatch):
    calls, answers = [], []

    def fake(method, url, **kwargs):
        calls.append({"method": method, "url": url, **kwargs})
        status = answers.pop(0) if answers else 200
        if isinstance(status, Exception):
            raise status
        return OutboundResponse(status, "application/json", b"{}")

    monkeypatch.setattr(egress, "send_https", fake)
    return calls, answers


def _queue(app, kind="webhook", target="ops", payload=None):
    with app.app_context():
        return enqueue(1, kind, target, payload or {"event": "case_assigned", "case": "CASE-1"})


def _message(outbox, message_id):
    return outbox.execute("SELECT * FROM outbox_messages WHERE id = ?", (message_id,)).fetchone()


def test_nothing_is_queued_while_outbound_delivery_is_off(app):
    assert app.config["EGRESS_ENABLED"] is False
    with app.app_context():
        assert enqueue(1, "webhook", "ops", {"event": "x"}) is None


@pytest.mark.parametrize(
    ("kind", "target", "payload"),
    [
        ("sms", "ops", {}),
        ("webhook", "https://evil.example/x", {}),
        ("email", "not-an-address", {"subject": "s", "text": "t"}),
        ("email", "a@b.example", {"text": "t"}),
    ],
)
def test_messages_that_cannot_be_sent_are_refused_before_queueing(kind, target, payload):
    with pytest.raises(ValueError):
        validate_message(kind, target, payload)
    with pytest.raises(ValueError, match="too large"):
        validate_message("webhook", "ops", {"blob": "x" * 300_000})


def test_a_webhook_is_delivered_with_a_verifiable_signature(app, outbox, settings, sent):
    calls, _ = sent
    message_id = _queue(app)
    assert egress.deliver_one(outbox, settings)
    [call] = calls
    assert call["method"] == "POST" and call["url"] == "https://hooks.example.com/socify" and call["allowed_hosts"] == {"hooks.example.com", "smtp.example.com"}
    headers = call["headers"]
    expected = hmac.new(SECRET.encode(), headers["X-SOCify-Timestamp"].encode() + b"." + call["body"], hashlib.sha256).hexdigest()
    assert headers["X-SOCify-Signature"] == "sha256=" + expected and headers["X-SOCify-Delivery"] == str(message_id)
    assert json.loads(call["body"]) == {"event": "case_assigned", "case": "CASE-1"}
    row = _message(outbox, message_id)
    assert row["status"] == "sent" and row["attempts"] == 1
    assert outbox.execute("SELECT outcome, status_code FROM outbox_results").fetchall()[0][:] == ("sent", 200)
    assert not egress.deliver_one(outbox, settings)


def test_temporary_failures_back_off_and_end_as_failed(app, outbox, settings, sent):
    _, answers = sent
    answers.extend([503, TimeoutError("slow"), 429])
    message_id = _queue(app)
    for attempt in range(1, 4):
        outbox.execute("UPDATE outbox_messages SET next_attempt_at = '2000-01-01T00:00:00Z' WHERE id = ?", (message_id,))
        assert egress.deliver_one(outbox, settings)
        row = _message(outbox, message_id)
        assert row["attempts"] == attempt
    assert row["status"] == "failed" and "429" in row["last_error"]
    assert [backoff_seconds(n) for n in (1, 2, 3, 8, 20)] == [30, 60, 120, 3600, 3600]


def test_permanent_failures_stop_at_once(app, outbox, settings, sent):
    _, answers = sent
    answers.append(404)
    first = _queue(app)
    unknown = _queue(app, target="nowhere")
    assert egress.deliver_one(outbox, settings) and egress.deliver_one(outbox, settings)
    assert _message(outbox, first)["status"] == "failed" and _message(outbox, unknown)["status"] == "failed"
    assert "not configured" in _message(outbox, unknown)["last_error"]


def test_a_stopped_worker_leaves_its_message_due_again(app, outbox):
    message_id = _queue(app)
    taken = claim(outbox, lease_seconds=60)
    assert taken["id"] == message_id and taken["status"] == "sending" and claim(outbox) is None
    outbox.execute(
        "UPDATE outbox_messages SET lease_expires_at = ? WHERE id = ?", ((utc_now() - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"), message_id)
    )
    assert claim(outbox)["id"] == message_id


def test_email_goes_to_the_vetted_address_over_tls(app, outbox, settings, monkeypatch):
    seen = {}

    class FakeSMTP:
        def __init__(self, host, port, address, **kwargs):
            seen.update(host=host, port=port, address=address)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def starttls(self, context):
            seen["tls"] = context.check_hostname and context.verify_mode

        def send_message(self, message):
            seen["to"], seen["subject"] = message["To"], message["Subject"]

    monkeypatch.setattr(egress, "vetted_address", lambda host, port, allowlist: ("198.51.100.25", port))
    monkeypatch.setattr(egress, "_pinned", lambda base: FakeSMTP)
    message_id = _queue(app, "email", "analyst@example.com", {"subject": "Case assigned", "text": "CASE-1 was assigned to you."})
    assert egress.deliver_one(outbox, settings)
    assert seen == {
        "host": "smtp.example.com",
        "port": 587,
        "address": ("198.51.100.25", 587),
        "tls": 2,
        "to": "analyst@example.com",
        "subject": "Case assigned",
    }
    assert _message(outbox, message_id)["status"] == "sent"


def test_only_allowlisted_public_hosts_are_contacted(monkeypatch):
    with pytest.raises(egress.PermanentFailure, match="ALLOWLIST"):
        egress.vetted_address("smtp.other.example", 587, frozenset({"smtp.example.com"}))
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 587))])
    with pytest.raises(egress.PermanentFailure, match="non-public"):
        egress.vetted_address("smtp.example.com", 587, frozenset({"smtp.example.com"}))
    with pytest.raises(ValidationError):
        send_https("POST", "https://not-allowed.example/x", allowed_hosts={"hooks.example.com"})
    with pytest.raises(ValueError):
        send_https("DELETE", "https://hooks.example.com/x", allowed_hosts={"hooks.example.com"})


def test_managers_see_failed_messages_and_send_them_again(app, client, login_as, outbox, settings, sent):
    _, answers = sent
    answers.append(400)
    message_id = _queue(app)
    egress.deliver_one(outbox, settings)
    login_as("analyst")
    assert client.get("/api/outbox").status_code == 403
    login_as("soc_manager")
    listed = client.get("/api/outbox").json
    assert listed["enabled"] and listed["items"][0]["id"] == message_id and listed["items"][0]["status"] == "failed"
    assert "payload" not in listed["items"][0]
    assert client.post(f"/api/outbox/{message_id}/retry").json == {"id": message_id, "status": "pending"}
    assert _message(outbox, message_id)["status"] == "pending" and _message(outbox, message_id)["attempts"] == 0
    assert client.post(f"/api/outbox/{message_id}/retry").status_code == 404


def test_the_relay_needs_its_token_and_allows_only_known_request_types(settings, sent):
    calls, _ = sent
    server = ThreadingHTTPServer(("127.0.0.1", 0), egress.relay_handler(settings))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}/relay"

    def post(body, token="r" * 40):
        request = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310 - local test server
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    try:
        assert post({"type": "get_json", "url": "https://hooks.example.com/.well-known/openid-configuration"}, token="x" * 40)[0] == 401
        assert post({"type": "shell", "url": "https://hooks.example.com/"})[0] == 422
        status, body = post({"type": "get_json", "url": "https://hooks.example.com/.well-known/openid-configuration"})
        assert status == 200 and base64.b64decode(body["body"]) == b"{}" and calls[-1]["method"] == "GET"
        status, _ = post({"type": "post_form", "url": "https://hooks.example.com/token", "form": {"grant_type": "authorization_code"}})
        assert status == 200 and calls[-1]["body"] == b"grant_type=authorization_code"
    finally:
        server.shutdown()


def test_the_egress_worker_beats_in_the_outbox_and_the_health_check_reads_it(app, outbox, settings, sent):
    egress.serve(settings, once=True)
    assert outbox.execute("SELECT state FROM worker_heartbeats WHERE name = 'egress'").fetchone()[0] == "idle"
    assert healthcheck.main(["worker", "--name", "egress", "--database", settings.outbox]) == 0


def test_egress_settings_are_validated(monkeypatch):
    monkeypatch.setenv("SOCIFY_EGRESS_WEBHOOKS", "ops=https://hooks.example.com/a, soc=https://hooks.example.com/b")
    monkeypatch.setenv("SOCIFY_EGRESS_WEBHOOK_SECRET_OPS", SECRET)
    monkeypatch.setenv("SOCIFY_EGRESS_ALLOWLIST", "Hooks.Example.com.")
    parsed = egress_settings()
    assert parsed.webhooks == {"ops": "https://hooks.example.com/a", "soc": "https://hooks.example.com/b"} and parsed.webhook_secrets == {"ops": SECRET}
    assert parsed.allowlist == frozenset({"hooks.example.com"}) and parsed.relay_token is None
    for name, value in (
        ("SOCIFY_EGRESS_WEBHOOKS", "ops=http://plain.example"),
        ("SOCIFY_SMTP_TLS", "none"),
        ("SOCIFY_EGRESS_TOKEN", "short"),
        ("SOCIFY_EGRESS_MAX_ATTEMPTS", "0"),
    ):
        with monkeypatch.context() as scoped:
            scoped.setenv(name, value)
            with pytest.raises(RuntimeError):
                egress_settings()
    assert dataclasses.is_dataclass(parsed)


def test_outbox_views_when_delivery_is_off_and_invalid_messages(app, client, login_as):
    login_as("soc_manager")
    assert client.get("/api/outbox").json == {"enabled": False, "items": []}
    assert client.post("/api/outbox/1/retry").status_code == 409
    app.config.update(EGRESS_ENABLED=True)
    with app.app_context(), pytest.raises(ValueError):
        enqueue(1, "webhook", "Not A Name!", {"event": "x"})
