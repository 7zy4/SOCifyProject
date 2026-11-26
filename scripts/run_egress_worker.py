"""The egress service: delivers outbox messages to allowlisted destinations, and relays allowlisted requests.

It is the only SOCify process with internet access. It mounts the outbox volume and nothing else: no case database,
no credential key, no analysis socket. Webhook URLs and secrets and SMTP credentials come from its own environment.

    python -m scripts.run_egress_worker [--once]
"""

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import smtplib
import socket
import ssl
import threading
import time
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from socify.config import EgressSettings, egress_settings
from socify.outbound import ResolutionError, send_https
from socify.outbox import claim, connect_outbox, finish
from socify.timeutils import iso_now
from socify.validation import ValidationError
from socify.worker_health import Heartbeat

log = logging.getLogger("socify.egress")
RELAY_TYPES = {"get_json", "post_form"}
RELAY_BODY_LIMIT = 64 * 1024


class PermanentFailure(Exception):
    """A delivery that retrying cannot fix, such as an unknown destination or a 4xx answer."""


def vetted_address(host: str, port: int, allowlist: frozenset[str]) -> tuple:
    """The first public address for an allowlisted host; any non-public answer refuses the whole host."""
    if host not in allowlist:
        raise PermanentFailure("host is not in SOCIFY_EGRESS_ALLOWLIST")
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    for family, _kind, _protocol, _name, address in answers:
        ip = ipaddress.ip_address(address[0])
        if family not in {socket.AF_INET, socket.AF_INET6} or not ip.is_global or ip.is_multicast or ip.is_reserved:
            raise PermanentFailure("host resolves to a non-public address")
    if not answers:
        raise OSError("host did not resolve")
    return answers[0][4]


class PinnedSMTP(smtplib.SMTP):
    """SMTP to the vetted address; STARTTLS still checks the configured host name."""

    def __init__(self, host, port, address, **kwargs):
        self._vetted = address
        super().__init__(host, port, **kwargs)

    def _get_socket(self, host, port, timeout):
        return socket.create_connection(self._vetted[:2], timeout)


class PinnedSMTPSSL(smtplib.SMTP_SSL):
    """Implicit-TLS SMTP to the vetted address, with the certificate checked against the configured host name."""

    def __init__(self, host, port, address, **kwargs):
        self._vetted = address
        super().__init__(host, port, **kwargs)

    def _get_socket(self, host, port, timeout):
        # smtplib keeps the configured host name in _host; it stays the TLS server name.
        return self.context.wrap_socket(socket.create_connection(self._vetted[:2], timeout), server_hostname=self._host)  # type: ignore[attr-defined]


def _pinned(base):
    return PinnedSMTPSSL if base is smtplib.SMTP_SSL else PinnedSMTP


def send_webhook(settings: EgressSettings, message, payload: dict) -> int:
    url = settings.webhooks.get(message["target"])
    if url is None:
        raise PermanentFailure("webhook destination is not configured in the egress service")
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "SOCify-egress", "X-SOCify-Delivery": str(message["id"])}
    secret = settings.webhook_secrets.get(message["target"])
    if secret:
        timestamp = str(int(time.time()))
        headers["X-SOCify-Timestamp"] = timestamp
        headers["X-SOCify-Signature"] = "sha256=" + hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    try:
        response = send_https("POST", url, allowed_hosts=set(settings.allowlist), headers=headers, body=body, limit=64 * 1024)
    except ResolutionError:
        raise  # a resolver outage: retried with backoff
    except ValidationError as error:
        raise PermanentFailure(error.public_message) from error
    if 200 <= response.status < 300:
        return response.status
    if response.status in {408, 429} or response.status >= 500:
        raise ConnectionError(f"destination answered {response.status}")
    raise PermanentFailure(f"destination answered {response.status}")


def send_email(settings: EgressSettings, message, payload: dict) -> int:
    smtp = settings.smtp
    host, port, sender = str(smtp["host"]), int(str(smtp["port"])), str(smtp["sender"])
    if not host or not sender:
        raise PermanentFailure("SOCIFY_SMTP_HOST and SOCIFY_SMTP_FROM are not configured")
    address = vetted_address(host, port, settings.allowlist)
    email = EmailMessage()
    email["From"], email["To"], email["Subject"] = sender, message["target"], payload["subject"]
    email.set_content(payload["text"])
    context = ssl.create_default_context()
    if smtp["tls"] == "ssl":
        client = _pinned(smtplib.SMTP_SSL)(host, port, address, timeout=20, context=context)
    else:
        client = _pinned(smtplib.SMTP)(host, port, address, timeout=20)
    with client:
        if smtp["tls"] == "starttls":
            client.starttls(context=context)
        if smtp["username"]:
            client.login(str(smtp["username"]), str(smtp["password"]))
        client.send_message(email)
    return 250


def deliver_one(connection, settings: EgressSettings) -> bool:
    """Deliver the next due message, if any; returns whether one was handled."""
    message = claim(connection)
    if message is None:
        return False
    payload = json.loads(message["payload"])
    try:
        status = send_webhook(settings, message, payload) if message["kind"] == "webhook" else send_email(settings, message, payload)
    except PermanentFailure as error:
        outcome = finish(connection, message, sent=False, max_attempts=int(message["attempts"]), error=str(error))
    except ResolutionError as error:
        outcome = finish(connection, message, sent=False, max_attempts=settings.max_attempts, error="ResolutionError: " + error.public_message)
    except (ValueError, TypeError, KeyError) as error:
        # A message that cannot be built (for example a header with a line break) fails alone; delivery goes on.
        outcome = finish(connection, message, sent=False, max_attempts=int(message["attempts"]), error="invalid message: " + type(error).__name__)
    except (OSError, smtplib.SMTPException, ValidationError, ConnectionError, TimeoutError) as error:
        outcome = finish(connection, message, sent=False, max_attempts=settings.max_attempts, error=type(error).__name__ + ": " + str(error)[:200])
    else:
        outcome = finish(connection, message, sent=True, max_attempts=settings.max_attempts, status_code=status)
    log.info("egress_delivery id=%s kind=%s outcome=%s attempt=%s", message["id"], message["kind"], outcome, message["attempts"])
    return True


def relay(settings: EgressSettings, request: dict) -> dict:
    """One allowlisted request for a component that needs an answer now (single sign-on discovery, keys and token exchange)."""
    if not isinstance(request, dict) or request.get("type") not in RELAY_TYPES or not isinstance(request.get("url"), str):
        raise ValueError("unsupported relay request")
    if request["type"] == "get_json":
        response = send_https("GET", request["url"], allowed_hosts=set(settings.allowlist), headers={"Accept": "application/json"})
    else:
        form = request.get("form")
        if not isinstance(form, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in form.items()):
            raise ValueError("post_form needs a form of text fields")
        from urllib.parse import urlencode

        response = send_https(
            "POST",
            request["url"],
            allowed_hosts=set(settings.allowlist),
            headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
            body=urlencode(form).encode(),
        )
    return {"status": response.status, "content_type": response.content_type, "body": base64.b64encode(response.body).decode()}


def relay_handler(settings: EgressSettings):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SOCify-egress"

        def log_message(self, *_args):
            return

        def _answer(self, status: int, body: dict) -> None:
            encoded = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_POST(self):  # noqa: N802 - the http.server method name
            scheme, _, supplied = self.headers.get("Authorization", "").partition(" ")
            if self.path != "/relay" or scheme.lower() != "bearer" or not hmac.compare_digest(supplied.strip().encode(), str(settings.relay_token).encode()):
                self._answer(401, {"error": "unauthorized"})
                return
            declared = self.headers.get("Content-Length", "")
            length = int(declared) if declared.isdigit() else 0
            if not 0 < length <= RELAY_BODY_LIMIT:
                self._answer(413, {"error": "request too large"})
                return
            try:
                self._answer(200, relay(settings, json.loads(self.rfile.read(length))))
            except (ValueError, ValidationError) as error:
                self._answer(422, {"error": getattr(error, "public_message", str(error))})
            except (OSError, TimeoutError):
                self._answer(502, {"error": "destination unavailable"})

    return Handler


def serve(settings: EgressSettings, once: bool = False, sleep=time.sleep) -> None:
    connection = connect_outbox(settings.outbox)
    heartbeat = Heartbeat("egress")
    if settings.relay_token and not once:
        server = ThreadingHTTPServer(("0.0.0.0", settings.relay_port), relay_handler(settings))  # noqa: S104  # nosec B104 - the app reaches the relay on the internal network; no port is published
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        heartbeat.beat(connection, "ready", force=True)
        while True:
            handled = deliver_one(connection, settings)
            heartbeat.beat(connection, "active" if handled else "idle", force=handled)
            if once:
                return
            if not handled:
                sleep(1.0)
    finally:
        connection.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Deliver SOCify outbox messages.")
    parser.add_argument("--once", action="store_true")
    arguments = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = egress_settings()
    log.info(
        "egress_started at=%s destinations=%s allowlist=%s relay=%s", iso_now(), len(settings.webhooks), len(settings.allowlist), bool(settings.relay_token)
    )
    serve(settings, arguments.once)


if __name__ == "__main__":
    main()
