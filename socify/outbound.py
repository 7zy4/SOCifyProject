"""HTTPS source transport bound to the addresses approved by network policy."""

import http.client
import io
import ipaddress
import socket
import time
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import urlparse

from .validation import ValidationError


@dataclass(frozen=True)
class ExternalTarget:
    hostname: str
    port: int
    path: str
    addresses: tuple[tuple[Any, ...], ...]


def _remaining_time(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Source request timed out")
    return remaining


class _DeadlineReader(io.RawIOBase):
    """Bound each underlying receive, including buffered header/chunk line reads."""

    def __init__(self, connection: socket.socket, deadline: float):
        super().__init__()
        self.connection = connection
        self.deadline = deadline
        self.stream: io.RawIOBase | None = None
        self.stream = cast(io.RawIOBase, connection.makefile("rb", buffering=0))

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int | None:
        if self.stream is None or self.closed:
            raise ValueError("Source response is closed")
        self.connection.settimeout(_remaining_time(self.deadline))
        return self.stream.readinto(buffer)

    def close(self) -> None:
        try:
            if self.stream is not None:
                self.stream.close()
        finally:
            super().close()


def resolve_external_target(endpoint: str, allowed_hosts: set[str]) -> ExternalTarget:
    try:
        if not isinstance(endpoint, str) or any(character.isspace() or ord(character) < 32 for character in endpoint):
            raise ValueError("invalid URL characters")
        parsed = urlparse(endpoint)
        port = 443 if parsed.port is None else parsed.port
        if parsed.scheme != "https" or not parsed.hostname or not 1 <= port <= 65535:
            raise ValueError("invalid authority")
        hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except (ValueError, UnicodeError) as exc:
        raise ValidationError("يلزم عنوان HTTPS صالح") from exc
    if parsed.username is not None or parsed.password is not None:
        raise ValidationError("بيانات الاعتماد غير مسموحة داخل عنوان المصدر")
    if hostname not in {host.lower().rstrip(".") for host in allowed_hosts}:
        raise ValidationError("المضيف غير موجود في قائمة السماح")
    try:
        addresses = tuple(socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM))
    except OSError as exc:
        raise ValidationError("تعذر حل اسم المضيف") from exc
    if not addresses:
        raise ValidationError("تعذر حل اسم المضيف")
    for family, _kind, _protocol, _name, address in addresses:
        try:
            ip = ipaddress.ip_address(address[0])
        except ValueError as exc:
            raise ValidationError("عنوان المضيف محجوب بواسطة سياسة الشبكة") from exc
        if family not in {socket.AF_INET, socket.AF_INET6} or not ip.is_global or ip.is_multicast or ip.is_reserved:
            raise ValidationError("عنوان المضيف محجوب بواسطة سياسة الشبكة")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return ExternalTarget(hostname, port, path, addresses)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, target: ExternalTarget, deadline: float):
        super().__init__(target.hostname, port=target.port, timeout=5)
        self.target = target
        self.deadline = deadline
        self.transport_socket: socket.socket | None = None
        # HTTPSConnection retains its certificate checks and hostname/SNI handling.
        # Only TCP address selection changes; it must never repeat a hostname lookup.
        self._create_connection = self._connect_approved

        class DeadlineResponse(http.client.HTTPResponse):
            def __init__(self, sock, debuglevel=0, method=None, url=None):
                super().__init__(sock, debuglevel=debuglevel, method=method, url=url)
                original = self.fp
                self.fp = io.BufferedReader(_DeadlineReader(sock, deadline))
                if original is not None:
                    original.close()

        self.response_class = DeadlineResponse

    def _remaining(self) -> float:
        return _remaining_time(self.deadline)

    def _connect_approved(self, address, timeout=5, source_address=None):
        if address != (self.target.hostname, self.target.port) or source_address is not None:
            raise ValueError("Unexpected source transport destination")
        failure: OSError = OSError("Unable to connect to source")
        for family, kind, protocol, _name, sockaddr in self.target.addresses:
            connection = socket.socket(family, kind, protocol)
            try:
                connection.settimeout(self._remaining())
                connection.connect(sockaddr)
                # HTTPSConnection wraps this socket immediately. Handshake time
                # must use what remains after TCP, not restart the initial budget.
                connection.settimeout(self._remaining())
                return connection
            except OSError as exc:
                connection.close()
                failure = exc
        raise failure

    def connect(self) -> None:
        super().connect()
        self.transport_socket = self.sock
        self.limit_read_time()

    def limit_read_time(self) -> None:
        if self.transport_socket is not None:
            self.transport_socket.settimeout(self._remaining())


def fetch_source_bytes(endpoint: str, headers: dict[str, str], allowed_hosts: set[str], limit: int) -> tuple[bytes, str]:
    target = resolve_external_target(endpoint, allowed_hosts)
    connection = _PinnedHTTPSConnection(target, time.monotonic() + 5)
    try:
        # Direct connections prevent ambient proxy settings from changing the approved destination.
        connection.request("GET", target.path, headers={"Accept": "application/json, text/plain", "Connection": "close", **headers})
        connection.limit_read_time()
        with connection.getresponse() as response:
            if 300 <= response.status < 400:
                raise ValidationError("رابط المصدر يعيد التوجيه؛ حدّثه إلى الرابط المباشر")
            if response.status == 429:
                raise ValidationError("المصدر يقيّد معدل الطلبات؛ أعد المحاولة لاحقًا")
            if not 200 <= response.status < 300:
                raise ValidationError("تعذر سحب السجلات من المصدر؛ تحقق من الاتصال والصلاحيات")
            body = bytearray()
            while len(body) <= limit and not response.isclosed():
                connection.limit_read_time()
                chunk = response.read1(min(65536, limit + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
            if len(body) > limit:
                raise ValidationError("Remote SIEM response exceeds 5 MiB limit")
            if response.length not in {None, 0}:
                raise ValidationError("انقطع رد المصدر قبل اكتماله؛ أعد المحاولة")
            return bytes(body), str(response.headers.get("Content-Type", "application/octet-stream"))
    except http.client.HTTPException as exc:
        raise ValidationError("تعذر سحب السجلات من المصدر؛ تحقق من الاتصال والصلاحيات") from exc
    finally:
        connection.close()
