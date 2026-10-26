import ipaddress
from collections.abc import Callable, Iterable
from typing import Any

from werkzeug.exceptions import BadRequest, SecurityError
from werkzeug.wsgi import get_host


class CodespacesProxy:
    def __init__(self, application: Callable, public_host: str):
        self.application = application
        self.public_host = public_host

    def __call__(self, environ: dict[str, Any], start_response: Callable) -> Iterable[bytes]:
        try:
            address = ipaddress.ip_address(environ.get("REMOTE_ADDR", ""))
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
        except ValueError:
            return self.application(environ, start_response)
        protocol = environ.get("HTTP_X_FORWARDED_PROTO", "")
        secure = protocol == "https" or (not protocol and environ.get("wsgi.url_scheme") == "https" and environ.get("HTTP_X_FORWARDED_SSL") == "on")
        if not address.is_loopback or not secure:
            return self.application(environ, start_response)
        try:
            get_host(environ, trusted_hosts=[self.public_host, "localhost", "127.0.0.1", "[::1]"])
        except SecurityError as error:
            return error(environ, start_response)
        forwarded = environ.get("HTTP_X_FORWARDED_HOST", "").strip().lower()
        if forwarded and forwarded not in {self.public_host, f"{self.public_host}:443"}:
            return BadRequest("The forwarded host does not match this Codespace.")(environ, start_response)
        environ["HTTP_HOST"] = self.public_host
        environ["SERVER_NAME"] = self.public_host
        environ["SERVER_PORT"] = "443"
        environ["wsgi.url_scheme"] = "https"
        return self.application(environ, start_response)
