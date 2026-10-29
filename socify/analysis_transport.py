import base64
import errno
import json
import socket
import struct
import time

MAX_REQUEST = 24 * 1024 * 1024
MAX_RESPONSE = 48 * 1024 * 1024


class AnalysisUnavailableError(ConnectionError):
    pass


class IncompleteMessageError(ValueError):
    pass


def receive(stream, maximum):
    def exact(size):
        parts = bytearray()
        while len(parts) < size:
            chunk = stream.recv(min(65536, size - len(parts)))
            if not chunk:
                raise IncompleteMessageError("Incomplete analysis message")
            parts.extend(chunk)
        return bytes(parts)

    size = struct.unpack("!I", exact(4))[0]
    if not 1 <= size <= maximum:
        raise ValueError("Analysis message exceeds limit")
    return json.loads(exact(size))


def send(stream, payload, maximum):
    encoded = json.dumps(payload, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()
    if len(encoded) > maximum:
        raise ValueError("Analysis message exceeds limit")
    stream.sendall(struct.pack("!I", len(encoded)) + encoded)


def remote_artifacts(path, payload, operation, formats, timeout):
    try:
        for delay in (0.1, 0.2, 0.4, None):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
                stream.settimeout(timeout + 5)
                try:
                    stream.connect(path)
                except (ConnectionRefusedError, FileNotFoundError):
                    if delay is None:
                        raise
                else:
                    # Never replay work after a request may have reached the service.
                    send(stream, {"operation": operation, "payload": payload}, MAX_REQUEST)
                    result = receive(stream, MAX_RESPONSE)
                    break
            if delay is not None:
                time.sleep(delay)
    except (OSError, IncompleteMessageError) as exc:
        reason = {
            errno.ENOENT: "socket missing; start the isolated analysis service",
            errno.ECONNREFUSED: "service not accepting connections",
            errno.EACCES: "socket permission denied; verify service UID/GID and socket mode",
            errno.EPERM: "socket access denied by operating-system policy",
            errno.EROFS: "read-only filesystem rejected the operation",
        }.get(getattr(exc, "errno", 0) or 0, "connection interrupted or timed out")
        raise AnalysisUnavailableError(f"Isolated analysis transport is temporarily unavailable: {reason}") from exc
    if not isinstance(result, dict) or set(result) != {"files"} or not isinstance(result["files"], dict) or set(result["files"]) != set(formats):
        raise ValueError("Isolated analysis service failed")
    files = {kind: base64.b64decode(value, validate=True) for kind, value in result["files"].items()}
    if any(len(content) > 20 * 1024 * 1024 for content in files.values()):
        raise ValueError("Analysis artifact exceeds limit")
    return files
