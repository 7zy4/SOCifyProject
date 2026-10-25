import base64
import json
import socket
import struct

MAX_REQUEST = 24 * 1024 * 1024
MAX_RESPONSE = 48 * 1024 * 1024


def receive(stream, maximum):
    def exact(size):
        parts = bytearray()
        while len(parts) < size:
            chunk = stream.recv(min(65536, size - len(parts)))
            if not chunk:
                raise ValueError("Incomplete analysis message")
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
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(timeout + 5)
        stream.connect(path)
        send(stream, {"operation": operation, "payload": payload}, MAX_REQUEST)
        result = receive(stream, MAX_RESPONSE)
    if not isinstance(result, dict) or set(result) != {"files"} or not isinstance(result["files"], dict) or set(result["files"]) != set(formats):
        raise ValueError("Isolated analysis service failed")
    files = {kind: base64.b64decode(value, validate=True) for kind, value in result["files"].items()}
    if any(len(content) > 20 * 1024 * 1024 for content in files.values()):
        raise ValueError("Analysis artifact exceeds limit")
    return files
