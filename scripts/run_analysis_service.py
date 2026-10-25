import base64
import ctypes
import os
import socket
from contextlib import suppress
from pathlib import Path

from socify.analysis_transport import MAX_REQUEST, MAX_RESPONSE, receive, send
from socify.autopsy_report_render import FORMATS
from socify.autopsy_worker import compute_artifacts


def verify_container():
    if os.environ.get("SOCIFY_ISOLATED_ANALYSIS_CONTAINER") != "1" or any(
        key in os.environ for key in ("SOCIFY_SECRET_KEY", "SOCIFY_CREDENTIAL_KEY", "SOCIFY_DATABASE")
    ):
        raise RuntimeError("Analysis service requires a dedicated credential-free container")
    if os.getuid() == 0 or Path("/data").exists():
        raise RuntimeError("Analysis service must be unprivileged and have no data mount")
    mounts = Path("/proc/self/mountinfo").read_text().splitlines()
    if not any(line.split()[4] == "/" and "ro" in line.split()[5].split(",") for line in mounts):
        raise RuntimeError("Analysis service requires a read-only root filesystem")
    routes = Path("/proc/net/route").read_text().splitlines()[1:]
    if any(line.split()[1] == "00000000" for line in routes if len(line.split()) > 2):
        raise RuntimeError("Analysis service must have no default network route")


def main():
    verify_container()
    if ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0) != 0:
        raise RuntimeError("Unable to protect analysis coordinator memory")
    path = Path("/analysis-ipc/analysis.sock")
    path.unlink(missing_ok=True)
    os.umask(0o007)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        server.listen(8)
        while True:
            stream, _ = server.accept()
            with stream:
                stream.settimeout(60)
                try:
                    message = receive(stream, MAX_REQUEST)
                    if not isinstance(message, dict) or set(message) != {"operation", "payload"} or not isinstance(message["operation"], str):
                        raise ValueError("Invalid analysis operation")
                    operation = message["operation"]
                    if operation not in {"report", "sample", "probe"}:
                        raise ValueError("Unknown analysis operation")
                    formats = list(FORMATS) if operation == "report" else ["analysis" if operation == "sample" else "probe"]
                    files = compute_artifacts(message["payload"], operation, formats, 50 if operation == "report" else 30, isolated_container=True)
                    send(stream, {"files": {kind: base64.b64encode(content).decode() for kind, content in files.items()}}, MAX_RESPONSE)
                except (ValueError, TypeError, OSError, TimeoutError, RecursionError):
                    with suppress(OSError):
                        send(stream, {"error": "ISOLATED_ANALYSIS_FAILED"}, MAX_RESPONSE)


if __name__ == "__main__":
    main()
