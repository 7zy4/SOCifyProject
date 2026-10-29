import base64
import ctypes
import fcntl
import os
import shutil
import socket
import stat
import tempfile
import time
from contextlib import contextmanager, suppress
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
    scratch_roots = (Path(tempfile.gettempdir()), Path("/dev") / "shm")
    if scratch_roots[0] != Path("/") / "tmp":
        raise RuntimeError("Analysis service requires its dedicated temporary mount")
    for root in scratch_roots:
        records = [line.split() for line in mounts if line.split()[4] == str(root)]
        if (
            len(records) != 1
            or records[0][3] != "/"
            or records[0][records[0].index("-") + 1] != "tmpfs"
            or not {"noexec", "nosuid", "nodev"} <= set(records[0][5].split(","))
        ):
            raise RuntimeError("Analysis scratch storage must use dedicated hardened tmpfs mounts")
    return scratch_roots


@contextmanager
def singleton(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size or metadata.st_mode & 0o222 or metadata.st_uid != os.getuid():
            raise RuntimeError("Analysis lease must be an empty immutable-access regular file")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def main():
    scratch_roots = verify_container()
    if ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0) != 0:
        raise RuntimeError("Unable to protect analysis coordinator memory")
    path = Path("/analysis-ipc/analysis.sock")
    os.umask(0o007)
    with singleton(path.parent / "analysis.lock"), socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        if any(entry.name not in {"analysis.sock", "analysis.lock"} for entry in path.parent.iterdir()):
            raise RuntimeError("Unexpected files in analysis IPC storage; refusing to expose them to analysis jobs")
        with suppress(PermissionError):
            path.parent.chmod(0o770)
        path.unlink(missing_ok=True)
        server.bind(str(path))
        path.chmod(0o660)
        server.listen(8)
        with suppress(PermissionError):
            path.parent.chmod(0o555)
        deadline = time.monotonic() + 30
        while os.access(path.parent, os.W_OK):
            if time.monotonic() >= deadline:
                raise RuntimeError("Analysis IPC directory must be read-only before accepting work")
            time.sleep(0.05)
        clear_scratch(scratch_roots)
        while True:
            stream, _ = server.accept()
            with stream:
                stream.settimeout(60)
                try:
                    message = receive(stream, MAX_REQUEST)
                    if not isinstance(message, dict) or set(message) != {"operation", "payload"} or not isinstance(message["operation"], str):
                        raise ValueError("Invalid analysis operation")
                    operation = message["operation"]
                    if operation not in {"report", "sample", "probe", "yara_validation"}:
                        raise ValueError("Unknown analysis operation")
                    formats = list(FORMATS) if operation == "report" else [{"sample": "analysis", "probe": "probe", "yara_validation": "validation"}[operation]]
                    try:
                        files = compute_artifacts(message["payload"], operation, formats, 50 if operation == "report" else 30, isolated_container=True)
                    finally:
                        clear_scratch(scratch_roots)
                    send(stream, {"files": {kind: base64.b64encode(content).decode() for kind, content in files.items()}}, MAX_RESPONSE)
                except (ValueError, TypeError, OSError, TimeoutError, RecursionError):
                    with suppress(OSError):
                        send(stream, {"error": "ISOLATED_ANALYSIS_FAILED"}, MAX_RESPONSE)


def clear_scratch(scratch_roots):
    try:
        for scratch in scratch_roots:
            for entry in scratch.iterdir():
                if entry.is_dir() and not entry.is_symlink():
                    entry.chmod(0o700)
                    for root_path, directories, _files in os.walk(entry, followlinks=False):
                        for name in directories:
                            child = Path(root_path) / name
                            if not child.is_symlink():
                                child.chmod(0o700)
                    shutil.rmtree(entry)
                else:
                    entry.unlink()
    except OSError as exc:
        raise RuntimeError("Scratch isolation could not be restored; refusing subsequent cases") from exc


if __name__ == "__main__":
    main()
