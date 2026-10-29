import base64
import errno
import json
import struct

import pytest

from socify.analysis_transport import AnalysisUnavailableError, remote_artifacts


class Stream:
    def __init__(self, error=None, reply=None):
        self.error = error
        encoded = json.dumps(reply or {"files": {"analysis": base64.b64encode(b"retained result").decode()}}).encode()
        self.response = struct.pack("!I", len(encoded)) + encoded
        self.sent = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True

    def settimeout(self, value):
        self.timeout = value

    def connect(self, path):
        if self.error:
            raise self.error

    def sendall(self, content):
        self.sent.append(content)

    def recv(self, length):
        result, self.response = self.response[:length], self.response[length:]
        return result


def setup_streams(monkeypatch, streams):
    attempts, waits = [], []

    def create(*_):
        stream = streams[len(attempts)]
        attempts.append(stream)
        return stream

    monkeypatch.setattr("socify.analysis_transport.socket.socket", create)
    monkeypatch.setattr("socify.analysis_transport.time.sleep", waits.append)
    return attempts, waits


def test_startup_retry_closes_failed_connections_and_sends_only_once(monkeypatch):
    streams = [Stream(ConnectionRefusedError(errno.ECONNREFUSED, "starting")), Stream(FileNotFoundError(errno.ENOENT, "starting")), Stream()]
    attempts, waits = setup_streams(monkeypatch, streams)
    assert remote_artifacts("/ipc/analysis.sock", {}, "sample", ["analysis"], 1) == {"analysis": b"retained result"}
    assert len(attempts) == 3 and waits == [0.1, 0.2]
    assert all(stream.closed for stream in streams)
    assert [len(stream.sent) for stream in streams] == [0, 0, 1]


@pytest.mark.parametrize("code,message", [(errno.ENOENT, "socket missing"), (errno.ECONNREFUSED, "not accepting")])
def test_startup_retries_are_bounded(monkeypatch, code, message):
    attempts, waits = setup_streams(monkeypatch, [Stream(OSError(code, "unavailable")) for _ in range(4)])
    with pytest.raises(AnalysisUnavailableError, match=message):
        remote_artifacts("/ipc/analysis.sock", {}, "sample", ["analysis"], 1)
    assert len(attempts) == 4 and waits == [0.1, 0.2, 0.4]
    assert all(stream.closed and not stream.sent for stream in attempts)


@pytest.mark.parametrize("code", [errno.EACCES, errno.EPERM, errno.EROFS])
def test_permission_failures_are_not_retried(monkeypatch, code):
    attempts, waits = setup_streams(monkeypatch, [Stream(OSError(code, "denied"))])
    with pytest.raises(AnalysisUnavailableError):
        remote_artifacts("/ipc/analysis.sock", {}, "sample", ["analysis"], 1)
    assert len(attempts) == 1 and waits == [] and attempts[0].closed


def test_incomplete_response_never_replays_submitted_work(monkeypatch):
    stream = Stream()
    stream.response = b"\x00\x00"
    attempts, waits = setup_streams(monkeypatch, [stream])
    with pytest.raises(AnalysisUnavailableError, match="interrupted"):
        remote_artifacts("/ipc/analysis.sock", {}, "sample", ["analysis"], 1)
    assert len(attempts) == 1 and len(stream.sent) == 1 and waits == [] and stream.closed


def test_unsupported_host_fails_closed_with_service_instructions(monkeypatch):
    from socify.autopsy_worker import compute_artifacts

    monkeypatch.delenv("SOCIFY_ANALYSIS_SOCKET", raising=False)
    monkeypatch.setattr("socify.autopsy_worker.sys.platform", "win32")
    with pytest.raises(AnalysisUnavailableError, match="Docker analysis service"):
        compute_artifacts({}, "probe", ["probe"], 1)


def test_unavailable_process_reports_actionable_diagnostic(monkeypatch):
    from socify.autopsy_worker import compute_artifacts

    def unavailable(*args, **kwargs):
        raise FileNotFoundError(errno.ENOENT, "procfs unavailable")

    monkeypatch.delenv("SOCIFY_ANALYSIS_SOCKET", raising=False)
    monkeypatch.setattr("socify.autopsy_worker.subprocess.run", unavailable)
    with pytest.raises(AnalysisUnavailableError, match="verify procfs"):
        compute_artifacts({}, "probe", ["probe"], 1)
