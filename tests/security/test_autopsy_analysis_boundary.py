import base64
import hashlib
import json
import multiprocessing
import os
import socket
import struct
import tempfile
import threading
from pathlib import Path

import pytest

from socify.analysis_transport import receive, remote_artifacts, send
from socify.autopsy_worker import compute_artifacts, read_artifact


def syscall_probe(connection):
    from socify.analysis_sandbox import restrict_syscalls

    directory = tempfile.TemporaryDirectory(prefix="socify-seccomp-owned-")
    owned = Path(directory.name) / "owned"
    owned.write_text("Synthetic owned permission fixture")
    restrict_syscalls()
    result = {}
    for name, action in (("network", lambda: socket.socket(socket.AF_INET)), ("process", os.fork), ("metadata", lambda: os.chmod(owned, 0o700))):
        try:
            action()
            result[name] = False
        except PermissionError:
            result[name] = True
    observed = []
    thread = threading.Thread(target=lambda: observed.append("native-font-thread-allowed"))
    thread.start()
    thread.join(timeout=2)
    result["threads"] = observed == ["native-font-thread-allowed"]
    connection.send(result)
    connection.close()
    directory.cleanup()


def test_real_kernel_seccomp_blocks_network_and_fork_but_preserves_native_font_threads():
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(target=syscall_probe, args=(child,))
    process.start()
    child.close()
    try:
        assert parent.poll(20), "Seccomp probe did not return"
        assert parent.recv() == {"network": True, "process": True, "metadata": True, "threads": True}
        process.join(timeout=5)
        assert process.exitcode == 0
    finally:
        parent.close()
        if process.is_alive():
            process.kill()
            process.join(timeout=5)


def test_analysis_child_cannot_read_coordinator_database_keys_or_process_memory(tmp_path):
    private = tmp_path / "coordinator-private.db"
    private.write_text("Synthetic company evidence visible only to the coordinator")
    content = compute_artifacts({"paths": {"coordinator_private": str(private), "database": "/data/socify.db"}}, "probe", ["probe"], 30)
    result = json.loads(content["probe"])
    assert all(result["denied"].values()), result
    assert {"network", "unix_socket", "process_memory", "coordinator_private", "database", "parent_environment"} <= set(result["denied"])
    assert not {"SOCIFY_SECRET_KEY", "SOCIFY_CREDENTIAL_KEY", "SOCIFY_DATABASE", "HTTP_PROXY", "HTTPS_PROXY"} & set(result["environment_keys"])
    assert result["isolation"]["syscalls"] == "linux-seccomp"
    assert result["isolation"]["database_access"] in {"landlock-denied", "not-mounted-in-analysis-container"}


def test_local_analysis_rejects_unknown_operation_and_oversized_input(monkeypatch):
    monkeypatch.delenv("SOCIFY_ANALYSIS_SOCKET", raising=False)
    with pytest.raises(ValueError):
        compute_artifacts({}, "unknown", [], 1)
    with pytest.raises(ValueError):
        compute_artifacts({"content": "x" * (24 * 1024 * 1024 + 1)}, "sample", [], 1)


def test_analysis_output_must_be_regular_single_link_and_bounded(tmp_path):
    output = tmp_path / "artifact"
    output.write_bytes(b"bounded result")
    assert read_artifact(output) == b"bounded result"
    with pytest.raises(ValueError):
        read_artifact(output, 1)
    link = tmp_path / "linked"
    link.symlink_to(output)
    with pytest.raises(OSError):
        read_artifact(link)
    hard = tmp_path / "hard"
    os.link(output, hard)
    with pytest.raises(ValueError):
        read_artifact(output)


def test_analysis_transport_rejects_incomplete_and_oversized_messages():
    for content in (struct.pack("!I", 101), b"\x00\x00", struct.pack("!I", 5) + b"{"):
        client, server = socket.socketpair()
        with client, server:
            client.sendall(content)
            client.shutdown(socket.SHUT_WR)
            with pytest.raises(ValueError):
                receive(server, 100)
    client, server = socket.socketpair()
    with client, server:
        with pytest.raises(ValueError):
            send(client, {"too_large": "x" * 100}, 10)
        send(client, {"result": "bounded"}, 100)
        assert receive(server, 100) == {"result": "bounded"}


@pytest.mark.parametrize("response", [{"error": "DENIED"}, {"files": {"wrong": ""}}, {"files": {"analysis": "invalid-base64"}}])
def test_remote_analysis_validates_result_protocol(tmp_path, response):
    path = str(tmp_path / "server.sock")
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(path)
        listener.listen(1)

        def answer():
            stream, _ = listener.accept()
            with stream:
                receive(stream, 10000)
                send(stream, response, 10000)

        thread = threading.Thread(target=answer)
        thread.start()
        try:
            with pytest.raises(ValueError):
                remote_artifacts(path, {}, "sample", ["analysis"], 1)
        finally:
            thread.join(timeout=5)


def test_yara_result_is_real_and_preserves_sample_sha256():
    content = b"Synthetic EICAR-STANDARD-ANTIVIRUS-TEST-FILE acceptance marker"
    result = json.loads(
        compute_artifacts(
            {"sample_id": 1, "evidence_id": 1, "sha256": hashlib.sha256(content).hexdigest(), "content": base64.b64encode(content).decode()},
            "sample",
            ["analysis"],
            30,
        )["analysis"]
    )
    assert result["sha256"] == hashlib.sha256(content).hexdigest()
    assert result["yara_matches"][0]["rule"] == "SOCify_EICAR_Test_Marker"


def test_analysis_jobs_cannot_persist_case_data_in_shared_scratch_or_ipc():
    written = json.loads(compute_artifacts({"paths": {}, "scratch_persistence_test": True}, "probe", ["probe"], 30)["probe"])
    assert written["denied"]["ipc_permission_change"] is True
    assert written["scratch_writes"]["/analysis-ipc/socify-isolation-marker"] is False
    checked = json.loads(
        compute_artifacts(
            {
                "paths": {
                    "previous_tmp": str(Path(tempfile.gettempdir()) / "socify-isolation-marker"),
                    "previous_shm": str(Path("/dev") / "shm" / "socify-isolation-marker"),
                    "previous_ipc": "/analysis-ipc/socify-isolation-marker",
                }
            },
            "probe",
            ["probe"],
            30,
        )["probe"]
    )
    assert all(checked["denied"].values())
