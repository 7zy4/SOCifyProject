import base64
import builtins
import ctypes
import errno
import hashlib
import io
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from socify import analysis_sandbox


def test_yara_validation_does_not_initialize_native_report_engines(tmp_path, monkeypatch):
    original = builtins.__import__

    def no_report_engine(name, *args, **kwargs):
        if name.split(".")[0] in {"weasyprint", "docx"}:
            raise ImportError("Synthetic unavailable report renderer")
        return original(name, *args, **kwargs)

    payload = {
        "rules": 'rule Startup { strings: $a = "SOCIFY" condition: $a }',
        "fixtures": {"positive": [base64.b64encode(b"SOCIFY").decode()], "negative": [base64.b64encode(b"normal").decode()]},
    }
    monkeypatch.setenv("SOCIFY_ANALYSIS_OPERATION", "yara_validation")
    monkeypatch.setenv("SOCIFY_ANALYSIS_OUTPUT", str(tmp_path))
    monkeypatch.setattr(analysis_sandbox.sys, "argv", ["analysis"])
    monkeypatch.setattr(analysis_sandbox.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode())))
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.setattr(analysis_sandbox, "harden", lambda _: {"scope": "dispatch test; real boundary tested independently"})
    monkeypatch.setattr(builtins, "__import__", no_report_engine)
    assert analysis_sandbox.main() == 0
    assert json.loads((tmp_path / "validation").read_text())["valid"]


@pytest.mark.parametrize("operation,invalid", [("sample", False), ("sample", True), ("report", False), ("probe", False)])
def test_analysis_dispatch_limits_and_artifact_contract_independent_of_os_policy(tmp_path, monkeypatch, operation, invalid):
    content = b"Synthetic EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    payload = {"sample_id": 1, "evidence_id": 1, "sha256": hashlib.sha256(content).hexdigest(), "content": base64.b64encode(content).decode()}
    if invalid:
        payload["sha256"] = "invalid"
    if operation == "report":
        payload = {"case": {"title": "Synthetic dispatch", "reference": "TEST-DISPATCH"}, "revision": 1, "summary": {"status": "synthetic"}}
    if operation == "probe":
        payload = {"paths": {"public_fixture": str(tmp_path / "fixture")}}
        (tmp_path / "fixture").write_text("Synthetic nonsecret fixture")
    monkeypatch.setenv("SOCIFY_ANALYSIS_OPERATION", operation)
    monkeypatch.setenv("SOCIFY_ANALYSIS_OUTPUT", str(tmp_path))
    monkeypatch.setattr(analysis_sandbox.sys, "argv", ["analysis"])
    monkeypatch.setattr(analysis_sandbox.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode())))
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.setattr(analysis_sandbox, "harden", lambda _: {"scope": "dispatch unit test; real OS policy tested separately"})
    assert analysis_sandbox.main() == (1 if invalid else 0)
    if invalid:
        assert (tmp_path / "error").read_text() == "ValueError"
        assert not (tmp_path / "done").exists()
    elif operation == "sample":
        result = json.loads((tmp_path / "analysis").read_bytes())
        assert result["sha256"] == payload["sha256"]
        assert result["yara_matches"][0]["rule"] == "SOCify_EICAR_Test_Marker"
    elif operation == "report":
        assert (tmp_path / "pdf").read_bytes().startswith(b"%PDF-")
        assert (tmp_path / "docx").read_bytes().startswith(b"PK")
    else:
        result = json.loads((tmp_path / "probe").read_text())
        assert result["denied"]["public_fixture"] is False
        assert result["denied"]["network"] is False


def test_analysis_entrypoint_rejects_invalid_operation_oversized_input_and_output(tmp_path, monkeypatch):
    monkeypatch.setattr(analysis_sandbox.sys, "argv", ["analysis"])
    monkeypatch.setenv("SOCIFY_ANALYSIS_OPERATION", "unknown")
    assert analysis_sandbox.main() == 2
    monkeypatch.setenv("SOCIFY_ANALYSIS_OPERATION", "sample")
    monkeypatch.setenv("SOCIFY_ANALYSIS_OUTPUT", str(tmp_path))
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.setattr(analysis_sandbox.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"x" * 20)))
    monkeypatch.setattr(analysis_sandbox, "MAX_INPUT", 10)
    assert analysis_sandbox.main() == 1
    assert not (tmp_path / "done").exists()
    monkeypatch.setenv("SOCIFY_ANALYSIS_OPERATION", "probe")
    monkeypatch.setattr(analysis_sandbox.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"{}")))
    monkeypatch.setattr(analysis_sandbox, "harden", lambda _: {})
    monkeypatch.setattr(analysis_sandbox, "probe", lambda *_: {"bounded": "x" * 100})
    monkeypatch.setattr(analysis_sandbox, "MAX_OUTPUT", 10)
    assert analysis_sandbox.main() == 1
    assert not (tmp_path / "done").exists()


def test_os_boundary_fails_closed_without_dedicated_container_contract(tmp_path, monkeypatch):
    limits = []
    monkeypatch.setattr(analysis_sandbox.resource, "setrlimit", lambda key, value: limits.append((key, value)))
    monkeypatch.setattr(ctypes, "CDLL", lambda *_args, **_kwargs: SimpleNamespace(prctl=lambda *_: 0))
    monkeypatch.setattr(analysis_sandbox, "restrict_filesystem", lambda *_: (_ for _ in ()).throw(OSError(errno.ENOSYS, "Unsupported fixture kernel")))
    monkeypatch.setattr(analysis_sandbox, "restrict_syscalls", lambda: None)
    monkeypatch.delenv("SOCIFY_ISOLATED_ANALYSIS_CONTAINER", raising=False)
    with pytest.raises(OSError) as error:
        analysis_sandbox.harden(tmp_path)
    assert error.value.errno == errno.ENOSYS
    assert len(limits) == 5
    monkeypatch.setenv("SOCIFY_ISOLATED_ANALYSIS_CONTAINER", "1")
    monkeypatch.chdir(tmp_path)
    assert analysis_sandbox.harden(tmp_path)["database_access"] == "not-mounted-in-analysis-container"
    monkeypatch.setattr(analysis_sandbox, "restrict_filesystem", lambda *_: (_ for _ in ()).throw(OSError(errno.EPERM, "Denied fixture kernel")))
    with pytest.raises(OSError):
        analysis_sandbox.harden(tmp_path)


def test_landlock_permission_adapter_allows_only_runtime_reads_and_job_directory_writes(tmp_path, monkeypatch):
    observed = []

    class Syscall:
        def __call__(self, number, *args):
            if number == 444:
                if args[0] == 0:
                    return 5
                return analysis_sandbox.os.open("/dev/null", analysis_sandbox.os.O_RDONLY)
            if number == 445:
                rule = ctypes.cast(args[2], ctypes.POINTER(analysis_sandbox.PathRule)).contents
                observed.append((Path(analysis_sandbox.os.readlink(f"/proc/self/fd/{rule.parent_fd}")), rule.allowed_access))
            return 0

    monkeypatch.setattr(ctypes, "CDLL", lambda *_args, **_kwargs: SimpleNamespace(syscall=Syscall(), prctl=lambda *_: 0))
    assert analysis_sandbox.restrict_filesystem(tmp_path) == 5
    paths = {path: access for path, access in observed}
    assert tmp_path in paths and paths[tmp_path] & analysis_sandbox.WRITE_FILE
    project = Path(__file__).resolve().parents[2]
    assert project not in paths and Path("/data") not in paths and Path("/proc") not in paths
    assert all(not access & analysis_sandbox.WRITE_FILE for path, access in paths.items() if path not in {tmp_path, Path("/dev/null")})
    ctypes.set_errno(errno.EPERM)
    with pytest.raises(OSError):
        analysis_sandbox._checked(-1)


def test_probe_detects_absent_scratch_and_metadata_isolation(tmp_path):
    roots = [tmp_path / name for name in ("temporary", "shared", "ipc")]
    for root in roots:
        root.mkdir()
    observed = analysis_sandbox.probe({"paths": {}, "scratch_persistence_test": True}, {"scope": "unhardened negative-control fixture"}, scratch_roots=roots)
    assert all(observed["scratch_writes"].values())
    assert observed["denied"]["ipc_permission_change"] is False
