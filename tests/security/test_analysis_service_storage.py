from pathlib import Path

import pytest

from scripts.run_analysis_service import clear_scratch, singleton
from socify import analysis_sandbox


def test_scratch_cleanup_removes_restricted_directories_without_following_links(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    retained = outside / "must-stay"
    retained.write_text("Synthetic retained external fixture")
    nested = scratch / "restricted" / "nested"
    nested.mkdir(parents=True)
    (nested / "payload").write_text("Synthetic case residue")
    (scratch / "outside-link").symlink_to(outside, target_is_directory=True)
    nested.chmod(0)
    nested.parent.chmod(0)
    clear_scratch([scratch])
    assert list(scratch.iterdir()) == []
    assert retained.read_text() == "Synthetic retained external fixture"


def test_scratch_cleanup_failure_stops_service_instead_of_accepting_next_case(tmp_path, monkeypatch):
    marker = tmp_path / "marker"
    marker.write_text("Synthetic residue")

    def denied(*_args, **_kwargs):
        raise PermissionError("Synthetic failed cleanup")

    monkeypatch.setattr(Path, "unlink", denied)
    with pytest.raises(RuntimeError, match="refusing subsequent cases"):
        clear_scratch([tmp_path])


def test_analysis_lease_is_readonly_empty_and_excludes_concurrent_service(tmp_path):
    lock = tmp_path / "analysis.lock"
    with singleton(lock):
        assert lock.stat().st_size == 0
        assert lock.stat().st_mode & 0o222 == 0
        with pytest.raises(BlockingIOError), singleton(lock):
            pytest.fail("Concurrent service acquired an exclusive lease")
    with singleton(lock):
        assert lock.read_bytes() == b""
    lock.chmod(0o600)
    lock.write_text("Untrusted shared-state payload")
    with pytest.raises(RuntimeError), singleton(lock):
        pytest.fail("Lease file accepted mutable case data")


@pytest.mark.parametrize("missing", [b"fchmodat2", b"clone3"])
def test_missing_security_critical_syscall_resolution_fails_before_loading_filter(monkeypatch, missing):
    library = analysis_sandbox.ctypes.CDLL("libseccomp.so.2", use_errno=True)
    original = library.seccomp_syscall_resolve_name

    class Resolver:
        def __call__(self, name):
            return -1 if name == missing else original(name)

    library.seccomp_syscall_resolve_name = Resolver()
    monkeypatch.setattr(analysis_sandbox.ctypes, "CDLL", lambda *_args, **_kwargs: library)
    with pytest.raises(RuntimeError, match="required|legacy"):
        analysis_sandbox.restrict_syscalls()
