import ctypes
import errno
import json
import os
import resource
import sys
import sysconfig
from pathlib import Path

MAX_INPUT = 24 * 1024 * 1024
MAX_OUTPUT = 20 * 1024 * 1024
READ_FILE = 1 << 2
READ_DIR = 1 << 3
WRITE_FILE = 1 << 1
REMOVE_DIR = 1 << 4
REMOVE_FILE = 1 << 5
MAKE_DIR = 1 << 7
MAKE_REG = 1 << 8
REFER = 1 << 13
TRUNCATE = 1 << 14


class Ruleset(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class PathRule(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


class ArgumentComparison(ctypes.Structure):
    _fields_ = [("argument", ctypes.c_uint), ("operation", ctypes.c_int), ("mask", ctypes.c_uint64), ("value", ctypes.c_uint64)]


def _checked(value):
    if value < 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))
    return value


def restrict_filesystem(directory: Path) -> int:
    if sys.platform != "linux":
        raise RuntimeError("Linux Landlock and seccomp are required for local analysis")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    abi = _checked(libc.syscall(444, 0, 0, 1))
    if abi < 3:
        raise RuntimeError("Landlock ABI 3 or newer is required")
    handled = (1 << 15) - 1
    if abi >= 5:
        handled |= 1 << 15
    attributes = Ruleset(handled)
    ruleset = _checked(libc.syscall(444, ctypes.byref(attributes), ctypes.sizeof(attributes), 0))
    root = Path(__file__).resolve().parent.parent
    readable = [
        Path(sysconfig.get_path("stdlib")),
        *(Path(path) for path in sys.path if path.endswith("site-packages")),
        Path("/usr/lib"),
        Path("/lib"),
        Path("/lib64"),
        Path("/etc/fonts"),
        Path("/usr/share/fonts"),
        Path("/usr/local/share/fonts"),
        Path("/usr/share/fontconfig"),
        Path("/var/cache/fontconfig"),
        Path("/etc/ld.so.cache"),
        Path("/etc/localtime"),
        Path("/usr/share/zoneinfo"),
        root / "static" / "fonts",
        root / "static" / "report.css",
        root / "static" / "design-tokens.json",
        Path("/dev/urandom"),
        Path("/dev/random"),
    ]
    try:
        paths = {path.resolve(): READ_FILE | (READ_DIR if path.is_dir() else 0) for path in readable if path.exists()}
        paths[directory.resolve()] = READ_FILE | READ_DIR | WRITE_FILE | REMOVE_DIR | REMOVE_FILE | MAKE_DIR | MAKE_REG | REFER | TRUNCATE
        paths[Path("/dev/null")] = READ_FILE | WRITE_FILE
        for path, access in paths.items():
            descriptor = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                rule = PathRule(access, descriptor)
                _checked(libc.syscall(445, ruleset, 1, ctypes.byref(rule), 0))
            finally:
                os.close(descriptor)
        _checked(libc.prctl(38, 1, 0, 0, 0))
        _checked(libc.syscall(446, ruleset, 0))
    finally:
        os.close(ruleset)
    return abi


def restrict_syscalls() -> None:
    library = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    library.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    library.seccomp_rule_add.restype = ctypes.c_int
    library.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint, ctypes.POINTER(ArgumentComparison)]
    library.seccomp_rule_add_array.restype = ctypes.c_int
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_load.restype = ctypes.c_int
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    context = library.seccomp_init(0x7FFF0000)
    if not context:
        raise RuntimeError("Unable to create seccomp filter")
    denied = (
        "socket",
        "socketpair",
        "connect",
        "bind",
        "listen",
        "accept",
        "accept4",
        "sendto",
        "sendmsg",
        "sendmmsg",
        "ptrace",
        "process_vm_readv",
        "process_vm_writev",
        "pidfd_getfd",
        "pidfd_send_signal",
        "kill",
        "tkill",
        "tgkill",
        "execve",
        "execveat",
        "fork",
        "vfork",
        "unshare",
        "setns",
        "mount",
        "umount2",
        "pivot_root",
        "chroot",
        "bpf",
        "perf_event_open",
        "userfaultfd",
        "io_uring_setup",
        "open_by_handle_at",
        "name_to_handle_at",
        "keyctl",
        "add_key",
        "request_key",
        "chmod",
        "fchmod",
        "fchmodat",
        "fchmodat2",
        "chown",
        "fchown",
        "fchownat",
        "lchown",
        "utime",
        "utimes",
        "futimesat",
        "utimensat",
        "mq_open",
        "mq_unlink",
        "mq_timedsend",
        "mq_timedreceive",
        "mq_notify",
        "mq_getsetattr",
        "shmget",
        "shmat",
        "shmdt",
        "shmctl",
        "semget",
        "semop",
        "semtimedop",
        "semctl",
        "msgget",
        "msgsnd",
        "msgrcv",
        "msgctl",
    )
    try:
        for name in denied:
            identifier = library.seccomp_syscall_resolve_name(name.encode())
            if identifier < 0 and name in {"fchmodat2", "io_uring_setup", "pidfd_getfd", "process_vm_readv", "process_vm_writev"}:
                raise RuntimeError("libseccomp cannot resolve a required security boundary syscall")
            if identifier >= 0 and library.seccomp_rule_add(context, 0x00050000 | errno.EPERM, identifier, 0) != 0:
                raise RuntimeError("Unable to install a required syscall rule")
        clone = library.seccomp_syscall_resolve_name(b"clone")
        comparison = ArgumentComparison(0, 7, 0x10000, 0)
        if clone < 0 or library.seccomp_rule_add_array(context, 0x00050000 | errno.EPERM, clone, 1, ctypes.byref(comparison)) != 0:
            raise RuntimeError("Unable to restrict process creation while allowing native font threads")
        clone3 = library.seccomp_syscall_resolve_name(b"clone3")
        if clone3 < 0 or library.seccomp_rule_add(context, 0x00050000 | errno.ENOSYS, clone3, 0) != 0:
            raise RuntimeError("Unable to enforce legacy clone flag validation")
        if library.seccomp_load(context) != 0:
            raise RuntimeError("Unable to enforce seccomp filter")
    finally:
        library.seccomp_release(context)


def harden(directory: Path) -> dict:
    resource.setrlimit(resource.RLIMIT_CPU, (40, 45))
    resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024 * 1024, 1536 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_FSIZE, (24 * 1024 * 1024, 24 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    _checked(libc.prctl(4, 0, 0, 0, 0))
    try:
        abi = restrict_filesystem(directory)
        filesystem = "linux-landlock"
    except OSError as exc:
        if exc.errno not in {errno.ENOSYS, errno.EOPNOTSUPP} or os.environ.get("SOCIFY_ISOLATED_ANALYSIS_CONTAINER") != "1":
            raise
        abi, filesystem = None, "dedicated-readonly-container-without-database-or-credentials"
    restrict_syscalls()
    os.chdir(directory)
    return {
        "filesystem": filesystem,
        "landlock_abi": abi,
        "syscalls": "linux-seccomp",
        "environment": "fresh-minimal",
        "network": "kernel-denied",
        "database_access": "landlock-denied" if abi else "not-mounted-in-analysis-container",
        "process_introspection": "kernel-denied",
    }


def main() -> int:
    operation = os.environ.get("SOCIFY_ANALYSIS_OPERATION")
    output = os.environ.get("SOCIFY_ANALYSIS_OUTPUT")
    if len(sys.argv) != 1 or operation not in {"report", "sample", "probe", "yara_validation"} or not output:
        return 2
    directory = Path(output).resolve()
    phase = "imports"
    try:
        import tempfile

        from .autopsy_domain import canonical

        # Load only the selected engine before installing its OS boundary.
        # A YARA request must not depend on native PDF/font initialization.
        if operation == "report":
            from docx import Document
            from weasyprint import HTML

            from .autopsy_report_render import render_files

            _ = Document, HTML
        elif operation in {"sample", "yara_validation"}:
            from .autopsy_static_analysis import analyze_sample, validate_yara

        tempfile.tempdir = str(directory)
        phase = "input"
        body = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(body) > MAX_INPUT:
            raise ValueError("Analysis request exceeds limit")
        payload = json.loads(body)
        phase = "boundary"
        boundary = harden(directory)
        phase = "compute"
        if operation == "sample":
            result = analyze_sample(payload)
            result["isolation"] = boundary
            files = {"analysis": canonical(result).encode()}
        elif operation == "yara_validation":
            result = validate_yara(payload)
            result["isolation"] = boundary
            files = {"validation": canonical(result).encode()}
        elif operation == "report":
            files = render_files(payload)
        else:
            files = {"probe": canonical(probe(payload, boundary)).encode()}
        phase = "output"
        for name, content in files.items():
            if len(content) > MAX_OUTPUT:
                raise ValueError("Analysis artifact exceeds limit")
            (directory / name).write_bytes(content)
        (directory / "done").write_text("ok")
        return 0
    except Exception as exc:
        (directory / "error").write_text(type(exc).__name__)
        # Never include source rules, evidence, exception messages, or secrets.
        (directory / "diagnostic.json").write_text(
            json.dumps({"phase": phase, "error_type": type(exc).__name__, "errno": exc.errno if isinstance(exc, OSError) else None})
        )
        return 1


def probe(payload, boundary, scratch_roots=None):
    import socket

    result = {"isolation": boundary, "environment_keys": sorted(os.environ), "denied": {}}
    if payload.get("scratch_persistence_test") is True:
        roots = scratch_roots or (Path(os.environ["SOCIFY_ANALYSIS_OUTPUT"]).parent, Path("/dev") / "shm", Path("/analysis-ipc"))
        result["scratch_writes"] = {}
        for root in roots:
            path = Path(root) / "socify-isolation-marker"
            try:
                path.write_text("Synthetic isolation acceptance marker")
                result["scratch_writes"][str(path)] = True
            except PermissionError:
                result["scratch_writes"][str(path)] = False
        try:
            os.chmod(roots[-1], 0o700)
            result["denied"]["ipc_permission_change"] = False
        except PermissionError:
            result["denied"]["ipc_permission_change"] = True
    for name, path in payload["paths"].items():
        try:
            Path(path).read_bytes()
            result["denied"][name] = False
        except (PermissionError, FileNotFoundError):
            result["denied"][name] = True
    for name, action in (
        ("network", lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM)),
        ("unix_socket", lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)),
        ("process_memory", lambda: os.open(f"/proc/{os.getppid()}/mem", os.O_RDONLY)),
        ("parent_environment", lambda: os.open(f"/proc/{os.getppid()}/environ", os.O_RDONLY)),
    ):
        try:
            opened = action()
            if isinstance(opened, int):
                os.close(opened)
            else:
                opened.close()
            result["denied"][name] = False
        except PermissionError:
            result["denied"][name] = True
    return result


if __name__ == "__main__":
    raise SystemExit(main())
