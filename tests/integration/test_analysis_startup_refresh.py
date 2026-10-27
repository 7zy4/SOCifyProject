"""A rebuilt development image must not strand startup behind its old container."""

import json
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/start_local_analysis.sh"


@pytest.mark.parametrize(
    ("refresh", "different_mount", "stop_fails", "replaced"),
    [(True, False, False, True), (False, False, False, False), (True, True, False, False), (True, False, True, False)],
)
def test_rebuild_only_replaces_expected_backend(tmp_path, refresh, different_mount, stop_fails, replaced):
    directory = tmp_path / "ipc"
    directory.mkdir()
    sentinel = directory / "retained-evidence"
    sentinel.write_text("preserved")
    trace = tmp_path / "docker-calls.jsonl"
    docker = tmp_path / "docker"
    docker.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "args = sys.argv[1:]\n"
        "with open(os.environ['TRACE'], 'a') as output: output.write(json.dumps(args) + '\\n')\n"
        "if args[:2] == ['image', 'inspect']: print('new-image')\n"
        "elif args[:2] == ['container', 'inspect'] and '--format' in args:\n"
        "    query = args[args.index('--format') + 1]\n"
        "    print(os.environ['MOUNT'] if '.Mounts' in query else 'old-image')\n"
        "elif args[0] == 'stop' and os.environ['STOP_FAILS'] == '1': sys.exit(9)\n"
        "elif args[0] == 'run': sys.exit(17)\n"
    )
    docker.chmod(0o700)
    environment = {
        **os.environ,
        "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        "TRACE": str(trace),
        "MOUNT": str(tmp_path / "other" if different_mount else directory),
        "STOP_FAILS": str(int(stop_fails)),
        "SOCIFY_ANALYSIS_CONTAINER_NAME": "socify-test-analysis",
        "SOCIFY_ANALYSIS_IPC_DIRECTORY": str(directory),
        "SOCIFY_ANALYSIS_REFRESH_IMAGE": str(int(refresh)),
    }
    result = subprocess.run(["bash", str(SCRIPT)], env=environment, capture_output=True, text=True, check=False)  # noqa: S603,S607
    calls = [json.loads(line) for line in trace.read_text().splitlines()]
    operations = [call[0] for call in calls]
    assert sentinel.read_text() == "preserved"
    if replaced:
        assert result.returncode == 17  # Reached replacement startup, not the stale-image guard.
        assert operations.index("stop") < operations.index("rm") < operations.index("run")
        assert ["stop", "--time", "30", "socify-test-analysis"] in calls
        assert ["rm", "socify-test-analysis"] in calls
    else:
        assert result.returncode != 0
        assert "rm" not in operations and "run" not in operations
        if different_mount or not refresh:
            assert "stop" not in operations
