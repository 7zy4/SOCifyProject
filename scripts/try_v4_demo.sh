#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
  printf '%s\n' 'Usage: bash scripts/try_v4_demo.sh [demo-directory]'
  exit 0
fi
if [[ $# -gt 1 ]]; then
  printf '%s\n' 'Usage: bash scripts/try_v4_demo.sh [demo-directory]' >&2
  exit 2
fi
if [[ "${SOCIFY_ENV:-development}" != development ]]; then
  printf '%s\n' 'The synthetic demo is restricted to development.' >&2
  exit 1
fi
python_command=.venv/bin/python
if [[ ! -x "$python_command" ]]; then
  printf '%s\n' 'Python environment missing. Finish Rebuild Container, or run: bash scripts/setup_devcontainer.sh' >&2
  exit 1
fi
demo_directory=${1:-instance/v4-demo}
listen_port=${SOCIFY_PORT:-5000}
"$python_command" - "$listen_port" <<'PY'
import socket
import sys

try:
    port = int(sys.argv[1])
    if not 1 <= port <= 65535:
        raise ValueError
except ValueError:
    raise SystemExit('SOCIFY_PORT must be between 1 and 65535.') from None
with socket.socket() as probe:
    probe.settimeout(0.5)
    if probe.connect_ex(('127.0.0.1', port)) == 0:
        raise SystemExit(f'Port {port} is already in use. Stop the previous server in its terminal before retrying.')
PY
if [[ -e "$demo_directory" && ! -f "$demo_directory/manifest.json" ]]; then
  printf '%s\n' "Existing incomplete or non-demo directory: $demo_directory. Preserved; choose a new directory as the first argument." >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  printf '%s\n' 'Docker is unavailable. In the existing Codespace run Codespaces: Rebuild Container, then verify docker info.' >&2
  exit 1
fi
if ! docker image inspect socify-v4-analysis >/dev/null 2>&1; then
  docker build --target analysis -t socify-v4-analysis .
fi
bash scripts/start_v4_analysis.sh
export SOCIFY_ANALYSIS_SOCKET=/tmp/socify-v4-dev-analysis-ipc/analysis.sock
if [[ ! -e "$demo_directory" ]]; then
  "$python_command" -m scripts.prepare_v4_demo --directory "$demo_directory"
fi
printf '%s\n' "Accounts: ${demo_directory}/accounts.json (open privately in the editor)." "Starting the V4 demo on port ${listen_port}. In Codespaces open Ports -> ${listen_port} -> Open in Browser; keep visibility Private."
exec "$python_command" -m scripts.run_v4_demo --directory "$demo_directory" --host "${SOCIFY_HOST:-127.0.0.1}" --port "$listen_port"
