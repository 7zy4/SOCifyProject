#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' 'Usage: bash scripts/try_codespace.sh EMAIL [--create-manager|--reset-password|--recover-access]'
}

if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
  usage
  exit 0
fi
if [[ $# -lt 1 || $# -gt 2 || ( $# -eq 2 && "$2" != --create-manager && "$2" != --reset-password && "$2" != --recover-access ) ]]; then
  usage >&2
  exit 2
fi

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"
account_email="$1"
if [[ -x "$repository_root/.venv/bin/python" ]]; then
  python_command="$repository_root/.venv/bin/python"
else
  python_command="$(command -v python)"
fi

listen_port="$("$python_command" - <<'PY'
import os
import socket

if os.environ.get("SOCIFY_ENV", "development").strip().lower() != "development":
    raise SystemExit("This launcher is for development only; production requires its configured services.")
try:
    port = int(os.environ.get("SOCIFY_PORT", "5000"))
except ValueError as error:
    raise SystemExit("SOCIFY_PORT must be an integer between 1 and 65535.") from error
if not 1 <= port <= 65535:
    raise SystemExit("SOCIFY_PORT must be an integer between 1 and 65535.")
with socket.socket() as probe:
    probe.settimeout(0.5)
    if probe.connect_ex(("127.0.0.1", port)) == 0:
        raise SystemExit(f"Port {port} is already in use. Stop the previous server before starting another instance.")
print(port)
PY
)"

export SOCIFY_ENV=development
export SOCIFY_HOST=0.0.0.0
export SOCIFY_PORT="$listen_port"
if [[ "${2:-}" != --create-manager ]]; then
  "$python_command" -m scripts.bootstrap_team --email "$account_email" --status
fi

if ! command -v docker >/dev/null 2>&1; then
  printf '%s\n' 'Docker is missing. Run Codespaces: Rebuild Container on this existing Codespace, then retry.' >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  printf '%s\n' 'Docker is not ready. Finish rebuilding the container and verify docker info, then retry.' >&2
  exit 1
fi
if ! docker image inspect socify-v3-verification-analysis >/dev/null 2>&1; then
  docker build --target analysis --tag socify-v3-verification-analysis "$repository_root"
fi
bash scripts/start_local_analysis.sh
export SOCIFY_ANALYSIS_SOCKET=/tmp/socify-v3-dev-analysis-ipc/analysis.sock

if [[ "${2:-}" == --create-manager ]]; then
  "$python_command" -m scripts.bootstrap_team --email "$account_email" --name 'مالك المنصة' --team 'فريق التحقيق الداخلي' --generate-password-file
elif [[ "${2:-}" == --reset-password ]]; then
  "$python_command" -m scripts.bootstrap_team --email "$account_email" --reset-password
elif [[ "${2:-}" == --recover-access ]]; then
  "$python_command" -m scripts.bootstrap_team --email "$account_email" --reset-password --generate-password-file
fi

printf '%s\n' "Starting SOCify for ${account_email}. Open port ${listen_port} from Ports when the server is listening."
exec "$python_command" run.py
