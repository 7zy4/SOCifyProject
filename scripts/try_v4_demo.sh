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
if [[ ! -x .venv/bin/python ]]; then
  printf '%s\n' 'Python environment missing. Run: bash scripts/setup_devcontainer.sh' >&2
  exit 1
fi
exec .venv/bin/python -m scripts.start_v4_demo --directory "${1:-instance/v4-demo}" --port "${SOCIFY_PORT:-5000}"
