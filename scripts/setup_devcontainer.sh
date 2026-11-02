#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m scripts.prepare_codespace
.venv/bin/python -m scripts.start_codespace --check
printf '%s\n' 'SOCify environment ready. Start with: bash scripts/try_codespace.sh EMAIL --create-manager'
