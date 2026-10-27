#!/usr/bin/env bash
set -euo pipefail
export SOCIFY_ANALYSIS_CONTAINER_NAME=socify-v4-dev-analysis
export SOCIFY_ANALYSIS_IPC_DIRECTORY=/tmp/socify-v4-dev-analysis-ipc
export SOCIFY_ANALYSIS_IMAGE=socify-v4-analysis
exec bash "$(dirname "$0")/start_local_analysis.sh"
