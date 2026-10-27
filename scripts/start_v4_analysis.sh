#!/usr/bin/env bash
set -euo pipefail
export SOCIFY_ANALYSIS_CONTAINER_NAME=socify-v4-dev-analysis
export SOCIFY_ANALYSIS_IPC_DIRECTORY=/tmp/socify-v4-dev-analysis-ipc
export SOCIFY_ANALYSIS_IMAGE=socify-v4-analysis
# The V4 development backend is disposable; refresh it after an image rebuild.
# start_local_analysis.sh still rejects a container bound to another directory.
export SOCIFY_ANALYSIS_REFRESH_IMAGE=1
exec bash "$(dirname "$0")/start_local_analysis.sh"
