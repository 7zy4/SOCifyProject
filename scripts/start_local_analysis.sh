#!/usr/bin/env bash
set -euo pipefail
if ! command -v docker >/dev/null 2>&1; then
  printf '%s\n' 'Docker is not installed. In Codespaces, update V3 and run Codespaces: Rebuild Container on the existing Codespace.' >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  printf '%s\n' 'Docker is installed but its daemon is unavailable. Finish the container rebuild and verify docker info before starting analysis.' >&2
  exit 1
fi
analysis_container=${SOCIFY_ANALYSIS_CONTAINER_NAME:-socify-v3-dev-analysis}
analysis_directory=${SOCIFY_ANALYSIS_IPC_DIRECTORY:-/tmp/socify-v3-dev-analysis-ipc}
analysis_image=${SOCIFY_ANALYSIS_IMAGE:-socify-v3-verification-analysis}
analysis_expected="$(docker image inspect --format '{{.Id}}' "$analysis_image")"
if docker container inspect "$analysis_container" >/dev/null 2>&1; then
  analysis_actual="$(docker container inspect --format '{{.Image}}' "$analysis_container")"
  analysis_mount="$(docker container inspect --format '{{range .Mounts}}{{if eq .Destination "/analysis-ipc"}}{{.Source}}{{end}}{{end}}' "$analysis_container")"
  if [[ "$analysis_actual" != "$analysis_expected" || "$analysis_mount" != "$analysis_directory" ]]; then
    printf '%s\n' 'Existing development backend differs; inspect it before replacement.' >&2
    exit 1
  fi
  if [[ "$(docker container inspect --format '{{.State.Running}}' "$analysis_container")" == true ]]; then
    test -S "$analysis_directory/analysis.sock"
    printf '%s\n' "$analysis_directory/analysis.sock"
    exit 0
  fi
  docker rm "$analysis_container" >/dev/null
fi
install -d -m 2770 "$analysis_directory"
if [[ -e "$analysis_directory/analysis.sock" && ! -S "$analysis_directory/analysis.sock" ]]; then
  printf '%s\n' 'Unexpected IPC entry; inspect before startup.' >&2
  exit 1
fi
rm -f "$analysis_directory/analysis.sock"
docker run --detach --init --name "$analysis_container" --no-healthcheck --network none --read-only --cap-drop ALL --security-opt no-new-privileges --group-add "$(id -g)" --memory 2g --pids-limit 32 --tmpfs /tmp:size=128m,noexec,nosuid,nodev --mount "type=bind,source=${analysis_directory},target=/analysis-ipc" "$analysis_image" >/dev/null
for attempt in $(seq 1 30); do
  if test -S "$analysis_directory/analysis.sock" && test -f "$analysis_directory/analysis.lock"; then
    chmod 555 "$analysis_directory"
    printf '%s\n' "$analysis_directory/analysis.sock"
    exit 0
  fi
  sleep 1
done
docker logs --tail 20 "$analysis_container" >&2
exit 1
