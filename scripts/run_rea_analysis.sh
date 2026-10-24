#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
analysis_target="$(mktemp -d)"
output_path="${1:-$repository_root/artifacts/rea-analysis.json}"
trap 'rm -rf "$analysis_target"' EXIT

mkdir -p "$analysis_target/static" "$analysis_target/templates" "$(dirname "$output_path")"
cp "$repository_root/static/app.js" "$analysis_target/static/app.js"
cp "$repository_root/templates/app.html" "$analysis_target/templates/app.html"
if [[ -n "${SOCIFY_REA_CLI:-}" ]]; then
  node "$SOCIFY_REA_CLI" analyze-javascript-application "$analysis_target" --json | tee "$output_path"
else
  NPM_CONFIG_CACHE="${NPM_CONFIG_CACHE:-/tmp/socify-rea-npm-cache}" npx -y rea-agents@6.7.0 analyze-javascript-application "$analysis_target" --json | tee "$output_path"
fi
