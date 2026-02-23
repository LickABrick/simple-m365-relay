#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
E2E_DIR="$ROOT_DIR/tests/e2e"

run_one(){
  local name="$1"; shift
  local files=("$@")
  local proj="sm365r-e2e-${name}-$(date +%s)"

  echo "==> E2E: ${name} (project: ${proj})"

  local args=()
  for f in "${files[@]}"; do
    args+=( -f "$f" )
  done

  (cd "$E2E_DIR" && docker compose -p "$proj" "${args[@]}" up --build --abort-on-container-exit --exit-code-from e2e)

  echo "==> E2E: ${name} cleanup"
  (cd "$E2E_DIR" && docker compose -p "$proj" "${args[@]}" down -v --remove-orphans)
}

run_one core docker-compose.e2e.base.yml
run_one mailhog docker-compose.e2e.base.yml docker-compose.e2e.mailhog.yml

echo "ALL E2E OK"
