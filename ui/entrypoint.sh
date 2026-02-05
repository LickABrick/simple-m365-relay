#!/bin/sh
set -eu

# Non-root runtime. /data permissions are prepared by the postfix container.
export PYTHONDONTWRITEBYTECODE=1
export XDG_CACHE_HOME=/tmp

BIND="${UI_BIND:-0.0.0.0}"
PORT="${UI_PORT:-8000}"

exec uvicorn app.main:app --host "$BIND" --port "$PORT"
