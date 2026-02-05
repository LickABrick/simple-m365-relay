#!/bin/sh
set -eu

BIND="${UI_BIND:-0.0.0.0}"
PORT="${UI_PORT:-8000}"

# Ensure /data is writable for the non-root user (shared volume)
if [ -d /data ]; then
  chown -R app:app /data || true
fi

exec su-exec app uvicorn app.main:app --host "$BIND" --port "$PORT"
