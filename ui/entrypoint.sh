#!/bin/sh
set -eu

BIND="${UI_BIND:-0.0.0.0}"
PORT="${UI_PORT:-8000}"

exec uvicorn app.main:app --host "$BIND" --port "$PORT"
