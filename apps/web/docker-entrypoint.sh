#!/bin/sh
set -eu

export HOST="${UI_BIND:-0.0.0.0}"
export PORT="${UI_PORT:-8000}"
export HOST_HEADER="${HOST_HEADER:-host}"

# Named volumes begin root-owned. Prepare only the paths the UI owns, then
# permanently drop privileges before loading application code.
mkdir -p "${DATA_DIR:-/data}/state"
chown 10001:10001 "${DATA_DIR:-/data}/state"
chmod 0700 "${DATA_DIR:-/data}/state"

if [ "$#" -gt 0 ]; then
  exec gosu 10001:10001 node /opt/ms365-relay/admin-cli.mjs "$@"
fi

exec gosu 10001:10001 node /opt/ms365-relay/build
