#!/bin/sh
set -eu

export HOST="${UI_BIND:-0.0.0.0}"
export PORT="${UI_PORT:-8000}"
export HOST_HEADER="${HOST_HEADER:-host}"

# Named volumes begin root-owned. Prepare only the paths the UI owns, then
# permanently drop privileges before loading application code.
DATA_ROOT="${DATA_DIR:-/data}"
STATE_DIR="$DATA_ROOT/state"
SETUP_TOKEN_FILE="$STATE_DIR/setup.token"

mkdir -p "$STATE_DIR"
chown 10001:10001 "$STATE_DIR"
chmod 0700 "$STATE_DIR"

# Fail-safe first-run bootstrap: an explicit environment token wins. When it
# is absent, generate a persistent token as the unprivileged application user.
# It is removed after the administrator is created.
if [ "${ALLOW_UNAUTHENTICATED_SETUP:-0}" != "1" ]; then
  if [ -n "${SETUP_TOKEN:-}" ]; then
    echo "[setup] Using SETUP_TOKEN supplied through the UI container environment."
  else
    if [ ! -s "$SETUP_TOKEN_FILE" ]; then
      gosu 10001:10001 sh -c '
        set -eu
        umask 077
        tmp=$(mktemp "$1/.setup-token.XXXXXX")
        trap '\''rm -f "$tmp"'\'' EXIT
        node -e '\''process.stdout.write(require("node:crypto").randomBytes(32).toString("base64url") + "\n")'\'' > "$tmp"
        mv -f "$tmp" "$1/setup.token"
        trap - EXIT
      ' sh "$STATE_DIR"
    fi
    echo "[setup] First-run administrator setup token:"
    printf '[setup] %s\n' "$(gosu 10001:10001 sh -c 'cat "$1"' sh "$SETUP_TOKEN_FILE")"
    echo "[setup] Enter this token at /setup. It is deleted after setup succeeds."
    echo "[setup] Retrieve it again with: docker compose logs ui"
  fi
fi

if [ "$#" -gt 0 ]; then
  exec gosu 10001:10001 node /opt/ms365-relay/admin-cli.mjs "$@"
fi

exec gosu 10001:10001 node /opt/ms365-relay/build
