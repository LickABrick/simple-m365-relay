#!/usr/bin/env bash
set -euo pipefail

# Ensure aliases db exists (required by postfix sometimes)
newaliases || true

# Start postfix in foreground-ish mode by tailing logs
postfix start-fg
