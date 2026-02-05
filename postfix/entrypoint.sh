#!/bin/sh
set -eu

DATA_DIR=/data
CFG_JSON="$DATA_DIR/config/config.json"
CERT_PATH="${RELAY_TLS_CERT_PATH:-/data/certs/tls.crt}"
KEY_PATH="${RELAY_TLS_KEY_PATH:-/data/certs/tls.key}"
CN="${RELAY_TLS_SELF_SIGNED_CN:-${RELAY_HOSTNAME:-relay.local}}"

mkdir -p "$DATA_DIR/config" "$DATA_DIR/state" "$DATA_DIR/certs" "$DATA_DIR/tokens" "$DATA_DIR/sasl" "$DATA_DIR/log"

# Ensure Postfix daemons can update token files (sasl-xoauth2 refresh writes a temp file next to the token)
chown -R postfix:postfix "$DATA_DIR/tokens" 2>/dev/null || true

# Allow the UI container (non-root) to write its state/config in the shared volume.
# UI runs as uid:gid 10001:10001.
UI_UID=${UI_UID:-10001}
UI_GID=${UI_GID:-10001}

for p in "$DATA_DIR/config" "$DATA_DIR/state"; do
  mkdir -p "$p" || true
  chown -R "$UI_UID:$UI_GID" "$p" 2>/dev/null || true
  chmod -R u+rwX "$p" 2>/dev/null || true
done

# Create default config if missing
if [ ! -f "$CFG_JSON" ]; then
  cat > "$CFG_JSON" <<'EOF'
{
  "hostname": "relay.local",
  "domain": "local",
  "mynetworks": ["127.0.0.0/8"],

  "relayhost": "[smtp.office365.com]:587",
  "tls": {
    "smtpd_25": "may",
    "smtpd_587": "encrypt"
  },

  "oauth": {
    "tenant_id": "",
    "client_id": "",
    "auto_refresh_minutes": 30
  },

  "allowed_from": {},
  "default_from": {}
}
EOF
fi

# generate self-signed cert if requested and missing
if [ "${RELAY_TLS_GENERATE_SELF_SIGNED:-true}" = "true" ] && { [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; }; then
  echo "[tls] generating self-signed cert for CN=$CN"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY_PATH" -out "$CERT_PATH" -days 3650 \
    -subj "/CN=$CN" >/dev/null 2>&1 || true
  chmod 600 "$KEY_PATH" || true
fi

# Make sure Cyrus SASL can find sasldb2 (only if it exists and looks non-empty).
# We don't create an empty sasldb2 file because sasldblistusers2 will complain about invalid DB format.
mkdir -p /etc/sasl2
if [ -f "$DATA_DIR/sasl/sasldb2" ] && [ ! -s "$DATA_DIR/sasl/sasldb2" ]; then
  rm -f "$DATA_DIR/sasl/sasldb2" || true
fi

# If there's an existing sasldb2 but it's not readable by this image (db format mismatch), move it aside.
if [ -f "$DATA_DIR/sasl/sasldb2" ]; then
  if ! sasldblistusers2 -f "$DATA_DIR/sasl/sasldb2" >/dev/null 2>&1; then
    ts=$(date +%s 2>/dev/null || echo 0)
    mv "$DATA_DIR/sasl/sasldb2" "$DATA_DIR/sasl/sasldb2.bad.${ts}" 2>/dev/null || rm -f "$DATA_DIR/sasl/sasldb2" || true
  fi
fi

if [ -f "$DATA_DIR/sasl/sasldb2" ]; then
  ln -sf "$DATA_DIR/sasl/sasldb2" /etc/sasl2/sasldb2
fi

# Render postfix config
python3 /opt/ms365-relay/postfix/render.py \
  --config "$CFG_JSON" \
  --outdir /etc/postfix \
  --token-dir "$DATA_DIR/tokens" \
  --tls-cert "$CERT_PATH" \
  --tls-key "$KEY_PATH"

# Render sasl-xoauth2 config (used by the sasl-xoauth2 plugin for token refresh)
# Prefer app config.json, fallback to env.
# Match https://std.rocks/relay-ms365-oauth.html : client_secret may be empty but MUST exist.
_cfg_client_id=$(python3 - <<'PY'
import json
from pathlib import Path
p=Path('/data/config/config.json')
try:
  cfg=json.loads(p.read_text())
  print((cfg.get('oauth') or {}).get('client_id','') or '')
except Exception:
  print('')
PY
)
_cfg_tenant_id=$(python3 - <<'PY'
import json
from pathlib import Path
p=Path('/data/config/config.json')
try:
  cfg=json.loads(p.read_text())
  print((cfg.get('oauth') or {}).get('tenant_id','') or '')
except Exception:
  print('')
PY
)
client_id="${_cfg_client_id:-${MS365_CLIENT_ID:-}}"
tenant_id="${_cfg_tenant_id:-${MS365_TENANT_ID:-}}"

if [ -n "${client_id:-}" ] && [ -n "${tenant_id:-}" ]; then
  cat > /etc/sasl-xoauth2.conf <<EOF
{
  "client_id": "${client_id}",
  "client_secret": "",
  "token_endpoint": "https://login.microsoftonline.com/${tenant_id}/oauth2/v2.0/token",
  "log_full_trace_on_failure": "${OAUTH_LOG_FULL_TRACE:-no}",
  "log_to_syslog_on_failure": "${OAUTH_LOG_TO_SYSLOG:-yes}"
}
EOF
fi

# Ensure postfix dirs
postfix check || true

# Start syslog to file
# busybox syslogd writes to a file with -O
syslogd -n -O "$DATA_DIR/log/maillog" &

# Start control API
python3 /opt/ms365-relay/postfix/control.py &

# Run postfix in foreground
exec /usr/sbin/postfix start-fg
