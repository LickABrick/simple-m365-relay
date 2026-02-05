#!/usr/bin/env bash
set -euo pipefail

DATA_DIR=${DATA_DIR:-/data}
CFG_DIR="$DATA_DIR/config"
TOK_DIR="$DATA_DIR/tokens"
CERT_DIR="$DATA_DIR/certs"

mkdir -p "$CFG_DIR" "$TOK_DIR" "$CERT_DIR" "$DATA_DIR/log" "$DATA_DIR/state"

# Ensure Postfix can read tokens and certs
chown -R postfix:postfix "$TOK_DIR" || true
chmod 750 "$TOK_DIR" || true

# Persist SASL db in /data (clients authenticating to this relay)
if [ ! -e "$DATA_DIR/sasldb2" ]; then
  touch "$DATA_DIR/sasldb2"
  chmod 600 "$DATA_DIR/sasldb2"
fi
ln -sf "$DATA_DIR/sasldb2" /etc/sasldb2

# Default config file
CONFIG_JSON="$CFG_DIR/config.json"
if [ ! -f "$CONFIG_JSON" ]; then
cat >"$CONFIG_JSON" <<'JSON'
{
  "hostname": "relay.local",
  "domain": "local",
  "mynetworks": ["127.0.0.0/8"],
  "allowed_from": {},
  "default_from": {}
}
JSON
fi

# TLS cert generation (self-signed)
TLS_CERT_PATH=${RELAY_TLS_CERT_PATH:-/data/certs/tls.crt}
TLS_KEY_PATH=${RELAY_TLS_KEY_PATH:-/data/certs/tls.key}
TLS_CN=${RELAY_TLS_SELF_SIGNED_CN:-relay.local}
if [ "${RELAY_TLS_GENERATE_SELF_SIGNED:-true}" = "true" ]; then
  if [ ! -s "$TLS_CERT_PATH" ] || [ ! -s "$TLS_KEY_PATH" ]; then
    echo "[entrypoint] generating self-signed TLS cert ($TLS_CN)" >&2
    mkdir -p "$(dirname "$TLS_CERT_PATH")" "$(dirname "$TLS_KEY_PATH")"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout "$TLS_KEY_PATH" -out "$TLS_CERT_PATH" \
      -subj "/CN=$TLS_CN"
    chmod 600 "$TLS_KEY_PATH"
  fi
fi

# Render postfix configs
python3 /opt/ms365-relay/postfix/render.py \
  --config "$CONFIG_JSON" \
  --outdir /etc/postfix \
  --token-dir "$TOK_DIR" \
  --tls-cert "$TLS_CERT_PATH" \
  --tls-key "$TLS_KEY_PATH"

# Ensure postfix dirs exist
mkdir -p /var/spool/postfix /var/lib/postfix

# Start supervisor (rsyslog + postfix + UI)
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/ms365-relay.conf
