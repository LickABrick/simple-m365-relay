#!/bin/sh
set -eu

DATA_DIR=/data
CFG_JSON="$DATA_DIR/config/config.json"
CERT_PATH="${RELAY_TLS_CERT_PATH:-/data/certs/tls.crt}"
KEY_PATH="${RELAY_TLS_KEY_PATH:-/data/certs/tls.key}"
CN="${RELAY_TLS_SELF_SIGNED_CN:-${RELAY_HOSTNAME:-relay.local}}"

mkdir -p "$DATA_DIR/config" "$DATA_DIR/state" "$DATA_DIR/certs" "$DATA_DIR/tokens" "$DATA_DIR/sasl" "$DATA_DIR/log"

# Create default config if missing
if [ ! -f "$CFG_JSON" ]; then
  cat > "$CFG_JSON" <<'EOF'
{"hostname":"relay.local","domain":"local","mynetworks":["127.0.0.0/8"],"allowed_from":{},"default_from":{}}
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

# Ensure sasldb exists
if [ ! -f "$DATA_DIR/sasl/sasldb2" ]; then
  touch "$DATA_DIR/sasl/sasldb2"
fi

# Make sure Cyrus SASL can find sasldb2
mkdir -p /etc/sasl2
ln -sf "$DATA_DIR/sasl/sasldb2" /etc/sasl2/sasldb2

# Render postfix config
python3 /opt/ms365-relay/postfix/render.py \
  --config "$CFG_JSON" \
  --outdir /etc/postfix \
  --token-dir "$DATA_DIR/tokens" \
  --tls-cert "$CERT_PATH" \
  --tls-key "$KEY_PATH"

# Render sasl-xoauth2 config (used by the sasl-xoauth2 plugin for token refresh)
# Match https://std.rocks/relay-ms365-oauth.html : client_secret may be empty but MUST exist.
if [ -n "${MS365_CLIENT_ID:-}" ] && [ -n "${MS365_TENANT_ID:-}" ]; then
  cat > /etc/sasl-xoauth2.conf <<EOF
{
  "client_id": "${MS365_CLIENT_ID}",
  "client_secret": "",
  "token_endpoint": "https://login.microsoftonline.com/${MS365_TENANT_ID}/oauth2/v2.0/token",
  "log_full_trace_on_failure": "yes",
  "log_to_syslog_on_failure": "yes"
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
