#!/bin/sh
set -eu

DATA_DIR=/data
CFG_JSON="$DATA_DIR/config/config.json"
CFG_DB="$DATA_DIR/state/relay.db"
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

for p in "$DATA_DIR/config" "$DATA_DIR/state" "$DATA_DIR/sasl"; do
  mkdir -p "$p" || true
  chown -R "$UI_UID:$UI_GID" "$p" 2>/dev/null || true
  chmod -R u+rwX "$p" 2>/dev/null || true
done

# Preserve and expose a legacy config for the UI's one-time SQLite import.
if [ -f "$CFG_JSON" ]; then
  chown "$UI_UID:$UI_GID" "$CFG_JSON" 2>/dev/null || true
  chmod 600 "$CFG_JSON" 2>/dev/null || true
fi

# generate self-signed cert if requested and missing
if [ "${RELAY_TLS_GENERATE_SELF_SIGNED:-true}" = "true" ] && { [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; }; then
  echo "[tls] generating self-signed cert for CN=$CN"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY_PATH" -out "$CERT_PATH" -days 3650 \
    -subj "/CN=$CN" >/dev/null 2>&1 || true
  chmod 600 "$KEY_PATH" || true
fi

# Dovecot SASL (auth socket for Postfix)
# We use Dovecot for stable SMTP AUTH behavior.
# User store: /data/sasl/users (passwd-file)
mkdir -p /etc/dovecot /etc/dovecot/conf.d "$DATA_DIR/sasl" || true

cat > /etc/dovecot/dovecot.conf <<'EOF'
# Debian 13 ships Dovecot 2.4+, which requires version pins as the first settings.
dovecot_config_version = 2.4.0
dovecot_storage_version = 2.4.0

# Dovecot base config
# Note: do NOT set "protocols = auth" (auth is a service, not a protocol).
listen = *
!include conf.d/*.conf
EOF

cat > /etc/dovecot/conf.d/10-auth.conf <<'EOF'
# Dovecot 2.4+: allow AUTH PLAIN/LOGIN without requiring TLS on the connection.
auth_allow_cleartext = yes

auth_mechanisms = plain login
!include auth-passwdfile.conf.ext
EOF

cat > /etc/dovecot/conf.d/auth-passwdfile.conf.ext <<'EOF'
# passwd-file user store: /data/sasl/users
# (Dovecot 2.4+ syntax)
passdb passwd-file {
  default_password_scheme = PLAIN
  auth_username_format = %{user}
  passwd_file_path = /data/sasl/users
}

# We don't need per-user home dirs; use a static userdb.
userdb static {
  fields {
    uid = postfix
    gid = postfix
    home = /tmp
  }
}
EOF

cat > /etc/dovecot/conf.d/10-master.conf <<'EOF'
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
EOF

mkdir -p /var/spool/postfix/private || true
chown -R postfix:postfix /var/spool/postfix || true

if [ ! -f "$DATA_DIR/sasl/users" ]; then
  touch "$DATA_DIR/sasl/users" || true
fi
# Dovecot (running as user "dovecot") must be able to read this file.
chmod 640 "$DATA_DIR/sasl/users" || true
chown dovecot:dovecot "$DATA_DIR/sasl/users" || true

# Start dovecot (auth only)
dovecot -F &

# The UI owns schema migrations and legacy import. Wait for its first migration
# before rendering Postfix configuration from the shared database.
waited=0
until python3 -c "import sqlite3; db=sqlite3.connect('file:$CFG_DB?mode=ro', uri=True); row=db.execute('select config from settings where id=1').fetchone(); raise SystemExit(0 if row else 1)" 2>/dev/null; do
  if [ "$waited" -ge 60 ]; then echo "[startup] SQLite database was not initialized within 60 seconds" >&2; exit 1; fi
  sleep 1; waited=$((waited + 1))
done

# Render postfix config
python3 /opt/ms365-relay/relay/render.py \
  --config "$CFG_DB" \
  --outdir /etc/postfix \
  --token-dir "$DATA_DIR/tokens" \
  --tls-cert "$CERT_PATH" \
  --tls-key "$KEY_PATH"

# Render sasl-xoauth2 config (used by the sasl-xoauth2 plugin for token refresh)
# Prefer the SQLite-backed application configuration, then fall back to env.
# Match https://std.rocks/relay-ms365-oauth.html : client_secret may be empty but MUST exist.
_cfg_client_id=$(python3 - <<'PY'
import json, sqlite3
try:
  with sqlite3.connect('file:/data/state/relay.db?mode=ro', uri=True) as db: cfg=json.loads(db.execute('select config from settings where id=1').fetchone()[0])
  print((cfg.get('oauth') or {}).get('client_id','') or '')
except Exception:
  print('')
PY
)
_cfg_tenant_id=$(python3 - <<'PY'
import json, sqlite3
try:
  with sqlite3.connect('file:/data/state/relay.db?mode=ro', uri=True) as db: cfg=json.loads(db.execute('select config from settings where id=1').fetchone()[0])
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
# Debian ships a default /etc/syslog.conf whose facility routes override BusyBox's
# -O destination. Ignore that host-oriented config so container mail logs remain
# in the persistent data volume consumed by the control API.
/bin/busybox syslogd -n -f /dev/null -O "$DATA_DIR/log/maillog" &

# Start control API
python3 /opt/ms365-relay/relay/control.py &

# Run postfix in foreground
exec /usr/sbin/postfix start-fg
