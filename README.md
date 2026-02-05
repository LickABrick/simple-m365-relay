# ms365-relay (Postfix → Microsoft 365 via OAuth2 / XOAUTH2)

Reusable Docker Compose stack that:

- Listens on **25** and **587** (submission)
- Accepts client mail with **SMTP AUTH** (Cyrus SASL sasldb2) and/or **trusted subnets** (mynetworks)
- Relays outbound mail via **smtp.office365.com:587** using **XOAUTH2** (`sasl-xoauth2`)
- Includes a minimal **web UI** (FastAPI) for status + basic settings
- Persists configuration, SMTP AUTH DB, and OAuth tokens in a Docker volume

This is based on the approach described here:
- https://std.rocks/relay-ms365-oauth.html

## Quick start

```bash
cd ms365-relay
cp env.example .env
# edit .env
docker compose up -d --build
```

Web UI:
- http://localhost:8000/

Put it behind a reverse proxy and protect it with basic auth (or SSO). The UI does **not** implement authentication.

## Microsoft 365 / Entra prerequisites

1. Create a **licensed** M365 user that will send mail (e.g. `postfix@…`).
2. Enable **Authenticated SMTP** for that mailbox/user.
3. Register an Entra application and grant **SMTP.Send** application permission; grant admin consent.
4. Enable **Public client flows** (device code flow).
5. Put values into `.env`:
   - `MS365_TENANT_ID`
   - `MS365_CLIENT_ID`
   - `MS365_SMTP_USER`

## OAuth device flow (mint token)

1. Open the UI → **OAuth Device Flow** → **Start device flow**.
2. Read the log block; it should show a URL (usually `https://microsoft.com/devicelogin`) and a code.
3. Complete the login in a browser as the configured `MS365_SMTP_USER`.

Token file location (persisted):
- `ms365-relay-data:/data/tokens/<MS365_SMTP_USER>`

## Client configuration

### Port 587 (recommended)
- Use STARTTLS
- SMTP AUTH required

### Port 25
- Opportunistic TLS (default)
- Relaying allowed for:
  - `mynetworks` (trusted subnets), or
  - SMTP AUTH users

## UI capabilities

- **Manage SMTP AUTH users** (adds/removes entries in sasldb2)
- Configure:
  - `hostname`, `domain`
  - `mynetworks` (trusted subnets)
  - allowed envelope-from addresses per authenticated login (sender login maps)
  - per-user “default From” (informational only)
- Start OAuth device flow and store token
- Show:
  - queue size
  - tail of `/var/log/mail.log`
  - token expiry (best effort)
- Buttons:
  - render config + reload postfix
  - reload postfix
  - send test mail

## Volumes / persistence

A single named volume is used:

- `/data/config/config.json` (UI settings)
- `/data/sasldb2` (SMTP AUTH user DB)
- `/data/tokens/` (OAuth token files)
- `/data/certs/` (TLS cert/key; self-signed by default)

## TLS certificates

By default the container generates a **self-signed** cert at first start.

To use your own cert, mount/replace the files in the volume and set:

- `RELAY_TLS_CERT_PATH=/data/certs/tls.crt`
- `RELAY_TLS_KEY_PATH=/data/certs/tls.key`

(Those are the defaults.)

## Security notes

- **Protect the web UI**: it can manage SMTP AUTH users and start device-flow.
- The OAuth token is a bearer credential. Restrict access to the Docker host and to the volume.
- This relay is intended for **internal / trusted** networks. Do not expose port 25/587 publicly unless you know what you are doing.
- Consider tightening Postfix restrictions further (rate limits, recipient restrictions, etc.) for your environment.
- SMTP AUTH passwords are stored in `sasldb2` (hashed). Still treat the volume as sensitive.

## Troubleshooting

- Check UI “Mail log (tail)” for errors.
- Verify token refresh works (inside container):
  ```bash
  docker exec -it ms365-relay sasl-xoauth2-tool test-token-refresh /data/tokens/$MS365_SMTP_USER
  ```
- Queue inspection:
  ```bash
  docker exec -it ms365-relay mailq
  ```
