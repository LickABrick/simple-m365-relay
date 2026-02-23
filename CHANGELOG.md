# Changelog

All notable changes to **Simple M365 Relay** will be documented in this file.

This project follows **Semantic Versioning** (SemVer): https://semver.org/

## [1.1.3] - 2026-02-23

### Added
- Update-available badge (stable releases only; ignores prereleases).
- Discard saved changes (restore last applied config snapshot).
- Test Mail: best-effort queue-id extraction + delivery verification.
- Allowed From UX: SMTP user datalist + clearer placeholders.
- Docker-based E2E test suite (core + MailHog).
- UI container healthcheck via public `/healthz` endpoint (compose example + default compose healthcheck).

### Fixed
- Startup robustness: dashboard/diagnostics are best-effort if the control API/socket isn’t ready yet.

### Security
- Stored XSS hardening: strict SMTP AUTH username validation in the control plane + remove inline `onclick` handlers.
- Config file permissions: enforce `0600` on `/data/config/config.json` after UI writes.
- GitHub Actions hardening: validate `workflow_dispatch` version input.

---

## [1.1.2] - 2026-02-20

### Fixed
- Inbound SMTP AUTH reliability: switch to Dovecot SASL (passwd-file) (issue #11).
- Healthcheck endpoint: make `/healthz` public (issue #12).
- OAuth apply: render `/etc/sasl-xoauth2.conf` on apply/reload so onboarding OAuth settings work without container restart.
- Token device flow: flush Postfix queue after successful token creation.
- Test Mail: allow blank From (fallback to configured MS365 identity) and normalize confusing sendmail DSN output to `queued` (issue #8).
- UI: Apply/Validate buttons no longer get stuck disabled after AJAX apply/validate.
- UX: clearer validation error when Allowed From is submitted without a From address (instead of raw 422 JSON).

### Added
- Dev outbound testing harness: `docker-compose.dev.mailhog.yml` (MailHog + smtpclient).

---

## [1.1.2-rc.5] - 2026-02-20

### Fixed
- UX: clearer validation error when Allowed From is submitted without a From address (instead of raw 422 JSON).

## [1.1.2-rc.4] - 2026-02-20

### Fixed
- UI: Apply/Validate buttons no longer get stuck disabled after AJAX apply/validate.

## [1.1.2-rc.3] - 2026-02-20

### Fixed
- OAuth apply: render `/etc/sasl-xoauth2.conf` on apply/reload so onboarding OAuth settings work without container restart.
- Token device flow: flush Postfix queue after successful token creation (reduces “stuck until restart” reports).
- Test Mail: allow blank From (fallback to configured MS365 identity) and normalize confusing sendmail DSN output to `queued`.

## [1.1.2-rc.2] - 2026-02-19

### Fixed
- UI: multi-line placeholder for Allowed From textarea now uses `&#10;` to avoid leading whitespace on line 2.

## [1.1.2-rc.1] - 2026-02-19

### Fixed
- Inbound SMTP AUTH reliability: switch from Cyrus SASL/sasldb2 to Dovecot SASL (passwd-file) (issue #11).
- Healthcheck endpoint: make `/healthz` public (no auth redirect) (issue #12).
- Test Mail: apply config before sending + improved reporting semantics to avoid false OK (issue #8).
- Rewrite locally-generated envelope senders (MAILER-DAEMON/postmaster) to the configured MS365 identity to avoid M365 SendAsDenied noise.

## [1.1.1] - 2026-02-18

### Fixed
- Fix onboarding refresh loop in some fresh installs where the UI could not read `/data/state/control.token` and the control API returned 403:
  - Control token file permissions are now UI-readable (`0640`, group 10001) and self-heal on existing volumes.
  - `/api/status` is best-effort for control API calls (no 500 crash → no loop).

## [1.1.0] - 2026-02-11

### Added
- Onboarding: “Quick start import” in Step 1 (imports backup bundle of saved settings + SMTP AUTH users).
- Backup import hardening: ZIP allowlist + size limits (UI + postfix control API).
- Dashboard UX: live “Next auto-refresh” countdown for OAuth token refresh.

### Changed
- Backup export download is now **POST + CSRF** (instead of GET) to mitigate CSRF.
- Postfix control API bind default is Docker-friendly (do not publish to host).

### Fixed
- OAuth token refresh writes are now atomic/locked and expiry handling is monotonic.
- Token file ownership/perms are corrected so Postfix can read refreshed tokens.
- SMTP AUTH users list no longer shows sasldb error output as fake users.
- AJAX settings save returns 400 on validation errors (instead of 500).
- Mail log is redacted (UI + control API).

### Security
- Control API maillog output redaction.
- TLS level inputs validated/allowlisted to prevent config injection.

## [1.0.2] - 2026-02-07

### Fixed
- More robust Postfix/UI startup for existing volumes: enforce UI write permissions on `/data/config/config.json` on every postfix startup.
- Avoid misleading "Session expired" UX caused by transient `/api/status` failures; `/api/status` is now best-effort and always returns JSON.

### Docs
- README GHCR compose example uses `POSTFIX_CONTROL_URL=http://postfix:18080` (recommended).

## [1.0.1] - 2026-02-06

### Fixed
- Onboarding could enter a refresh/redirect loop when the session was missing/invalid (API endpoints now return 401 instead of redirecting to `/login`; frontend handles 401/403 consistently).
- Fresh installs could hit a 500 when saving relay settings because `/data/config/config.json` was not writable by the non-root UI user (now chowned on initial creation).

### Added
- `docker-compose.dev.yml`: standalone dev stack with separate volume and non-conflicting ports.

## [1.0.0] - 2026-02-06

### Added
- Web UI with built-in admin auth, `/setup` first-run flow and an onboarding wizard.
- OAuth device flow re-auth wizard (dashboard + onboarding) with step-based UX and clear success/error states.
- Telegram/UX polish: copy-to-clipboard with fallback + feedback, robust session-expiry handling for AJAX.
- Postfix control API protected by token header and preferred **unix domain socket** transport.
- Anti-spoofing support via per-login allowed From rules and fallback From addresses.
- CLI utilities (run via `docker exec` in the UI container):
  - `admin reset` (reset admin + invalidate sessions)
  - `status`
  - `apply`
- GHCR publishing workflow via GitHub Actions (release-driven).

### Changed
- UI assets are self-hosted (Tailwind built at image build-time, Lucide vendored) for supply-chain hardening.

### Security
- UI container hardening defaults (non-root, read-only FS, no-new-privileges, cap-drop, tmpfs `/tmp`).
- Token expiry derived via control API (UI container does not read token files directly).

[1.1.3]: https://github.com/LickABrick/simple-m365-relay/releases/tag/v1.1.3
[1.1.2]: https://github.com/LickABrick/simple-m365-relay/releases/tag/v1.1.2
[1.1.1]: https://github.com/LickABrick/simple-m365-relay/releases/tag/v1.1.1
[1.1.0]: https://github.com/LickABrick/simple-m365-relay/releases/tag/v1.1.0
[1.0.2]: https://github.com/LickABrick/simple-m365-relay/releases/tag/v1.0.2
[1.0.1]: https://github.com/LickABrick/simple-m365-relay/releases/tag/v1.0.1
[1.0.0]: https://github.com/LickABrick/simple-m365-relay/releases/tag/v1.0.0
