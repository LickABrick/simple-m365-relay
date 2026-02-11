# Changelog

All notable changes to **Simple M365 Relay** will be documented in this file.

This project follows **Semantic Versioning** (SemVer): https://semver.org/

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

[1.1.0]: https://github.com/LickABrick/simple-m365-relay/releases/tag/v1.1.0
[1.0.2]: https://github.com/LickABrick/simple-m365-relay/releases/tag/v1.0.2
[1.0.1]: https://github.com/LickABrick/simple-m365-relay/releases/tag/v1.0.1
[1.0.0]: https://github.com/LickABrick/simple-m365-relay/releases/tag/v1.0.0
