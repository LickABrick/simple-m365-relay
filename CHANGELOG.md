# Changelog

All notable changes to **Simple M365 Relay** will be documented in this file.

This project follows **Semantic Versioning** (SemVer): https://semver.org/

## [1.0.2] - 2026-02-06

### Fixed
- More robust Postfix/UI startup for existing volumes: enforce UI write permissions on `/data/config/config.json` on every postfix startup.
- Avoid misleading "Session expired or invalid" onboarding banner caused by transient `/api/status` failures; `/api/status` is now best-effort and always returns JSON.

### Docs
- README GHCR compose example now uses `POSTFIX_CONTROL_URL=http://postfix:18080` (recommended) and removes optional env vars from the example.

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

[1.0.2]: https://github.com/LickABrick/simple-m365-relay/releases/tag/v1.0.2
[1.0.1]: https://github.com/LickABrick/simple-m365-relay/releases/tag/v1.0.1
[1.0.0]: https://github.com/LickABrick/simple-m365-relay/releases/tag/v1.0.0
