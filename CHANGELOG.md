# Changelog

All notable changes to **Simple M365 Relay** will be documented in this file.

This project follows **Semantic Versioning** (SemVer): https://semver.org/

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

[1.0.0]: https://github.com/LickABrick/simple-m365-relay/releases/tag/v1.0.0
