# v2 audit report

Audit target: `rc/v2.0.0-rc.1`, based on the latest v1 release-candidate line available when the rewrite began.

## Executive assessment

The v1 application was serviceable for a small installation, but its large FastAPI module, template-local JavaScript, JSON state, and mixed browser/control responsibilities made continued UI and schema evolution expensive. A major-version rewrite is justified. The resulting architecture remains a small Compose deployment rather than adding a separate public API or Turborepo: SvelteKit SSR is the browser boundary and its server actions call the private Postfix control service.

The RC is suitable for controlled upgrade testing after backing up `/data`. It is not a claim that Microsoft tenant policy, public reverse-proxy configuration, or every mail-client combination has been certified.

## Security

Implemented:

- Argon2 administrator password hashing and constant-time session signature checks.
- HTTP-only, SameSite Strict signed sessions with expiry and per-session CSRF tokens for privileged actions.
- SvelteKit origin checking plus explicit action CSRF validation.
- Login throttling after repeated failures.
- CSP, frame-ancestor denial, MIME sniffing protection, restrictive referrer and browser-permission policies.
- The browser never receives the private control token and cannot call the Postfix control service directly.
- SQLite and session-secret files use mode `0600`; the state directory uses `0700`.
- The container prepares a new named volume as root, then runs Node as UID/GID 10001.
- Backup imports use size and entry limits and never extract ZIP paths to disk.
- Diagnostics redact tenant/client identifiers and control-service output performs token redaction.
- Input normalization rejects control characters in Postfix-bound configuration.

Residual risks:

- Login throttling is process-local, so restarting the UI clears counters. A persistent limiter is appropriate if the UI will be internet-facing.
- `style-src 'unsafe-inline'` remains in CSP for current component styling compatibility.
- Reverse proxies must set an explicit `ORIGIN` for HTTPS and must not expose the internal control service.
- SMTP user files and backup archives contain sensitive credentials by design.
- `npm audit --omit=dev` reports two low-severity `cookie` findings through the current latest SvelteKit 2.70.2. npm offers only an invalid breaking downgrade, so this remains documented until an upstream patched release is available.

## Architecture and maintainability

- SvelteKit SSR/server actions replace the FastAPI HTML UI and keep a single deployable web boundary.
- A root npm workspace leaves room for future packages without adding Turborepo overhead today.
- shadcn-svelte components establish consistent primitives without hiding application behavior.
- Formsnap, SvelteKit Superforms, Zod validation, and progressive enhancement provide accessible fields, inline errors, and no-refresh submissions.
- The remaining Python Postfix control process is intentionally private and continues to own privileged mail-system operations.
- Configuration, authentication, and audit records have explicit Drizzle schema definitions and ordered SQL migrations.

## Data integrity and upgrades

- Migrations are idempotently applied during server initialization.
- SQLite enables WAL, foreign keys, and a five-second busy timeout.
- v1 `auth.json` and `config.json` are imported only into empty tables.
- Legacy files remain untouched for rollback; persistent logging tells operators when `config.json` is obsolete.
- Postfix render/control/backup code reads the SQLite canonical configuration.
- Backup export obtains configuration through a read-only SQLite connection; import writes in a transaction.
- Apply remains an explicit validate-render-reload operation, separate from save.

## UI, UX, and accessibility

- Responsive desktop navigation and mobile sheet navigation.
- Clear status hierarchy, pending/applied state, empty states, destructive-action labels, and operational feedback through toasts.
- Setup and login use labeled, autocomplete-aware fields and client-side validation.
- Configuration, SMTP clients, sender ownership/defaults, OAuth, test delivery, recovery, queue, and logs are grouped by operator task.
- Server rendering provides usable first paint and ordinary form fallback; enhancement avoids full-page refreshes.
- Current screenshots are generated from the actual release image by Playwright.

Known UX follow-ups:

- Large installations may need pagination and filtering for SMTP clients and sender rules.
- Live queue/log streaming would be useful, but polling or WebSockets are intentionally outside this RC.
- A dedicated multi-step onboarding wizard was removed in favor of setup plus one task-oriented dashboard; usability feedback should validate that choice.

## Error handling and observability

- Control-service failures are isolated so the dashboard remains available and reports unavailable state.
- Actions return actionable validation or operation messages without leaking stack traces.
- File import limits and compatible-archive errors are surfaced to the operator.
- `/healthz` covers web/database initialization, while the dashboard separately exposes control-service health.
- Downloadable diagnostics include redacted configuration, health, token status, queue, and recent log evidence.

## Verification performed

- `npm run check`
- Vitest unit suite
- production SvelteKit build
- Python bytecode compilation for modified Postfix modules
- shell syntax checks for both entrypoints
- `docker compose config --quiet`
- production Docker image build
- fresh named-volume startup, automatic database migration, file-mode inspection, and non-root Node process inspection
- Playwright first-run and authenticated dashboard flow used for documentation screenshots

## Release recommendation

Ship as `2.0.0-rc.1`, not a v1 minor. Exercise upgrade/rollback with copied production data, test a real Entra tenant and representative SMTP clients, and address any RC findings before `2.0.0`.
