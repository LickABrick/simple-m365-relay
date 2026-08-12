# SvelteKit control plane

This workspace contains the Simple M365 Relay v2 administration application.

## Stack

- SvelteKit with server-side rendering and the Node adapter.
- shadcn-svelte Nova components and Tailwind CSS 4.
- Formsnap and sveltekit-superforms with progressive enhancement and Zod validation.
- SQLite through better-sqlite3 and Drizzle migrations.
- Server-sent events for relay readiness, OAuth state, queue, and mail-log updates.

The browser only talks to SvelteKit. Server routes access SQLite and the authenticated internal Postfix control API; relay credentials and OAuth token files are never exposed to client-side code.

## Local development

From the repository root:

```bash
npm install
npm run dev --workspace @simple-m365-relay/web
```

Development storage defaults to `apps/web/.data`, avoiding writes to `/data`. To use a specific directory:

```bash
DATA_DIR=/tmp/simple-m365-relay-dev npm run dev --workspace @simple-m365-relay/web
```

The relay-dependent operations remain unavailable unless `POSTFIX_CONTROL_URL` or `POSTFIX_CONTROL_SOCKET` points at a running relay service.

## Checks

```bash
npm run check --workspace @simple-m365-relay/web
npm run lint --workspace @simple-m365-relay/web
npm run test:unit --workspace @simple-m365-relay/web -- --run
npm run build --workspace @simple-m365-relay/web
```

## Database

Migration files live under `drizzle/`. `initializeDatabase()` applies every pending migration before handling requests. On a fresh database it then bootstraps settings from environment values or imports legacy v1 state.

Generate a migration after an intentional schema change:

```bash
npm run db:generate --workspace @simple-m365-relay/web
```

Do not edit an already-released migration. Add a new migration and verify both fresh installation and upgrade paths.

## Documentation screenshots

`scripts/capture-docs.mjs` captures the configured routes and sanitizes visible email addresses, UUIDs, tenant hostnames, public IPs, and the operator label before writing images.

Use an existing administrator:

```bash
DOCS_BASE_URL=http://127.0.0.1:8000 \
DOCS_USERNAME=operator \
DOCS_PASSWORD='your-password' \
node apps/web/scripts/capture-docs.mjs
```

`DOCS_SESSION_COOKIE` is supported for explicitly provisioned documentation environments. Never commit credentials, cookies, production screenshots, or unsanitized intermediate images.

## Production CLI

The final image installs `/opt/ms365-relay/admin-cli.mjs`:

```bash
node /opt/ms365-relay/admin-cli.mjs status
node /opt/ms365-relay/admin-cli.mjs admin reset --yes
```

When arguments are passed directly to the container entrypoint, it invokes this CLI as the non-root application user.
