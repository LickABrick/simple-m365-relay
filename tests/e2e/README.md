# E2E tests (docker compose)

These are lightweight end-to-end checks that exercise:
- first-run setup + login + CSRF flow
- settings save + pending + discard
- testmail (best-effort) verification

They run inside Docker so they do not require local Python dependencies.

## Run

```bash
cd ms365-relay
./tests/e2e/run.sh
```

This will build images and start temporary docker compose projects.
