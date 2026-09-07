# Docker end-to-end tests

The end-to-end harness builds isolated UI and relay images and uses temporary Compose projects and volumes. It does not reuse the developer or production stack.

Coverage includes:

- first-run administrator setup, login, and CSRF behavior;
- configuration save, pending-change detection, validation, apply, and discard;
- Dovecot SMTP client management;
- backup export/import safety;
- relay health and control API integration;
- best-effort message submission and MailHog delivery where applicable.

Run all suites from the repository root:

```bash
./tests/e2e/run.sh
```

The harness tears down its projects on completion. If a run is interrupted, inspect its printed Compose project name before removing the associated containers and volume.

These tests require Docker with Compose v2. They do not replace the Svelte unit checks or Python security tests documented in the root README.
