# Code Review: simple-m365-relay
## Branch: analysis/improve-2026-05

---

## 🔍 Analyse: Quality, Security & Functionality

### ✅ Sterke punten

**Security**
- Wachtwoorden met Argon2id (best-in-class password hashing)
- CSRF-token op alle state-changing requests
- Account lockout na mislukte login-pogingen (brute-force protection)
- Session cookies: `httponly`, `samesite=lax`, `secure` (wanneer HTTPS)
- Backup ZIP: whitelisted filenames, size limits, geen disk-extractie (ZIP bombs/traversal protection)
- Config injectie Preventie: geen newlines/control chars in Postfix config values (`_safe_cf_value`)
- OAuth tokens: 640 postfix:postfix, UI leest ze niet direct maar via control API
- Control API: shared token authenticatie (`X-Control-Token`)
- `no-new-privileges`, `cap_drop: ALL`, `read_only: true`, `tmpfs` voor UI container
- Token refresh retry logic met exponential backoff
- Dovecot passwd-file format is geometrisch veilig (`_validate_login`, `_validate_password`)
- Redactie van tokens in mail log output

**Functionaliteit**
- Complete onboarding wizard
- OAuth device flow voor Microsoft 365
- SMTP AUTH user management
- Allowed-from regels per gebruiker
- Discard/apply workflow voorkomt per ongeluk Postfix restarts
- Healthcheck endpoints
- Auto token refresh als background loop
- CLI tools voor break-glass recovery
- Self-signed TLS out-of-the-box
- Test mail functionaliteit met delivery verificatie

**Quality**
- E2E tests aanwezig (core + mailhog)
- Backup ZIP security tests
- Token refresh retry logic tests
- Clean aparte postfix/ en app/ directory structuur
- CI/CD publiceren naar GHCR

---

## ⚠️ Issues & Improvements

### 1. **[Security] Postfix container: geen security hardening flags**
Postfix container heeft **geen** `no-new-privileges`, `read_only`, `tmpfs` of `cap_drop`.

**Bestand:** `docker-compose.yml`
**Fix:** Voeg hardening toe aan de postfix service.

---

### 2. **[Security] CSRF token niet uit session cookies verwijderd na gebruik**
Login CSRF (`sm365r_login_csrf`) en session CSRF worden niet anti-replay beschermd. Een oude cookie kan opnieuw gebruikt worden als de attacker die kan stelen.

**Bestand:** `app/auth.py`, `app/main.py`
**Fix:** Sla CSRF op in server-side session state, of gebruik een nonce-per-request dat wordt geroteerd na gebruik.

---

### 3. **[Quality] `validate_cfg_obj` imported vanuit `app.backup` in `app.main`**
`validate_cfg_obj` leeft in `app/backup.py` maar wordt gebruikt door `app/main.py` voor config validatie. Semantisch misplaatst — zou in een aparte config-validatie module moeten zijn.

**Bestand:** `app/main.py:62`, `app/backup.py`
**Fix:** Verplaats `validate_cfg_obj` naar `app/config.py` (nieuwe file).

---

### 4. **[Bug] `effective_ms365_user` laadt config uit file, niet uit memory cache**
Overal waar `effective_ms365_user(cfg)` wordt aangeroepen wordt `load_cfg()` apart uitgevoerd, maar de `cfg` parameter wordt genegeerd in de functie zelf. De functie doet zijn eigen `load_cfg()` call.

**Bestand:** `app/main.py:762`
**Fix:** Verwijder overbodige `load_cfg()` calls bij aanroepen, of cache de cfg in de request state.

---

### 5. **[UX] Onboarding JS: `&& .` in `showToast` call**
Een copy-paste foutje in de onboarding template: `showToast('Copied to clipboard.', 'ok')` en daarna `await setBtnOk()` — deze staan apart ondanks de bedoeling van een chained call. Werkt correct, maar is onduidelijk.

**Bestand:** `app/templates/onboarding.html`
**Fix:** Maak expliciet als aparte statements.

---

### 6. **[Quality] `postfix/control.py` importt van `backup` als local module**
`control.py` doet `from backup import ...` maar draait als script vanuit `/opt/ms365-relay/postfix/`. Werkt omdat `postfix/` op de Python path staat via de entrypoint. Fragiel.

**Bestand:** `postfix/control.py:11`
**Fix:** Gebruik expliciet `from postfix.backup import` of `from .backup import` consistent.

---

### 7. **[Security] `render.py` chown/chmod kan falen zonder logging**
`_ensure_dovecot_readable` in `control.py` en `chmod 600` in `render.py` doen best-effort errors die worden geswallowed. Zou tenminste een warning moeten loggen.

**Bestand:** `postfix/control.py`, `postfix/render.py`
**Fix:** Voeg stderr logging toe bij chown/chmod failures.

---

### 8. **[UX] `docker-compose.yml`: UI healthcheck is er, postfix niet**
Postfix container heeft geen healthcheck. Als postfix niet start, merk je dat alleen aan de mail log.

**Bestand:** `docker-compose.yml`
**Fix:** Voeg postfix healthcheck toe die `/health` of `postfix check` doet.

---

### 9. **[Security] `update_check.json` world-readable in state dir**
`UPDATE_CACHE_PATH = DATA_DIR / "state" / "update_check.json"` — wordt aangemaakt met default umask (0o644). Geen permission hardening.

**Bestand:** `app/main.py`
**Fix:** `os.chmod` naar 0o600 na write.

---

### 10. **[Quality] README: Quick start verwijst naar niet-bestaand `env.example`**
De README noemt `cp env.example .env` maar dat bestand bestaat niet in de repo.

**Bestand:** `README.md`
**Fix:** Verwijder referentie of maak een echte `env.example`.

---

## 📋 Bevestigde werkende tests

```
PASS: test_postfix_backup_rejects_too_many_entries
PASS: test_postfix_backup_rejects_oversized_config_member
PASS: test_postfix_backup_traversal_only_is_empty_bundle
PASS: test_next_refresh_delay_success_uses_normal_interval
PASS: test_next_refresh_delay_failure_uses_fast_retry
PASS: test_next_refresh_delay_retry_is_capped_by_interval

E2E core: OK
E2E mailhog: OK (testmail delivery flow werkt)
```