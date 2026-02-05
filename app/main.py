import hashlib
import json
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
CFG_JSON = DATA_DIR / "config" / "config.json"
DEVICE_FLOW_LOG = DATA_DIR / "state" / "device_flow.log"

templates = Jinja2Templates(directory="/opt/ms365-relay/app/templates")
app = FastAPI(title="ms365-relay")

POSTFIX_CONTROL_URL = os.environ.get("POSTFIX_CONTROL_URL", "http://postfix:18080").rstrip("/")

_device_flow_lock = threading.Lock()
_device_flow_running = False


def load_cfg() -> Dict[str, Any]:
    if not CFG_JSON.exists():
        return {"hostname": "relay.local", "domain": "local", "mynetworks": ["127.0.0.0/8"], "allowed_from": {}, "default_from": {}}
    return json.loads(CFG_JSON.read_text(encoding="utf-8"))


APPLIED_HASH_PATH = DATA_DIR / "state" / "applied.hash"


def save_cfg(cfg: Dict[str, Any]) -> None:
    CFG_JSON.parent.mkdir(parents=True, exist_ok=True)
    CFG_JSON.write_text(json.dumps(cfg, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def cfg_hash(cfg: Dict[str, Any]) -> str:
    # stable hash of config for pending/applied tracking
    raw = json.dumps(cfg, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def get_applied_hash() -> Optional[str]:
    try:
        if APPLIED_HASH_PATH.exists():
            return APPLIED_HASH_PATH.read_text(encoding="utf-8").strip() or None
    except Exception:
        return None
    return None


def set_applied_hash(h: str) -> None:
    APPLIED_HASH_PATH.parent.mkdir(parents=True, exist_ok=True)
    APPLIED_HASH_PATH.write_text((h or "") + "\n", encoding="utf-8")


def sh(cmd, check=True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=check)


def tail(path: Path, n: int = 200) -> str:
    if not path.exists():
        return ""
    try:
        return sh(["tail", "-n", str(n), str(path)], check=False).stdout
    except Exception:
        return path.read_text(encoding="utf-8", errors="ignore")[-8000:]


def parse_queue_size(mailq_out: str) -> int:
    # crude: count queue ids (hex) in mailq output
    # Postfix prints like: ABCDEF1234*  ...
    ids = re.findall(r"^[A-F0-9]{5,}(?:\*|!)?\s", mailq_out, flags=re.M)
    return len(ids)


def token_expiry_ts_best_effort(token_path: Path) -> Optional[int]:
    if not token_path.exists():
        return None
    try:
        data = json.loads(token_path.read_text(encoding="utf-8"))
    except Exception:
        # fallback: file mtime
        return int(token_path.stat().st_mtime)

    # try common MSAL/cache fields
    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                lk = str(k).lower()
                if lk in ("expires_on", "expiresat", "expires_at", "expireson", "expiry"):
                    yield v
                yield from walk(v)
        elif isinstance(obj, list):
            for it in obj:
                yield from walk(it)

    for v in walk(data):
        try:
            ts = int(str(v))
            if ts > 10_000_000_000:
                ts //= 1000
            return ts
        except Exception:
            pass
    return None


def token_expiry_best_effort(token_path: Path) -> Optional[str]:
    ts = token_expiry_ts_best_effort(token_path)
    if ts is None:
        return None
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _control_get(path: str) -> dict:
    import urllib.request
    import ssl

    url = POSTFIX_CONTROL_URL + path
    req = urllib.request.Request(url, headers={"User-Agent": "ms365-relay-ui"})
    with urllib.request.urlopen(req, timeout=10, context=ssl.create_default_context()) as r:
        return json.loads(r.read().decode("utf-8"))


def _control_post(path: str) -> dict:
    import urllib.request
    import ssl

    url = POSTFIX_CONTROL_URL + path
    req = urllib.request.Request(url, method="POST", data=b"", headers={"User-Agent": "ms365-relay-ui"})
    with urllib.request.urlopen(req, timeout=20, context=ssl.create_default_context()) as r:
        return json.loads(r.read().decode("utf-8"))


def postfix_reload() -> str:
    return (_control_post("/reload").get("output") or "ok")


def render_and_reload() -> str:
    return (_control_post("/render-reload").get("output") or "ok")


def ensure_user(login: str, password: str) -> str:
    import urllib.request, ssl

    data = json.dumps({"login": login, "password": password}).encode("utf-8")
    req = urllib.request.Request(
        POSTFIX_CONTROL_URL + "/users/add",
        method="POST",
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "ms365-relay-ui"},
    )
    with urllib.request.urlopen(req, timeout=15, context=ssl.create_default_context()) as r:
        return json.loads(r.read().decode("utf-8")).get("output") or "ok"


def delete_user(login: str) -> str:
    import urllib.request, ssl

    data = json.dumps({"login": login}).encode("utf-8")
    req = urllib.request.Request(
        POSTFIX_CONTROL_URL + "/users/delete",
        method="POST",
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "ms365-relay-ui"},
    )
    with urllib.request.urlopen(req, timeout=15, context=ssl.create_default_context()) as r:
        return json.loads(r.read().decode("utf-8")).get("output") or "ok"


def _sasldb_path() -> str:
    # Persisted sasldb2 shared with postfix container
    return str(DATA_DIR / "sasl" / "sasldb2")


def list_users() -> str:
    try:
        return (_control_get("/users").get("users") or "")
    except Exception:
        return ""


def send_test_mail(to_addr: str, from_addr: str, subject: str, body: str) -> str:
    import urllib.request, ssl

    payload = json.dumps({
        "to_addr": to_addr,
        "from_addr": from_addr,
        "subject": subject,
        "body": body,
    }).encode("utf-8")

    req = urllib.request.Request(
        POSTFIX_CONTROL_URL + "/testmail",
        method="POST",
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "ms365-relay-ui"},
    )
    with urllib.request.urlopen(req, timeout=20, context=ssl.create_default_context()) as r:
        return json.loads(r.read().decode("utf-8")).get("output") or "ok"


def start_device_flow_background() -> None:
    # Delegate to postfix control API
    _control_post("/token/start")


def device_flow_log() -> str:
    try:
        return (_control_get("/device-flow-log").get("log") or "")
    except Exception:
        return ""


def _best_effort_health() -> bool:
    try:
        return bool(_control_get("/health").get("ok"))
    except Exception:
        return False


def _extract_recent_warnings(mail_log: str, limit: int = 6) -> str:
    lines = [ln for ln in (mail_log or "").splitlines() if ln]
    interesting = []
    for ln in reversed(lines):
        ll = ln.lower()
        if (" warn " in ll) or (" err " in ll) or (" fatal" in ll) or ("panic" in ll):
            interesting.append(ln)
        if len(interesting) >= limit:
            break
    return "\n".join(reversed(interesting))


def from_identities(cfg: Dict[str, Any], ms365_user: str) -> list[str]:
    addrs = []

    # configured defaults
    for v in (cfg.get("default_from") or {}).values():
        if v:
            addrs.append(str(v).strip().lower())

    # configured allowed_from lists
    for lst in (cfg.get("allowed_from") or {}).values():
        for a in (lst or []):
            if a:
                addrs.append(str(a).strip().lower())

    if ms365_user:
        addrs.append(ms365_user.strip().lower())

    # unique but stable ordering
    seen = set()
    out = []
    for a in addrs:
        if a and a not in seen:
            seen.add(a)
            out.append(a)
    return out


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    cfg = load_cfg()
    current_hash = cfg_hash(cfg)
    applied_hash = get_applied_hash()
    if not applied_hash:
        # On first run, assume current config was already applied by the container entrypoint.
        set_applied_hash(current_hash)
        applied_hash = current_hash
    pending = (current_hash != applied_hash)

    mailq_out = (_control_get("/mailq").get("mailq") or "")
    qsize = parse_queue_size(mailq_out)
    mail_log = (_control_get("/maillog").get("maillog") or "")
    warn_tail = _extract_recent_warnings(mail_log)

    ms365_user = os.environ.get("MS365_SMTP_USER", "")
    token_path = DATA_DIR / "tokens" / ms365_user if ms365_user else None
    token_exp_ts = token_expiry_ts_best_effort(token_path) if token_path else None

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "cfg": cfg,
            "queue_size": qsize,
            "mailq": mailq_out,
            "mail_log": mail_log,
            "mail_log_warn": warn_tail,
            "postfix_ok": _best_effort_health(),
            "users": list_users(),
            "device_flow_log": device_flow_log(),
            "token_exp_ts": token_exp_ts,
            "pending": pending,
            "from_identities": from_identities(cfg, ms365_user),
            "env": {
                "MS365_SMTP_USER": ms365_user,
                "MS365_TENANT_ID": os.environ.get("MS365_TENANT_ID", ""),
                "MS365_CLIENT_ID": os.environ.get("MS365_CLIENT_ID", ""),
                "RELAYHOST": os.environ.get("RELAYHOST", "[smtp.office365.com]:587"),
            },
        },
    )


@app.post("/settings")
def update_settings(
    hostname: str = Form(...),
    domain: str = Form(...),
    mynetworks: str = Form(""),
):
    """HTML form endpoint (kept for no-JS fallback)."""
    cfg = load_cfg()
    cfg["hostname"] = hostname.strip()
    cfg["domain"] = domain.strip()
    nets = [n.strip() for n in mynetworks.replace(",", " ").split() if n.strip()]
    from urllib.parse import quote

    cfg["mynetworks"] = nets
    save_cfg(cfg)
    return RedirectResponse(url=f"/?toast={quote('Saved (not applied). Click Apply Changes.')}&toastLevel=ok#settings", status_code=303)


@app.post("/api/settings")
def api_settings_save(
    hostname: str = Form(...),
    domain: str = Form(...),
    mynetworks: str = Form(""),
):
    """AJAX endpoint: save settings without reload."""
    cfg = load_cfg()
    cfg["hostname"] = hostname.strip()
    cfg["domain"] = domain.strip()
    nets = [n.strip() for n in mynetworks.replace(",", " ").split() if n.strip()]
    cfg["mynetworks"] = nets
    save_cfg(cfg)

    current_hash = cfg_hash(cfg)
    applied_hash = get_applied_hash()
    pending = bool(applied_hash) and (current_hash != applied_hash)

    return {"ok": True, "pending": pending}


@app.post("/users/add")
def users_add(login: str = Form(...), password: str = Form(...)):
    ensure_user(login.strip(), password)
    return RedirectResponse(url="/", status_code=303)


@app.post("/users/delete")
def users_del(login: str = Form(...)):
    delete_user(login.strip())
    return RedirectResponse(url="/", status_code=303)


@app.post("/from/allow")
def allow_from(login: str = Form(...), from_addr: str = Form(...)):
    cfg = load_cfg()
    login = login.strip()
    addr = from_addr.strip().lower()
    cfg.setdefault("allowed_from", {})
    cfg["allowed_from"].setdefault(login, [])
    from urllib.parse import quote

    if addr and addr not in cfg["allowed_from"][login]:
        cfg["allowed_from"][login].append(addr)
    save_cfg(cfg)
    return RedirectResponse(url=f"/?toast={quote('Saved (not applied). Click Apply Changes.')}&toastLevel=ok#senders", status_code=303)


@app.post("/from/disallow")
def disallow_from(login: str = Form(...), from_addr: str = Form(...)):
    cfg = load_cfg()
    login = login.strip()
    addr = from_addr.strip().lower()
    from urllib.parse import quote

    if login in (cfg.get("allowed_from") or {}):
        cfg["allowed_from"][login] = [a for a in cfg["allowed_from"][login] if a != addr]
    save_cfg(cfg)
    return RedirectResponse(url=f"/?toast={quote('Saved (not applied). Click Apply Changes.')}&toastLevel=ok#senders", status_code=303)


@app.post("/from/default")
def set_default_from(login: str = Form(...), from_addr: str = Form(...)):
    cfg = load_cfg()
    cfg.setdefault("default_from", {})
    from urllib.parse import quote

    cfg["default_from"][login.strip()] = from_addr.strip()
    save_cfg(cfg)
    return RedirectResponse(url=f"/?toast={quote('Saved (not applied). Click Apply Changes.')}&toastLevel=ok#senders", status_code=303)


@app.post("/postfix/reload")
def btn_reload():
    out = postfix_reload()
    return PlainTextResponse(out)


@app.post("/apply")
def apply_changes():
    # Apply saved config.json to postfix by re-rendering + reloading.
    out = render_and_reload()

    # Mark current config as applied.
    cfg = load_cfg()
    set_applied_hash(cfg_hash(cfg))

    # Return to dashboard with a toast.
    from urllib.parse import quote

    msg = (out or "ok").strip() or "ok"
    if len(msg) > 600:
        msg = msg[:600] + "…"
    level = "error" if ("fatal" in msg.lower() or "error" in msg.lower()) else "ok"

    return RedirectResponse(url=f"/?toast={quote('Applied changes.')}&toastLevel={level}#status", status_code=303)


@app.post("/token/start")
def token_start():
    start_device_flow_background()
    return RedirectResponse(url="/", status_code=303)


@app.post("/testmail")
def testmail(
    to_addr: str = Form(...),
    from_addr: str = Form(...),
    subject: str = Form("Test"),
    body: str = Form("Does it work?"),
):
    # Return to the dashboard with a toast message.
    from urllib.parse import quote

    out = send_test_mail(to_addr, from_addr, subject, body)

    # keep it short for the URL
    msg = (out or "ok").strip()
    if len(msg) > 600:
        msg = msg[:600] + "…"

    level = "error" if "exit" in msg.lower() else "ok"

    return RedirectResponse(url=f"/?toast={quote(msg)}&toastLevel={level}#testmail", status_code=303)


@app.get("/api/status")
def api_status():
    cfg = load_cfg()
    mailq_out = (_control_get("/mailq").get("mailq") or "")
    qsize = parse_queue_size(mailq_out)
    mail_log = (_control_get("/maillog").get("maillog") or "")

    ms365_user = os.environ.get("MS365_SMTP_USER", "")
    token_path = DATA_DIR / "tokens" / ms365_user if ms365_user else None
    token_exp_ts = token_expiry_ts_best_effort(token_path) if token_path else None

    current_hash = cfg_hash(cfg)
    applied_hash = get_applied_hash()
    pending = bool(applied_hash) and (current_hash != applied_hash)

    return {
        "ok": _best_effort_health(),
        "pending": pending,
        "queue_size": qsize,
        "mailq": mailq_out,
        "mail_log": mail_log,
        "mail_log_warn": _extract_recent_warnings(mail_log),
        "token_exp_ts": token_exp_ts,
        "from_identities": from_identities(cfg, ms365_user),
        "env": {
            "MS365_SMTP_USER": ms365_user,
            "RELAYHOST": os.environ.get("RELAYHOST", "[smtp.office365.com]:587"),
        },
    }


def _redact_mail_log(text: str) -> str:
    if not text:
        return ""
    out_lines = []
    for ln in text.splitlines():
        ll = ln.lower()
        if "refresh_token=" in ll or "access_token" in ll or "tokenstore::read: refresh=" in ll:
            out_lines.append("[REDACTED token material]")
        else:
            out_lines.append(ln)
    return "\n".join(out_lines)


@app.get("/diagnostics.txt")
def diagnostics_txt():
    # No secrets: we do NOT include token files, and we redact token-like content from logs.
    cfg = load_cfg()
    mailq_out = (_control_get("/mailq").get("mailq") or "")
    mail_log = _redact_mail_log(_control_get("/maillog").get("maillog") or "")

    ms365_user = os.environ.get("MS365_SMTP_USER", "")
    token_path = DATA_DIR / "tokens" / ms365_user if ms365_user else None
    token_exp_ts = token_expiry_ts_best_effort(token_path) if token_path else None

    parts = []
    parts.append("# ms365-relay diagnostics\n")
    parts.append(f"timestamp: {time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime())}\n")
    parts.append("\n## env\n")
    parts.append(f"RELAYHOST={os.environ.get('RELAYHOST','')}\n")
    parts.append(f"MS365_SMTP_USER={ms365_user}\n")
    parts.append(f"token_expiry_ts={token_exp_ts or ''}\n")

    parts.append("\n## config.json\n")
    parts.append(json.dumps(cfg, indent=2, sort_keys=True) + "\n")

    parts.append("\n## mailq\n")
    parts.append(mailq_out.strip() + "\n")

    parts.append("\n## maillog (tail)\n")
    parts.append(mail_log.strip() + "\n")

    return PlainTextResponse("".join(parts))
