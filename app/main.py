import hashlib
import json
import os
import re
import secrets
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, Form, Request, UploadFile, File
from fastapi.responses import Response
from fastapi import HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
APP_DIR = Path(__file__).resolve().parent
CFG_JSON = DATA_DIR / "config" / "config.json"
DEVICE_FLOW_LOG = DATA_DIR / "state" / "device_flow.log"

# App metadata
APP_VERSION = (os.environ.get("APP_VERSION") or "").strip() or "0.0.0"
APP_GITHUB_REPO = (os.environ.get("APP_GITHUB_REPO") or "LickABrick/simple-m365-relay").strip()
APP_GITHUB_REPO_URL = f"https://github.com/{APP_GITHUB_REPO}"

# Update check (stable latest; ignore prereleases/RCs)
UPDATE_CACHE_PATH = DATA_DIR / "state" / "update_check.json"
UPDATE_CHECK_TTL_SECONDS = int(os.environ.get("UPDATE_CHECK_TTL_SECONDS") or "43200")  # 12h

templates = Jinja2Templates(directory=str(APP_DIR / "templates"))
templates.env.globals["APP_VERSION"] = APP_VERSION
templates.env.globals["APP_GITHUB_REPO_URL"] = APP_GITHUB_REPO_URL


def _template_response(name: str, context: dict, status_code: int = 200):
    """Render using Starlette's current request-first template API."""
    request = context.get("request")
    if request is None:
        raise ValueError("template context requires request")
    return templates.TemplateResponse(
        request=request, name=name, context=context, status_code=status_code
    )

app = FastAPI(title="Simple M365 Relay")
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    request.state.csp_nonce = secrets.token_urlsafe(24)
    resp = await call_next(request)
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        f"script-src 'self' 'nonce-{request.state.csp_nonce}'; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'",
    )
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
    if is_https_request(request):
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return resp

from . import auth  # noqa: E402
from . import lockout  # noqa: E402
from .security import client_ip, get_csrf_from_request, is_https_request, require_csrf  # noqa: E402
from .backup import b64d, b64e  # noqa: E402
from .config import validate_cfg_obj  # noqa: E402

POSTFIX_CONTROL_URL = os.environ.get("POSTFIX_CONTROL_URL", "http://postfix:18080").rstrip("/")
POSTFIX_CONTROL_SOCKET = (os.environ.get("POSTFIX_CONTROL_SOCKET") or "").strip()

_device_flow_lock = threading.Lock()
_device_flow_running = False


def _default_cfg() -> Dict[str, Any]:
    return {
        "hostname": "relay.local",
        "domain": "local",
        "mynetworks": ["127.0.0.0/8"],
        "relayhost": "[smtp.office365.com]:587",
        "ms365_smtp_user": "",
        "tls": {"smtpd_25": "may", "smtpd_587": "encrypt"},
        "oauth": {"tenant_id": "", "client_id": "", "auto_refresh_minutes": 30},
        "allowed_from": {},
        "default_from": {},
    }


def load_cfg() -> Dict[str, Any]:
    if not CFG_JSON.exists():
        return _default_cfg()
    cfg = json.loads(CFG_JSON.read_text(encoding="utf-8"))
    # merge defaults for forward-compat
    base = _default_cfg()
    base.update(cfg or {})
    base.setdefault("tls", _default_cfg()["tls"])
    base.setdefault("oauth", _default_cfg()["oauth"])
    base.setdefault("allowed_from", {})
    base.setdefault("default_from", {})
    # ensure new keys exist
    base.setdefault("ms365_smtp_user", "")
    return base


APPLIED_HASH_PATH = DATA_DIR / "state" / "applied.hash"
APPLIED_CFG_PATH = DATA_DIR / "state" / "applied_config.json"


def save_cfg(cfg: Dict[str, Any]) -> None:
    CFG_JSON.parent.mkdir(parents=True, exist_ok=True)
    CFG_JSON.write_text(json.dumps(cfg, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # Best-effort perms hardening
    try:
        os.chmod(CFG_JSON, 0o600)
    except Exception:
        pass


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


def _write_applied_cfg_snapshot(cfg: Dict[str, Any]) -> None:
    try:
        APPLIED_CFG_PATH.parent.mkdir(parents=True, exist_ok=True)
        APPLIED_CFG_PATH.write_text(json.dumps(cfg, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except Exception:
        pass


def read_applied_cfg_snapshot() -> Optional[Dict[str, Any]]:
    try:
        if APPLIED_CFG_PATH.exists():
            return json.loads(APPLIED_CFG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None
    return None


def set_applied_hash(h: str) -> None:
    APPLIED_HASH_PATH.parent.mkdir(parents=True, exist_ok=True)
    APPLIED_HASH_PATH.write_text((h or "") + "\n", encoding="utf-8")


def set_applied_state(cfg: Dict[str, Any]) -> None:
    # Persist both the hash and a snapshot so we can discard saved-but-not-applied changes later.
    set_applied_hash(cfg_hash(cfg))
    _write_applied_cfg_snapshot(cfg)


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


def _jwt_exp_best_effort(jwt: str) -> Optional[int]:
    # Parse JWT exp (no signature verification; best-effort display only)
    try:
        import base64

        parts = (jwt or "").split(".")
        if len(parts) < 2:
            return None
        payload = parts[1]
        payload += "=" * (-len(payload) % 4)
        raw = base64.urlsafe_b64decode(payload.encode("utf-8"))
        obj = json.loads(raw.decode("utf-8"))
        exp = obj.get("exp")
        if exp is None:
            return None
        return int(exp)
    except Exception:
        return None


def token_expiry_ts_best_effort(token_path: Path) -> Optional[int]:
    if not token_path.exists():
        return None
    try:
        data = json.loads(token_path.read_text(encoding="utf-8"))
    except Exception:
        # fallback: file mtime
        return int(token_path.stat().st_mtime)

    # common field
    try:
        exp0 = int(str(data.get("expiry", "") or 0))
        if exp0 > 0:
            return exp0
    except Exception:
        pass

    # fallback: access_token JWT exp
    jwt = data.get("access_token") if isinstance(data, dict) else None
    jwt_exp = _jwt_exp_best_effort(jwt or "")
    if jwt_exp:
        return jwt_exp

    # try nested common MSAL/cache fields
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
            if ts > 0:
                return ts
        except Exception:
            pass

    return None


def safe_token_filename(user: str) -> str:
    """Derive a safe filename for token storage.

    Token filenames must not allow path traversal or separators.
    """
    u = (user or "").strip()
    if not u:
        return ""
    # Replace anything not in a safe set.
    u2 = re.sub(r"[^A-Za-z0-9_.@+\-]", "_", u)
    # Disallow traversal artifacts.
    while ".." in u2:
        u2 = u2.replace("..", "__")
    u2 = u2.strip("._-")
    return u2[:128]


def token_file_for_ms365_user(ms365_user: str) -> Optional[Path]:
    if not ms365_user:
        return None
    safe = safe_token_filename(ms365_user)
    if not safe:
        return None
    p = DATA_DIR / "tokens" / safe

    # legacy support: if the old filename exists and is safe-ish (no separators), use it.
    legacy = (DATA_DIR / "tokens" / ms365_user.strip())
    try:
        if not p.exists():
            leg_name = ms365_user.strip()
            if "/" not in leg_name and "\\" not in leg_name and ".." not in leg_name and legacy.exists():
                return legacy
    except Exception:
        pass

    return p


def token_expiry_best_effort(token_path: Path) -> Optional[str]:
    ts = token_expiry_ts_best_effort(token_path)
    if ts is None:
        return None
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _control_token() -> str:
    """Read the shared control token used to authenticate to the postfix control API.

    Priority:
      1) CONTROL_TOKEN env
      2) /data/state/control.token (shared volume)

    We keep this in the shared /data volume so UI can talk to postfix without exposing
    the control API unauthenticated.
    """
    tok = (os.environ.get("CONTROL_TOKEN") or "").strip()
    if tok:
        return tok
    try:
        p = DATA_DIR / "state" / "control.token"
        if p.exists():
            return (p.read_text(encoding="utf-8", errors="ignore") or "").strip()
    except Exception:
        pass
    return ""


def _control_headers(extra: Optional[dict] = None) -> dict:
    h = {"User-Agent": "simple-m365-relay-ui"}
    tok = _control_token()
    if tok:
        h["X-Control-Token"] = tok
    if extra:
        h.update(extra)
    return h


def _unix_http_json(method: str, path: str, body: bytes = b"", headers: Optional[dict] = None, timeout: float = 10.0) -> dict:
    """Minimal HTTP client over a unix domain socket.

    We keep this tiny on purpose to avoid extra deps.
    """
    import socket

    sock_path = POSTFIX_CONTROL_SOCKET
    if not sock_path:
        raise RuntimeError("POSTFIX_CONTROL_SOCKET not set")

    hdrs = _control_headers(headers or {})
    if body:
        hdrs.setdefault("Content-Length", str(len(body)))
    else:
        hdrs.setdefault("Content-Length", "0")
    hdrs.setdefault("Host", "postfix")

    req = f"{method} {path} HTTP/1.1\r\n" + "\r\n".join([f"{k}: {v}" for k, v in hdrs.items()]) + "\r\n\r\n"

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(sock_path)
    try:
        s.sendall(req.encode("utf-8") + (body or b""))
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
            # stop early if body complete
            if b"\r\n\r\n" in data:
                head, rest = data.split(b"\r\n\r\n", 1)
                # try parse content-length
                hl = head.decode("iso-8859-1", "ignore").split("\r\n")
                clen = None
                for ln in hl[1:]:
                    if ln.lower().startswith("content-length:"):
                        try:
                            clen = int(ln.split(":", 1)[1].strip())
                        except Exception:
                            pass
                if clen is not None and len(rest) >= clen:
                    break
        if b"\r\n\r\n" not in data:
            raise RuntimeError("invalid response")
        head, body_bytes = data.split(b"\r\n\r\n", 1)
        status_line = head.split(b"\r\n", 1)[0].decode("ascii", "ignore")
        try:
            status = int(status_line.split()[1])
        except Exception:
            status = 0
        try:
            payload = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            payload = {"_raw": body_bytes.decode("utf-8", errors="replace")}

        if status >= 400:
            # Preserve error details from the control API when possible.
            err = None
            if isinstance(payload, dict):
                err = payload.get("error") or payload.get("detail")
            msg = f"control api error HTTP {status}"
            if err:
                msg += f": {err}"
            raise RuntimeError(msg)

        return payload
    finally:
        try:
            s.close()
        except Exception:
            pass


def _control_get(path: str) -> dict:
    import urllib.request
    import ssl

    if POSTFIX_CONTROL_SOCKET:
        return _unix_http_json("GET", path, timeout=10)

    url = POSTFIX_CONTROL_URL + path
    req = urllib.request.Request(url, headers=_control_headers())
    with urllib.request.urlopen(req, timeout=10, context=ssl.create_default_context()) as r:
        return json.loads(r.read().decode("utf-8"))


def _control_post(path: str) -> dict:
    import urllib.request
    import ssl

    if POSTFIX_CONTROL_SOCKET:
        return _unix_http_json("POST", path, body=b"", timeout=20)

    url = POSTFIX_CONTROL_URL + path
    req = urllib.request.Request(url, method="POST", data=b"", headers=_control_headers())
    with urllib.request.urlopen(req, timeout=20, context=ssl.create_default_context()) as r:
        return json.loads(r.read().decode("utf-8"))


def _control_post_json(path: str, obj: dict, timeout: int = 25) -> dict:
    import urllib.request
    import ssl

    body = json.dumps(obj).encode("utf-8")
    headers = {"Content-Type": "application/json"}

    if POSTFIX_CONTROL_SOCKET:
        return _unix_http_json("POST", path, body=body, headers=headers, timeout=timeout)

    url = POSTFIX_CONTROL_URL + path
    req = urllib.request.Request(url, method="POST", data=body, headers=_control_headers(headers))
    with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
        return json.loads(r.read().decode("utf-8"))


def postfix_reload() -> str:
    return (_control_post("/reload").get("output") or "ok")


def render_and_reload() -> str:
    return (_control_post("/render-reload").get("output") or "ok")


def render_validate_only() -> str:
    return (_control_post("/render-validate").get("output") or "ok")


def ensure_user(login: str, password: str) -> str:
    import urllib.request, ssl

    data = json.dumps({"login": login, "password": password}).encode("utf-8")
    if POSTFIX_CONTROL_SOCKET:
        j = _unix_http_json("POST", "/users/add", body=data, headers={"Content-Type": "application/json"}, timeout=15)
        return j.get("output") or "ok"

    req = urllib.request.Request(
        POSTFIX_CONTROL_URL + "/users/add",
        method="POST",
        data=data,
        headers=_control_headers({"Content-Type": "application/json"}),
    )
    with urllib.request.urlopen(req, timeout=15, context=ssl.create_default_context()) as r:
        return json.loads(r.read().decode("utf-8")).get("output") or "ok"


def delete_user(login: str) -> str:
    import urllib.request, ssl

    data = json.dumps({"login": login}).encode("utf-8")
    if POSTFIX_CONTROL_SOCKET:
        j = _unix_http_json("POST", "/users/delete", body=data, headers={"Content-Type": "application/json"}, timeout=15)
        return j.get("output") or "ok"

    req = urllib.request.Request(
        POSTFIX_CONTROL_URL + "/users/delete",
        method="POST",
        data=data,
        headers=_control_headers({"Content-Type": "application/json"}),
    )
    with urllib.request.urlopen(req, timeout=15, context=ssl.create_default_context()) as r:
        return json.loads(r.read().decode("utf-8")).get("output") or "ok"


def _sasldb_path() -> str:
    # Persisted sasldb2 shared with postfix container
    return str(DATA_DIR / "sasl" / "sasldb2")


def list_users_raw() -> str:
    try:
        return (_control_get("/users").get("users") or "")
    except Exception:
        return ""


def parse_sasl_users(text: str) -> list[str]:
    # Dovecot passwd-file (or sasldblistusers2 legacy) output looks like:
    #   user@example.internal: ...
    # Filter strictly to avoid showing error text or weird entries as "users".
    out: list[str] = []
    for ln in (text or "").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        if ":" not in ln:
            continue
        name = ln.split(":", 1)[0].strip()
        if not name or any(ch.isspace() for ch in name):
            continue
        try:
            name2 = _validate_login(name)
        except Exception:
            continue
        out.append(name2)

    # stable unique
    seen = set()
    uniq = []
    for u in out:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq


def _normalize_testmail_output(out: str) -> str:
    # sendmail sometimes returns a DSN-related line like:
    #   "Mail Delivery Status Report will be mailed to <user@domain>"
    # That is confusing in UI; treat it as queued.
    txt = (out or "").strip()
    if "Mail Delivery Status Report will be mailed to" in txt:
        return "queued"
    return txt


def send_test_mail(to_addr: str, from_addr: str, subject: str, body: str) -> str:
    import urllib.request, ssl

    # Allow blank From in UI: fallback to configured MS365 identity.
    if not (from_addr or "").strip():
        from_addr = effective_ms365_user(load_cfg())

    payload = json.dumps({
        "to_addr": to_addr,
        "from_addr": from_addr,
        "subject": subject,
        "body": body,
    }).encode("utf-8")

    if POSTFIX_CONTROL_SOCKET:
        j = _unix_http_json("POST", "/testmail", body=payload, headers={"Content-Type": "application/json"}, timeout=20)
        return _normalize_testmail_output(j.get("output") or "") or "queued"

    req = urllib.request.Request(
        POSTFIX_CONTROL_URL + "/testmail",
        method="POST",
        data=payload,
        headers=_control_headers({"Content-Type": "application/json"}),
    )
    with urllib.request.urlopen(req, timeout=20, context=ssl.create_default_context()) as r:
        out = json.loads(r.read().decode("utf-8")).get("output") or ""
        return _normalize_testmail_output(out) or "queued"


_QUEUE_ID_RE = re.compile(r"queued as\s+([A-Z0-9]{5,})", re.IGNORECASE)


def extract_queue_id_best_effort(sendmail_out: str) -> Optional[str]:
    """Extract the Postfix queue ID from sendmail -v output."""
    txt = (sendmail_out or "").strip()
    if not txt:
        return None

    # Search line-by-line for stability.
    for ln in txt.splitlines():
        m = _QUEUE_ID_RE.search(ln)
        if m:
            return m.group(1).strip().upper()

    # Fallback: search in entire blob.
    m = _QUEUE_ID_RE.search(txt)
    if m:
        return m.group(1).strip().upper()

    return None


def _delivery_state_from_line(line: str) -> Optional[str]:
    ll = (line or "").lower()
    if "status=sent" in ll:
        return "sent"
    if "status=deferred" in ll:
        return "deferred"
    if "status=bounced" in ll:
        return "bounced"
    if "status=reject" in ll or "reject:" in ll:
        return "rejected"
    return None


def verify_delivery_best_effort(queue_id: str, max_wait_seconds: int = 8) -> dict:
    """Best-effort delivery verification.

    We look for the queue id in recent maillog lines and in mailq.
    This is inherently heuristic.
    """
    qid = (queue_id or "").strip().upper()
    if not qid:
        return {"queue_id": None, "state": "unknown"}

    last_line = ""
    last_state = "unknown"
    in_queue = None

    for i in range(max(1, int(max_wait_seconds))):
        try:
            mail_log = _redact_mail_log((_control_get("/maillog").get("maillog") or ""))
        except Exception:
            mail_log = ""

        try:
            mailq = str((_control_get("/mailq").get("mailq") or ""))
        except Exception:
            mailq = ""

        in_queue = (qid in mailq)

        # Find the most recent log line referencing the queue id.
        lines = [ln for ln in (mail_log or "").splitlines() if qid in ln]
        if lines:
            last_line = lines[-1]
            st = _delivery_state_from_line(last_line)
            if st:
                last_state = st

        if last_state in ("sent", "bounced", "rejected"):
            break

        if in_queue:
            last_state = "queued"
        elif last_state == "unknown" and last_line:
            # We saw it in logs but couldn't classify.
            last_state = "seen"

        # Wait for log/queue to update.
        if i < max_wait_seconds - 1:
            time.sleep(1)

    return {
        "queue_id": qid,
        "state": last_state,
        "in_queue": in_queue,
        "line": last_line,
    }


def start_device_flow_background() -> None:
    # Delegate to postfix control API
    _control_post("/token/start")


def refresh_token_now() -> str:
    return (_control_post("/token/refresh").get("output") or "ok")


def get_device_flow_log() -> str:
    try:
        return (_control_get("/device-flow-log").get("log") or "")
    except Exception:
        return ""


def get_token_refresh_log() -> str:
    try:
        return (_control_get("/token/refresh-log").get("log") or "")
    except Exception:
        return ""


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


def _validate_login(v: str) -> str:
    """Conservative login validation (stored as key in allowed_from/default_from).

    Allow only email-ish logins (no whitespace/control chars).
    """
    v = _reject_ctl(v)
    v = v.strip()
    if not v or len(v) > 254:
        raise ValueError("invalid login")
    if re.search(r"\s", v):
        raise ValueError("invalid login")
    if not re.fullmatch(r"[A-Za-z0-9._%+\-@]+", v):
        raise ValueError("invalid login")
    return v


def _validate_emailish(v: str) -> str:
    v = _reject_ctl(v)
    v = v.strip().lower()
    if not v or len(v) > 254:
        raise ValueError("invalid address")
    if re.search(r"\s", v):
        raise ValueError("invalid address")
    # very small sanity check
    if "@" not in v or v.startswith("@") or v.endswith("@"):  # noqa: PLR1714
        raise ValueError("invalid address")
    if not re.fullmatch(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+", v):
        raise ValueError("invalid address")
    return v


def parse_addr_list(text: str) -> list[str]:
    # accepts comma/space/newline separated
    raw = (text or "").replace(",", " ")
    parts = []
    for ln in raw.splitlines():
        parts.extend([p.strip() for p in ln.split() if p.strip()])
    # normalize + unique (email-ish)
    seen = set()
    out = []
    for a in parts:
        try:
            aa = _validate_emailish(a)
        except Exception:
            continue
        if aa and aa not in seen:
            seen.add(aa)
            out.append(aa)
    return out


def effective_ms365_user(cfg: Dict[str, Any]) -> str:
    # Prefer env for backwards compatibility, fallback to config for v1.1.0+
    env_u = (os.environ.get("MS365_SMTP_USER") or "").strip()
    if env_u:
        return env_u
    return str((cfg or {}).get("ms365_smtp_user") or "").strip()


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


def _is_public_path(path: str) -> bool:
    if path in ("/login", "/logout", "/setup", "/healthz"):
        return True
    if path.startswith("/static"):
        return True
    return False


def onboarding_complete(cfg: Dict[str, Any]) -> bool:
    relayhost = str((cfg or {}).get("relayhost") or "").strip()
    ms365_user = str((cfg or {}).get("ms365_smtp_user") or "").strip()
    oauth = (cfg or {}).get("oauth") or {}
    tenant_id = str((oauth or {}).get("tenant_id") or "").strip()
    client_id = str((oauth or {}).get("client_id") or "").strip()
    return bool(relayhost and ms365_user and tenant_id and client_id)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path

    # Setup required first
    # Allow static assets (CSS/JS/favicon) to load on /setup and /login.
    if not auth.admin_exists() and (not _is_public_path(path)):
        return RedirectResponse(url="/setup", status_code=303)

    # If admin exists, require login for everything except login/setup/logout
    if auth.admin_exists() and (not _is_public_path(path)):
        tok = request.cookies.get(auth.SESSION_COOKIE, "")
        try:
            sess = auth.read_session(tok)
        except Exception:
            sess = None

        if not sess:
            # For API calls, do not redirect (fetch() will follow and break JSON parsing).
            if path.startswith("/api/"):
                return Response(content="Unauthorized", status_code=401)
            return RedirectResponse(url="/login", status_code=303)

        request.state.user = sess.get("u")
        request.state.csrf = sess.get("c")

        # CSRF protection for API POSTs (AJAX)
        if path.startswith("/api/") and request.method in ("POST", "PUT", "PATCH", "DELETE"):
            provided = get_csrf_from_request(request)
            if not provided or provided != request.state.csrf:
                return Response(content="Forbidden", status_code=403)

        # Onboarding gate (core settings only; OAuth device flow optional)
        if (not path.startswith("/api/")) and (path != "/onboarding"):
            try:
                if not onboarding_complete(load_cfg()):
                    return RedirectResponse(url="/onboarding", status_code=303)
            except Exception:
                pass

    return await call_next(request)


@app.get("/setup", response_class=HTMLResponse)
def setup_get(request: Request):
    if auth.admin_exists():
        return RedirectResponse(url="/", status_code=303)

    # First-run CSRF for setup screen
    tok = secrets.token_urlsafe(24)
    resp = _template_response("setup.html", {"request": request, "title": "Create admin", "error": None, "csrf_token": tok})
    resp.set_cookie("sm365r_setup_csrf", tok, httponly=True, samesite="lax", secure=is_https_request(request), max_age=3600, path="/")
    return resp


@app.post("/setup")
def setup_post(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    password2: str = Form(""),
    csrf_token: str = Form(""),
):
    if auth.admin_exists():
        return RedirectResponse(url="/", status_code=303)

    expected = request.cookies.get("sm365r_setup_csrf", "")
    if not expected or not csrf_token or not secrets.compare_digest(csrf_token, expected):
        return _template_response(
            "setup.html",
            {"request": request, "title": "Create admin", "error": "This form expired. Refresh the page and try again.", "csrf_token": expected},
            status_code=403,
        )

    username = (username or "").strip()
    if not username:
        return _template_response("setup.html", {"request": request, "title": "Create admin", "error": "Username is required."})
    if len(username) < 3:
        return _template_response("setup.html", {"request": request, "title": "Create admin", "error": "Username must be at least 3 characters."})
    if password != password2:
        return _template_response("setup.html", {"request": request, "title": "Create admin", "error": "Passwords do not match."})
    ok, msg = auth.validate_new_password(password)
    if not ok:
        return _template_response("setup.html", {"request": request, "title": "Create admin", "error": msg})

    pw_hash = auth.hash_password(password)
    auth.save_admin(username, pw_hash)

    resp = RedirectResponse(url="/", status_code=303)
    csrf = auth.new_csrf_token()
    resp.set_cookie(
        auth.SESSION_COOKIE,
        auth.make_session(username, csrf),
        httponly=True,
        samesite="lax",
        secure=is_https_request(request),
        max_age=auth.SESSION_MAX_AGE_SECONDS,
        path="/",
    )
    return resp


@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    if not auth.admin_exists():
        return RedirectResponse(url="/setup", status_code=303)

    # If already signed in, go to dashboard.
    if auth.session_user(request.cookies.get(auth.SESSION_COOKIE, "")):
        return RedirectResponse(url="/", status_code=303)

    tok = secrets.token_urlsafe(24)
    resp = _template_response("login.html", {"request": request, "title": "Sign in", "error": None, "csrf_token": tok})
    resp.set_cookie("sm365r_login_csrf", tok, httponly=True, samesite="lax", secure=is_https_request(request), max_age=3600, path="/")
    return resp


@app.post("/login")
def login_post(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    csrf_token: str = Form(""),
):
    if not auth.admin_exists():
        return RedirectResponse(url="/setup", status_code=303)

    expected = request.cookies.get("sm365r_login_csrf", "")
    if not expected or not csrf_token or not secrets.compare_digest(csrf_token, expected):
        return _template_response(
            "login.html",
            {"request": request, "title": "Sign in", "error": "This form expired. Refresh the page and try again.", "csrf_token": expected},
            status_code=403,
        )

    ip = client_ip(request)
    rem = lockout.get_lock_remaining(ip)
    if rem > 0:
        return _template_response(
            "login.html",
            {"request": request, "title": "Sign in", "error": f"Too many failed attempts. Try again in {rem} seconds.", "csrf_token": expected},
        )

    admin = auth.load_admin()
    if not admin:
        return _template_response("login.html", {"request": request, "title": "Sign in", "error": "Auth state missing/corrupt. Recreate admin.", "csrf_token": expected})

    username = (username or "").strip()
    if username != admin.username or (not auth.verify_password(password, admin.password_hash)):
        count, lock_for = lockout.record_failure(ip)
        if lock_for:
            return _template_response(
                "login.html",
                {"request": request, "title": "Sign in", "error": f"Too many failed attempts. Locked for {lock_for//60} minutes.", "csrf_token": expected},
            )
        return _template_response(
            "login.html",
            {"request": request, "title": "Sign in", "error": "Invalid username or password.", "csrf_token": expected},
        )

    lockout.clear(ip)

    resp = RedirectResponse(url="/", status_code=303)
    csrf = auth.new_csrf_token()
    resp.set_cookie(
        auth.SESSION_COOKIE,
        auth.make_session(username, csrf),
        httponly=True,
        samesite="lax",
        secure=is_https_request(request),
        max_age=auth.SESSION_MAX_AGE_SECONDS,
        path="/",
    )
    return resp


@app.post("/logout")
def logout_post(request: Request, csrf_token: str = Form("")):
    # CSRF-protected logout
    try:
        require_csrf(request, csrf_token)
    except HTTPException:
        # if token missing, still clear cookie but redirect to login
        pass
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie(auth.SESSION_COOKIE, path="/")
    return resp


@app.get("/onboarding", response_class=HTMLResponse)
def onboarding_get(request: Request):
    cfg = load_cfg()

    ms365_user = effective_ms365_user(cfg)
    env_ms365_user = (os.environ.get("MS365_SMTP_USER") or "").strip()
    cfg_ms365_user = str((cfg or {}).get("ms365_smtp_user") or "").strip()
    token_exp_ts = None
    try:
        token_exp_ts = (_control_get("/token/status") or {}).get("token_exp_ts")
    except Exception:
        token_exp_ts = None

    toast = str(request.query_params.get("toast") or "")
    toast_level = str(request.query_params.get("toastLevel") or "ok")

    return _template_response(
        "onboarding.html",
        {
            "request": request,
            "title": "Onboarding",
            "cfg": cfg,
            "csrf_token": getattr(request.state, "csrf", ""),
            "token_exp_ts": token_exp_ts,
            "device_flow_log": tail(DEVICE_FLOW_LOG, 400),
            "onboarding_ok": onboarding_complete(cfg),
            "ms365_user": ms365_user,
            "env_ms365_user": env_ms365_user,
            "cfg_ms365_user": cfg_ms365_user,
            "toast": toast,
            "toast_level": toast_level,
        },
    )


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    cfg = load_cfg()
    current_hash = cfg_hash(cfg)
    applied_hash = get_applied_hash()
    if not applied_hash:
        # On first run, assume current config was already applied by the container entrypoint.
        set_applied_state(cfg)
        applied_hash = cfg_hash(cfg)
    pending = (current_hash != applied_hash)

    # Best-effort: dashboard should not 500 if postfix/control socket is still starting.
    try:
        mailq_out = (_control_get("/mailq").get("mailq") or "")
    except Exception:
        mailq_out = ""
    qsize = parse_queue_size(mailq_out)

    try:
        mail_log_raw = (_control_get("/maillog").get("maillog") or "")
    except Exception:
        mail_log_raw = ""
    mail_log = _redact_mail_log(mail_log_raw)
    warn_tail = _extract_recent_warnings(mail_log)

    ms365_user = effective_ms365_user(cfg)
    env_ms365_user = (os.environ.get("MS365_SMTP_USER") or "").strip()
    cfg_ms365_user = str((cfg or {}).get("ms365_smtp_user") or "").strip()
    token_exp_ts = None
    try:
        token_exp_ts = (_control_get("/token/status") or {}).get("token_exp_ts")
    except Exception:
        token_exp_ts = None

    user = getattr(request.state, "user", "")
    csrf_token = getattr(request.state, "csrf", "")

    return _template_response(
        "index.html",
        {
            "request": request,
            "user": user,
            "csrf_token": csrf_token,
            "cfg": cfg,
            "queue_size": qsize,
            "mailq": mailq_out,
            "mail_log": mail_log,
            "mail_log_warn": warn_tail,
            "postfix_ok": _best_effort_health(),
            "users": list_users_raw(),
            "users_list": parse_sasl_users(list_users_raw()),
            "device_flow_log": device_flow_log(),
            "token_refresh_log": get_token_refresh_log(),
            "token_exp_ts": token_exp_ts,
            "pending": pending,
            "from_identities": from_identities(cfg, ms365_user),
            "env": {
                # effective value (env-first fallback)
                "MS365_SMTP_USER": ms365_user,
                # for debugging/UX: show both sources
                "ENV_MS365_SMTP_USER": env_ms365_user,
                "CFG_MS365_SMTP_USER": cfg_ms365_user,
                "MS365_TENANT_ID": (cfg.get("oauth") or {}).get("tenant_id", ""),
                "MS365_CLIENT_ID": (cfg.get("oauth") or {}).get("client_id", ""),
                "RELAYHOST": cfg.get("relayhost") or os.environ.get("RELAYHOST", "[smtp.office365.com]:587"),
                "AUTO_TOKEN_REFRESH_MINUTES": str((cfg.get("oauth") or {}).get("auto_refresh_minutes", "")),
            },
        },
    )


@app.post("/settings")
def update_settings(
    request: Request,
    csrf_token: str = Form(""),
    hostname: str = Form(...),
    domain: str = Form(...),
    mynetworks: str = Form(""),
    relayhost: str = Form(""),
    ms365_smtp_user: str = Form(""),
    tls_25: str = Form("may"),
    tls_587: str = Form("encrypt"),
    tenant_id: str = Form(""),
    client_id: str = Form(""),
    auto_refresh_minutes: str = Form("30"),
):
    """HTML form endpoint (kept for no-JS fallback)."""
    require_csrf(request, csrf_token)
    cfg = load_cfg()
    cfg["hostname"] = _validate_fqdnish(hostname, cfg.get("hostname") or "relay.local")
    cfg["domain"] = _validate_fqdnish(domain, cfg.get("domain") or "local")
    from urllib.parse import quote

    cfg["mynetworks"] = _validate_mynetworks(mynetworks)

    cfg["relayhost"] = _validate_relayhost(relayhost, cfg.get("relayhost") or "[smtp.office365.com]:587")
    if (ms365_smtp_user or "").strip():
        cfg["ms365_smtp_user"] = _reject_ctl(ms365_smtp_user or "")
    cfg.setdefault("tls", {})
    cfg["tls"]["smtpd_25"] = _validate_tls_level(tls_25, "may")
    cfg["tls"]["smtpd_587"] = _validate_tls_level(tls_587, "encrypt")

    cfg.setdefault("oauth", {})
    cfg["oauth"]["tenant_id"] = _reject_ctl(tenant_id or "")
    cfg["oauth"]["client_id"] = _reject_ctl(client_id or "")
    cfg["oauth"]["auto_refresh_minutes"] = _validate_int(auto_refresh_minutes, 30)

    save_cfg(cfg)
    return RedirectResponse(url=f"/?toast={quote('Saved (not applied). Click Apply Changes.')}&toastLevel=ok#settings", status_code=303)


def _validate_tls_level(v: str, default: str) -> str:
    v = (v or "").strip().lower()
    if v in ("none", "may", "encrypt"):
        return v
    return default


def _has_ctl(s: str) -> bool:
    return any((ord(ch) < 32) or (ord(ch) == 127) for ch in (s or ""))


def _reject_ctl(s: str) -> str:
    s = (s or "").strip()
    if _has_ctl(s) or "\n" in s or "\r" in s or "\x00" in s:
        raise ValueError("invalid control characters")
    return s


def _validate_fqdnish(v: str, default: str) -> str:
    """Strict-ish validation for hostname/domain to prevent config injection.

    We accept LDH labels separated by dots, 1-253 chars total.
    """
    import re

    v = _reject_ctl(v)
    if not v:
        return default
    if len(v) > 253:
        return default
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*", v):
        return default
    return v


def _validate_relayhost(v: str, default: str) -> str:
    """Validate relayhost format like [smtp.office365.com]:587 or smtp.example:587."""
    import re

    v = _reject_ctl(v)
    if not v:
        return default
    # allow bracketed host or plain host, optional port
    if not re.fullmatch(r"\[?[A-Za-z0-9.-]+\]?(?::\d{2,5})?", v):
        return default
    return v


def _validate_mynetworks(v: str) -> list[str]:
    """Parse and validate Postfix mynetworks tokens (CIDR/IP only)."""
    import ipaddress

    v = _reject_ctl(v)
    toks = [t.strip() for t in v.replace(",", " ").split() if t.strip()]
    out: list[str] = []
    for t in toks:
        try:
            if "/" in t:
                ipaddress.ip_network(t, strict=False)
                out.append(t)
            else:
                # allow single host IP -> normalize to /32 or /128
                ip = ipaddress.ip_address(t)
                out.append(str(ip) + ("/32" if ip.version == 4 else "/128"))
        except Exception:
            # skip invalid tokens
            continue
    # stable unique
    seen = set()
    uniq = []
    for n in out:
        if n not in seen:
            seen.add(n)
            uniq.append(n)
    return uniq


def _validate_int(v: str, default: int, lo: int = 0, hi: int = 1440) -> int:
    try:
        n = int(str(v).strip())
    except Exception:
        return default
    return max(lo, min(hi, n))


@app.post("/api/settings")
def api_settings_save(
    hostname: str = Form(""),
    domain: str = Form(""),
    mynetworks: str = Form(""),
    relayhost: str = Form(""),
    ms365_smtp_user: str = Form(""),
    tls_25: str = Form("may"),
    tls_587: str = Form("encrypt"),
    tenant_id: str = Form(""),
    client_id: str = Form(""),
    auto_refresh_minutes: str = Form("30"),
):
    """AJAX endpoint: save settings without reload.

    Note: fields are optional so onboarding can save partial configuration.
    """
    try:
        cfg = load_cfg()

        if hostname.strip():
            cfg["hostname"] = _validate_fqdnish(hostname, cfg.get("hostname") or "relay.local")
        if domain.strip():
            cfg["domain"] = _validate_fqdnish(domain, cfg.get("domain") or "local")
        if mynetworks.strip():
            cfg["mynetworks"] = _validate_mynetworks(mynetworks)

        cfg["relayhost"] = _validate_relayhost(relayhost, cfg.get("relayhost") or "[smtp.office365.com]:587")
        if (ms365_smtp_user or "").strip():
            cfg["ms365_smtp_user"] = _reject_ctl(ms365_smtp_user or "")
        cfg.setdefault("tls", {})
        cfg["tls"]["smtpd_25"] = _validate_tls_level(tls_25, "may")
        cfg["tls"]["smtpd_587"] = _validate_tls_level(tls_587, "encrypt")

        cfg.setdefault("oauth", {})
        cfg["oauth"]["tenant_id"] = _reject_ctl(tenant_id or "")
        cfg["oauth"]["client_id"] = _reject_ctl(client_id or "")
        cfg["oauth"]["auto_refresh_minutes"] = _validate_int(auto_refresh_minutes, 30)

        save_cfg(cfg)

        current_hash = cfg_hash(cfg)
        applied_hash = get_applied_hash()
        pending = bool(applied_hash) and (current_hash != applied_hash)

        return {"ok": True, "pending": pending}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/users/add")
def users_add(request: Request, csrf_token: str = Form(""), login: str = Form(...), password: str = Form(...)):
    # HTML fallback
    require_csrf(request, csrf_token)
    ensure_user(login.strip(), password)
    return RedirectResponse(url="/", status_code=303)


@app.post("/users/delete")
def users_del(request: Request, csrf_token: str = Form(""), login: str = Form(...)):
    # HTML fallback
    require_csrf(request, csrf_token)
    delete_user(login.strip())
    return RedirectResponse(url="/", status_code=303)


@app.get("/api/users")
def api_users_list():
    raw = list_users_raw()
    return {"ok": True, "users": raw, "users_list": parse_sasl_users(raw)}


@app.post("/api/users/add")
def api_users_add(login: str = Form(...), password: str = Form(...)):
    try:
        login2 = _validate_login(login)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e) or "invalid login")

    pw = str(password or "")
    if not pw:
        raise HTTPException(status_code=400, detail="missing password")

    try:
        ensure_user(login2, pw)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    raw = list_users_raw()
    return {"ok": True, "users": raw, "users_list": parse_sasl_users(raw)}


@app.post("/api/users/delete")
def api_users_delete(login: str = Form(...)):
    try:
        login2 = _validate_login(login)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e) or "invalid login")

    try:
        delete_user(login2)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    raw = list_users_raw()
    return {"ok": True, "users": raw, "users_list": parse_sasl_users(raw)}


@app.post("/from/allow")
def allow_from(request: Request, csrf_token: str = Form(""), login: str = Form(...), from_addr: str = Form(...)):
    # HTML fallback
    require_csrf(request, csrf_token)
    cfg = load_cfg()
    login = _validate_login(login)
    addrs = parse_addr_list(from_addr)
    cfg.setdefault("allowed_from", {})
    cfg["allowed_from"].setdefault(login, [])
    from urllib.parse import quote

    added = 0
    for addr in addrs:
        if addr and addr not in cfg["allowed_from"][login]:
            cfg["allowed_from"][login].append(addr)
            added += 1
    save_cfg(cfg)

    msg = "Saved (not applied). Click Apply Changes."
    if added == 0 and addrs:
        msg = "No changes (addresses already allowed). Saved (not applied)."

    return RedirectResponse(url=f"/?toast={quote(msg)}&toastLevel=ok#senders", status_code=303)


@app.post("/from/disallow")
def disallow_from(request: Request, csrf_token: str = Form(""), login: str = Form(...), from_addr: str = Form(...)):
    # HTML fallback
    require_csrf(request, csrf_token)
    cfg = load_cfg()
    login = login.strip()
    addr = from_addr.strip().lower()
    from urllib.parse import quote

    if login in (cfg.get("allowed_from") or {}):
        cfg["allowed_from"][login] = [a for a in cfg["allowed_from"][login] if a != addr]
    save_cfg(cfg)
    return RedirectResponse(url=f"/?toast={quote('Saved (not applied). Click Apply Changes.')}&toastLevel=ok#senders", status_code=303)


@app.post("/from/default")
def set_default_from(request: Request, csrf_token: str = Form(""), login: str = Form(...), from_addr: str = Form(...)):
    # HTML fallback
    require_csrf(request, csrf_token)
    cfg = load_cfg()
    cfg.setdefault("default_from", {})
    from urllib.parse import quote

    login2 = _validate_login(login)
    addr2 = _validate_emailish(from_addr) if (from_addr or '').strip() else ''
    cfg["default_from"][login2] = addr2
    save_cfg(cfg)
    return RedirectResponse(url=f"/?toast={quote('Saved (not applied). Click Apply Changes.')}&toastLevel=ok#senders", status_code=303)


@app.get("/api/senders")
def api_senders_get():
    cfg = load_cfg()
    ms365_user = effective_ms365_user(cfg)

    current_hash = cfg_hash(cfg)
    applied_hash = get_applied_hash()
    pending = bool(applied_hash) and (current_hash != applied_hash)

    return {
        "ok": True,
        "pending": pending,
        "allowed_from": (cfg.get("allowed_from") or {}),
        "default_from": (cfg.get("default_from") or {}),
        "from_identities": from_identities(cfg, ms365_user),
    }


@app.post("/api/from/allow")
def api_from_allow(login: str = Form(...), from_addr: str = Form(...)):
    cfg = load_cfg()
    login = _validate_login(login)
    addrs = parse_addr_list(from_addr)
    cfg.setdefault("allowed_from", {})
    cfg["allowed_from"].setdefault(login, [])

    added = 0
    skipped = 0
    for addr in addrs:
        if not addr:
            continue
        if addr in cfg["allowed_from"][login]:
            skipped += 1
            continue
        cfg["allowed_from"][login].append(addr)
        added += 1

    save_cfg(cfg)

    current_hash = cfg_hash(cfg)
    applied_hash = get_applied_hash()
    pending = bool(applied_hash) and (current_hash != applied_hash)

    return {"ok": True, "pending": pending, "added": added, "skipped": skipped}


@app.post("/api/from/disallow")
def api_from_disallow(login: str = Form(...), from_addr: str = Form(...)):
    cfg = load_cfg()
    login = login.strip()
    addr = from_addr.strip().lower()

    if login in (cfg.get("allowed_from") or {}):
        cfg["allowed_from"][login] = [a for a in cfg["allowed_from"][login] if a != addr]
    save_cfg(cfg)

    current_hash = cfg_hash(cfg)
    applied_hash = get_applied_hash()
    pending = bool(applied_hash) and (current_hash != applied_hash)

    return {"ok": True, "pending": pending}


@app.post("/api/from/default")
def api_from_default(login: str = Form(...), from_addr: str = Form(...)):
    cfg = load_cfg()
    cfg.setdefault("default_from", {})
    login2 = _validate_login(login)
    addr2 = _validate_emailish(from_addr) if (from_addr or '').strip() else ''
    cfg["default_from"][login2] = addr2
    save_cfg(cfg)

    current_hash = cfg_hash(cfg)
    applied_hash = get_applied_hash()
    pending = bool(applied_hash) and (current_hash != applied_hash)

    return {"ok": True, "pending": pending}


@app.post("/postfix/reload")
def btn_reload(request: Request, csrf_token: str = Form("")):
    require_csrf(request, csrf_token)
    out = postfix_reload()
    return PlainTextResponse(out)


@app.post("/apply")
def apply_changes(request: Request, csrf_token: str = Form("")):
    # HTML fallback
    require_csrf(request, csrf_token)
    out = render_and_reload()

    # Mark current config as applied.
    cfg = load_cfg()
    set_applied_state(cfg)

    # Return to dashboard with a toast.
    from urllib.parse import quote

    msg = (out or "ok").strip() or "ok"
    if len(msg) > 600:
        msg = msg[:600] + "…"
    level = "error" if ("fatal" in msg.lower() or "error" in msg.lower()) else "ok"

    return RedirectResponse(url=f"/?toast={quote('Applied changes.')}&toastLevel={level}#status", status_code=303)


@app.post("/api/apply")
def api_apply_changes(validate_only: str = Form("0")):
    # validate_only=1: render to temp dir only; do not reload and do not mark applied.
    v = (validate_only or "0").strip().lower() in ("1", "true", "yes", "on")

    if v:
        out = render_validate_only()
        msg = (out or "ok").strip() or "ok"
        level = "error" if ("fatal" in msg.lower() or "error" in msg.lower() or "valueerror" in msg.lower()) else "ok"
        return {"ok": True, "output": msg, "level": level, "pending": True, "validated": True}

    out = render_and_reload()

    cfg = load_cfg()
    set_applied_state(cfg)

    msg = (out or "ok").strip() or "ok"
    level = "error" if ("fatal" in msg.lower() or "error" in msg.lower()) else "ok"

    return {"ok": True, "output": msg, "level": level, "pending": False, "validated": False}


@app.post("/api/discard")
def api_discard_changes():
    snap = read_applied_cfg_snapshot()
    if not snap:
        raise HTTPException(status_code=409, detail="No applied config snapshot found yet.")

    # Restore saved config to last applied snapshot.
    save_cfg(snap)
    set_applied_state(snap)

    return {"ok": True, "pending": False}


@app.post("/token/start")
def token_start(request: Request, csrf_token: str = Form("")):
    # HTML fallback
    require_csrf(request, csrf_token)
    start_device_flow_background()
    return RedirectResponse(url="/#oauth", status_code=303)


@app.post("/token/refresh")
def token_refresh(request: Request, csrf_token: str = Form("")):
    # HTML fallback
    require_csrf(request, csrf_token)
    from urllib.parse import quote

    out = refresh_token_now()
    msg = (out or "ok").strip()
    if len(msg) > 600:
        msg = msg[:600] + "…"
    level = "error" if "failed" in msg.lower() or "error" in msg.lower() else "ok"

    return RedirectResponse(url=f"/?toast={quote('Token refresh executed.')}&toastLevel={level}#oauth", status_code=303)


@app.post("/api/token/start")
def api_token_start():
    start_device_flow_background()
    return {"ok": True}


@app.post("/api/token/refresh")
def api_token_refresh():
    out = refresh_token_now()

    # recompute expiry after refresh via postfix control (UI container can't read token file)
    token_exp_ts = None
    try:
        token_exp_ts = (_control_get("/token/status") or {}).get("token_exp_ts")
    except Exception:
        token_exp_ts = None

    return {"ok": True, "output": out, "token_exp_ts": token_exp_ts}


@app.post("/backup/export.zip")
def backup_export_zip(request: Request, csrf_token: str = Form("")):
    require_csrf(request, csrf_token)
    j = _control_get("/backup/export")
    if not j.get("ok"):
        raise HTTPException(status_code=500, detail=j.get("error") or "export_failed")
    zip_b64 = (j.get("zip_b64") or "").strip()
    if not zip_b64:
        raise HTTPException(status_code=500, detail="missing payload")
    blob = b64d(zip_b64)
    return Response(
        content=blob,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="simple-m365-relay-backup.zip"'},
    )


@app.post("/backup/import")
def backup_import(request: Request, csrf_token: str = Form(""), file: UploadFile = File(...)):
    require_csrf(request, csrf_token)
    raw = file.file.read() if file and file.file else b""
    if not raw:
        raise HTTPException(status_code=400, detail="empty upload")

    # Hard limits to reduce DoS risk from crafted ZIPs.
    MAX_ZIP_BYTES = 10 * 1024 * 1024  # 10 MiB
    MAX_ENTRIES = 25
    MAX_META_BYTES = 256 * 1024
    MAX_CONFIG_BYTES = 1 * 1024 * 1024
    MAX_USERS_BYTES = 5 * 1024 * 1024
    ALLOWED = {
        "meta.json": MAX_META_BYTES,
        "config/config.json": MAX_CONFIG_BYTES,
        "sasl/users": MAX_USERS_BYTES,
        "sasl/sasldb2": MAX_USERS_BYTES,
    }

    if len(raw) > MAX_ZIP_BYTES:
        raise HTTPException(status_code=400, detail="Invalid backup bundle: too large")

    # Validate config.json in bundle if present (avoid importing invalid config).
    import io
    import json as _json
    import zipfile

    try:
        with zipfile.ZipFile(io.BytesIO(raw), mode="r") as z:
            infos = z.infolist()
            if len(infos) > MAX_ENTRIES:
                raise ValueError(f"too many entries ({len(infos)} > {MAX_ENTRIES})")

            for zi in infos:
                name = zi.filename
                if name.endswith("/"):
                    continue
                if name not in ALLOWED:
                    continue
                if zi.file_size > int(ALLOWED[name]):
                    raise ValueError(f"member too large: {name}")

            if "config/config.json" in z.namelist():
                cfg_obj = _json.loads(z.read("config/config.json").decode("utf-8"))
                validate_cfg_obj(cfg_obj)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid backup bundle: {e}")

    res = _control_post_json("/backup/import", {"zip_b64": b64e(raw)})
    if not res.get("ok"):
        raise HTTPException(status_code=400, detail=res.get("error") or "import_failed")

    # After import, force pending until the admin explicitly applies.
    # Reason: if the imported config happens to match the last applied hash (or if hashes are missing),
    # the UI would not show the Apply reminder. Import should always be treated as "saved, not applied".
    try:
        # Keep discard functionality safe: after an import, treat the last-applied snapshot as unknown.
        set_applied_hash("import_pending")
    except Exception:
        pass

    from urllib.parse import quote

    # If the imported bundle doesn't include the core onboarding fields yet,
    # the onboarding gate would immediately redirect / -> /onboarding, making it look
    # like "nothing happened". Route users to the appropriate page explicitly.
    target = "/" if onboarding_complete(load_cfg()) else "/onboarding"

    return RedirectResponse(
        url=f"{target}?toast={quote('Backup imported. Review settings and click Apply Changes.')}&toastLevel=ok#settings",
        status_code=303,
        headers={},
    )


def _parse_device_flow_log(log: str) -> dict:
    import re

    txt = (log or "")

    # URL
    url = None
    m = re.search(r"https?://\S*devicelogin\S*", txt, re.IGNORECASE)
    if m:
        url = m.group(0).rstrip(').,;')
    else:
        m2 = re.search(r"microsoft\.com/devicelogin", txt, re.IGNORECASE)
        if m2:
            url = "https://microsoft.com/devicelogin"

    # Code (best effort)
    # Notes:
    # - Microsoft device codes can be hyphenated (ABCD-EFGH) or plain (H1TY9Q3YK).
    # - Some clients print lowercase codes; normalize to uppercase.
    code = None

    m = re.search(r"\b([A-Z0-9]{4,}-[A-Z0-9]{4,})\b", txt, re.IGNORECASE)
    if m:
        code = m.group(1)
    else:
        # common phrasing: "enter the code ABCDEF..." or "use code ABCDEF..."
        m2 = re.search(r"(?:enter|use)\s+(?:the\s+)?code\s+([A-Z0-9]{6,})\b", txt, re.IGNORECASE)
        if m2:
            code = m2.group(1)
        else:
            m3 = re.search(r"\bcode(?:\s+is)?\s*[: ]\s*([A-Z0-9]{6,})\b", txt, re.IGNORECASE)
            if m3:
                code = m3.group(1)

    if code:
        code = str(code).strip().upper()

    # Exit code
    exit_code = None
    m = re.search(r"\[exit\s+(\d+)\]", txt)
    if m:
        try:
            exit_code = int(m.group(1))
        except Exception:
            exit_code = None

    done = exit_code is not None
    ok = (exit_code == 0) if done else False

    # Error hint
    err = None
    if done and exit_code != 0:
        # pick a helpful last non-empty line
        lines = [ln.strip() for ln in txt.splitlines() if ln.strip()]
        if lines:
            err = lines[-1][:200]

    return {
        "url": url,
        "code": code,
        "done": done,
        "ok": ok,
        "exit": exit_code,
        "error": err,
    }


@app.get("/api/device-flow-log")
def api_device_flow_log():
    log = get_device_flow_log()
    return {"log": log, **_parse_device_flow_log(log)}


@app.get("/api/token-refresh-log")
def api_token_refresh_log():
    return {"log": get_token_refresh_log()}


@app.post("/testmail")
def testmail(
    request: Request,
    csrf_token: str = Form(""),
    to_addr: str = Form(...),
    from_addr: str = Form(""),
    subject: str = Form("Test"),
    body: str = Form("Does it work?"),
):
    # HTML fallback
    require_csrf(request, csrf_token)
    from urllib.parse import quote

    _ensure_applied_best_effort()
    out = send_test_mail(to_addr, from_addr, subject, body)

    msg = (out or "queued").strip()
    if len(msg) > 600:
        msg = msg[:600] + "…"

    level = "error" if "exit" in msg.lower() else "ok"

    return RedirectResponse(url=f"/?toast={quote(msg)}&toastLevel={level}#testmail", status_code=303)


def _ensure_applied_best_effort() -> str:
    """Best-effort: ensure Postfix has current config rendered + reloaded.

    Users can run the onboarding test-mail step before hitting Finish.
    If config changes (e.g. ms365_smtp_user) haven't been applied yet,
    Postfix may miss generated lmdb maps (e.g. sasl_passwd.lmdb) until a restart.

    Returns a short status string ("ok" or output from render/reload).
    """
    try:
        cfg = load_cfg()
        current_hash = cfg_hash(cfg)
        applied_hash = get_applied_hash()
        pending = (applied_hash is None) or (current_hash != applied_hash)
        if pending:
            out = render_and_reload()
            # Mark the saved config as applied (+ snapshot for discard)
            set_applied_state(cfg)
            return (out or "ok").strip() or "ok"
    except Exception as e:
        return f"apply_error:{type(e).__name__}"
    return "ok"


@app.post("/api/testmail")
def api_testmail(
    to_addr: str = Form(...),
    from_addr: str = Form(""),
    subject: str = Form("Test"),
    body: str = Form("Does it work?"),
    verify: str = Form("1"),
):
    apply_out = _ensure_applied_best_effort()
    out = send_test_mail(to_addr, from_addr, subject, body)

    msg = (out or "").strip()

    ok = True
    if not msg:
        msg = "queued"

    if ("sendmail exit" in msg.lower()) or ("error" in msg.lower()) or ("apply_error" in apply_out.lower()):
        ok = False

    qid = extract_queue_id_best_effort(msg)

    do_verify = str(verify or "").strip().lower() not in ("0", "false", "no", "off")
    delivery = None
    if ok and do_verify and qid:
        delivery = verify_delivery_best_effort(qid, max_wait_seconds=8)

    # Determine toast severity
    level = "ok"
    if not ok:
        level = "error"
    elif delivery and delivery.get("state") in ("deferred", "bounced", "rejected"):
        level = "error"

    note = "OK means queued/accepted locally; check Mail Log / queue for delivery."
    if delivery and delivery.get("state") == "sent":
        note = "Verified: message was sent upstream (status=sent in mail log)."

    return {
        "ok": ok,
        "output": msg,
        "level": level,
        "apply": apply_out,
        "queue_id": qid,
        "delivery": delivery,
        "note": note,
    }


def _semver_tuple(v: str) -> Optional[tuple]:
    """Parse x.y.z from a string (tolerates leading v and suffixes like -rc.1)."""
    s = str(v or "").strip()
    if s.startswith("v"):
        s = s[1:]
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", s)
    if not m:
        return None
    try:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except Exception:
        return None


def _read_update_cache() -> Optional[dict]:
    try:
        if UPDATE_CACHE_PATH.exists():
            return json.loads(UPDATE_CACHE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None
    return None


def _write_update_cache(obj: dict) -> None:
    try:
        UPDATE_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        UPDATE_CACHE_PATH.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(UPDATE_CACHE_PATH, 0o600)
    except Exception:
        pass


def _fetch_latest_stable_release() -> dict:
    """Fetch GitHub latest stable release info.

    Uses the public API endpoint that excludes prereleases.
    """
    import urllib.request

    url = f"https://api.github.com/repos/{APP_GITHUB_REPO}/releases/latest"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "simple-m365-relay-ui")
    with urllib.request.urlopen(req, timeout=6) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    return json.loads(raw)


def get_update_status() -> dict:
    """Return update status (any newer STABLE release; ignore RC/prerelease).

    Cached on disk so the UI can poll without hitting GitHub frequently.
    """
    now = int(time.time())
    cached = _read_update_cache() or {}
    checked_at = int(cached.get("checked_at") or 0)

    if checked_at and (now - checked_at) < max(60, UPDATE_CHECK_TTL_SECONDS):
        cached.setdefault("ok", True)
        cached.setdefault("policy", "stable")
        cached.setdefault("current_version", APP_VERSION)
        cached.setdefault("repo_url", APP_GITHUB_REPO_URL)
        return cached

    cur = _semver_tuple(APP_VERSION)

    out = {
        "ok": True,
        "policy": "stable",
        "checked_at": now,
        "current_version": APP_VERSION,
        "current_semver": cur,
        "repo_url": APP_GITHUB_REPO_URL,
        "update_available": False,
        "latest_version": None,
        "latest_semver": None,
        "url": APP_GITHUB_REPO_URL + "/releases/latest",
    }

    try:
        rel = _fetch_latest_stable_release() or {}
        tag = str(rel.get("tag_name") or "").strip()
        html_url = str(rel.get("html_url") or "").strip()
        latest = _semver_tuple(tag)

        out["latest_version"] = tag
        out["latest_semver"] = latest
        if html_url:
            out["url"] = html_url

        if cur and latest and latest > cur:
            out["update_available"] = True
    except Exception as e:
        out["ok"] = False
        out["error"] = f"{type(e).__name__}"

    _write_update_cache(out)
    return out


@app.get("/api/update")
def api_update():
    return get_update_status()


@app.get("/api/status")
def api_status():
    """Return best-effort status as JSON.

    This endpoint is polled by the UI. It must never crash into an HTML 500 page,
    otherwise frontend code can misinterpret it as an auth/session problem.
    """

    def _safe_control(path: str) -> dict:
        try:
            return _control_get(path) or {}
        except Exception as e:
            return {"_error": f"control_api_error:{path}:{type(e).__name__}"}

    cfg = load_cfg()

    mailq_resp = _safe_control("/mailq")
    mailq_out = str(mailq_resp.get("mailq") or "")
    qsize = parse_queue_size(mailq_out)

    maillog_resp = _safe_control("/maillog")
    mail_log = _redact_mail_log(str(maillog_resp.get("maillog") or ""))

    refresh_resp = _safe_control("/token/refresh-log")
    token_refresh_log = str(refresh_resp.get("log") or "")

    ms365_user = effective_ms365_user(cfg)
    env_ms365_user = (os.environ.get("MS365_SMTP_USER") or "").strip()
    cfg_ms365_user = str((cfg or {}).get("ms365_smtp_user") or "").strip()

    token_status = _safe_control("/token/status")
    token_exp_ts = (token_status or {}).get("token_exp_ts")

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
        "token_refresh_log": token_refresh_log,
        "from_identities": from_identities(cfg, ms365_user),
        "env": {
            # effective value (env-first fallback)
            "MS365_SMTP_USER": ms365_user,
            # for debugging/UX: show both sources
            "ENV_MS365_SMTP_USER": env_ms365_user,
            "CFG_MS365_SMTP_USER": cfg_ms365_user,
            "RELAYHOST": cfg.get("relayhost") or os.environ.get("RELAYHOST", "[smtp.office365.com]:587"),
            "AUTO_TOKEN_REFRESH_MINUTES": str((cfg.get("oauth") or {}).get("auto_refresh_minutes", "")),
        },
        "errors": {
            "control_mailq": mailq_resp.get("_error"),
            "control_maillog": maillog_resp.get("_error"),
            "control_token_status": token_status.get("_error") if isinstance(token_status, dict) else None,
            "control_token_refresh_log": refresh_resp.get("_error") if isinstance(refresh_resp, dict) else None,
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


@app.get("/healthz")
@app.head("/healthz")
@app.options("/healthz")
def healthz():
    return PlainTextResponse("ok")


@app.get("/favicon.ico")
def favicon_ico():
    # Browsers often request /favicon.ico by default; we serve the SVG.
    return RedirectResponse(url="/static/favicon.svg", status_code=307)


@app.get("/diagnostics.txt")
def diagnostics_txt():
    # No secrets: we do NOT include token files, and we redact token-like content from logs.
    cfg = load_cfg()

    # Best-effort: diagnostics should still render even if the postfix control API isn't reachable yet.
    try:
        mailq_out = (_control_get("/mailq").get("mailq") or "")
    except Exception:
        mailq_out = ""

    try:
        mail_log_raw = (_control_get("/maillog").get("maillog") or "")
    except Exception:
        mail_log_raw = ""
    mail_log = _redact_mail_log(mail_log_raw)

    ms365_user = effective_ms365_user(cfg)
    token_exp_ts = None
    try:
        token_exp_ts = (_control_get("/token/status") or {}).get("token_exp_ts")
    except Exception:
        token_exp_ts = None

    parts = []
    parts.append("# Simple M365 Relay diagnostics\n")
    parts.append(f"timestamp: {time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime())}\n")
    parts.append("\n## env\n")
    parts.append(f"RELAYHOST={os.environ.get('RELAYHOST','')}\n")
    parts.append(f"MS365_SMTP_USER={ms365_user}\n")
    parts.append(f"CFG_MS365_SMTP_USER={str((cfg or {}).get('ms365_smtp_user') or '')}\n")
    parts.append(f"token_expiry_ts={token_exp_ts or ''}\n")

    parts.append("\n## config.json\n")
    parts.append(json.dumps(cfg, indent=2, sort_keys=True) + "\n")

    parts.append("\n## mailq\n")
    parts.append(mailq_out.strip() + "\n")

    parts.append("\n## maillog (tail)\n")
    parts.append(mail_log.strip() + "\n")

    return PlainTextResponse("".join(parts))
