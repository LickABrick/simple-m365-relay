#!/usr/bin/env python3
import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import socketserver
from pathlib import Path

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
CFG_JSON = DATA_DIR / "config" / "config.json"
DEVICE_FLOW_LOG = DATA_DIR / "state" / "device_flow.log"
TOKEN_REFRESH_LOG = DATA_DIR / "state" / "token_refresh.log"

TEST_CONFIG = os.environ.get("SASL_XOAUTH2_TEST_CONFIG", "/usr/lib/x86_64-linux-gnu/sasl-xoauth2/test-config")
SASL_XOAUTH2_CONFIG = os.environ.get("SASL_XOAUTH2_CONFIG", "/etc/sasl-xoauth2.conf")


def load_cfg() -> dict:
    try:
        if CFG_JSON.exists():
            return json.loads(CFG_JSON.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def get_auto_refresh_minutes() -> int:
    # prefer config.json; fallback to env
    cfg = load_cfg()
    try:
        v = (cfg.get("oauth") or {}).get("auto_refresh_minutes", None)
        if v is not None:
            return max(0, int(v))
    except Exception:
        pass
    try:
        return max(0, int(os.environ.get("AUTO_TOKEN_REFRESH_MINUTES", "0") or "0"))
    except Exception:
        return 0

BIND = os.environ.get("CONTROL_BIND", "0.0.0.0")
PORT = int(os.environ.get("CONTROL_PORT", "18080"))
SOCKET_PATH = os.environ.get("CONTROL_SOCKET", "")
CONTROL_TOKEN_ENV = os.environ.get("CONTROL_TOKEN", "")
CONTROL_TOKEN_FILE = DATA_DIR / "state" / "control.token"

_device_lock = threading.Lock()
_device_running = False


def _get_control_token() -> str:
    """Return the shared control token.

    Priority:
      1) CONTROL_TOKEN env
      2) /data/state/control.token (generated once if missing)

    This token is used by the UI container to authenticate to this control API.
    """
    if CONTROL_TOKEN_ENV:
        return CONTROL_TOKEN_ENV

    try:
        if CONTROL_TOKEN_FILE.exists():
            v = (CONTROL_TOKEN_FILE.read_text(encoding="utf-8", errors="ignore") or "").strip()
            if v:
                return v
    except Exception:
        pass

    # generate and persist a token
    import secrets

    tok = secrets.token_urlsafe(32)
    try:
        CONTROL_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        # best effort: avoid changing existing token
        if not CONTROL_TOKEN_FILE.exists():
            CONTROL_TOKEN_FILE.write_text(tok + "\n", encoding="utf-8")
        else:
            v = (CONTROL_TOKEN_FILE.read_text(encoding="utf-8", errors="ignore") or "").strip()
            if v:
                return v
            CONTROL_TOKEN_FILE.write_text(tok + "\n", encoding="utf-8")
    except Exception:
        pass
    return tok


def _timing_safe_eq(a: str, b: str) -> bool:
    try:
        import hmac

        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
    except Exception:
        return a == b


def _safe_token_filename(user: str) -> str:
    import re

    u = (user or "").strip()
    if not u:
        return ""
    u2 = re.sub(r"[^A-Za-z0-9_.@+\-]", "_", u)
    while ".." in u2:
        u2 = u2.replace("..", "__")
    u2 = u2.strip("._-")
    return u2[:128]


def _token_path_for_user(user: str) -> str:
    safe = _safe_token_filename(user)
    if not safe:
        return str(DATA_DIR / "tokens" / "token")
    return str(DATA_DIR / "tokens" / safe)


def _redact_sensitive(text: str) -> str:
    import re

    t = text or ""
    # redact jwt-ish tokens
    t = re.sub(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "[REDACTED_JWT]", t)
    # redact common fields
    t = re.sub(r"(?i)(refresh_token|access_token|id_token|authorization)\s*[:=]\s*[^\s\"']+", r"\1=[REDACTED]", t)
    # NOTE: do NOT redact device codes here. The UI needs the device code to complete sign-in.
    # Device codes are short-lived and only shown to authenticated admins.
    return t


def sh(cmd, check=False):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=check).stdout


def tail(path: Path, n: int = 200) -> str:
    if not path.exists():
        return ""
    try:
        return sh(["tail", "-n", str(n), str(path)], check=False)
    except Exception:
        return path.read_text(encoding="utf-8", errors="ignore")[-8000:]


def render_and_reload() -> str:
    cert = os.environ.get("RELAY_TLS_CERT_PATH", "/data/certs/tls.crt")
    key = os.environ.get("RELAY_TLS_KEY_PATH", "/data/certs/tls.key")
    out = sh([
        "python3",
        "/opt/ms365-relay/postfix/render.py",
        "--config",
        str(CFG_JSON),
        "--outdir",
        "/etc/postfix",
        "--token-dir",
        str(DATA_DIR / "tokens"),
        "--tls-cert",
        cert,
        "--tls-key",
        key,
    ])
    out2 = sh(["postfix", "reload"], check=False)
    return (out + "\n" + out2).strip()


def send_test_mail(to_addr: str, from_addr: str, subject: str, body: str) -> str:
    # Basic header-injection guard
    for v in (to_addr, from_addr, subject):
        if "\n" in v or "\r" in v:
            raise ValueError("invalid header value")

    msg = (
        f"From: {from_addr}\n"
        f"To: {to_addr}\n"
        f"Subject: {subject}\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=UTF-8\n"
        "\n"
        f"{body}\n"
    )

    p = subprocess.run(
        ["/usr/sbin/sendmail", "-t", "-f", from_addr],
        input=msg,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    out = (p.stdout or "").strip()
    if p.returncode != 0:
        return f"sendmail exit {p.returncode}\n" + out
    return out or "ok"


def _append_log(path: Path, text: str, max_bytes: int = 200_000) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.exists() and path.stat().st_size > max_bytes:
            # truncate older content
            tail_txt = tail(path, 400)
            path.write_text(tail_txt + "\n[truncated]\n", encoding="utf-8")
        with open(path, "a", encoding="utf-8") as f:
            f.write(text)
            if not text.endswith("\n"):
                f.write("\n")
    except Exception:
        pass


def _jwt_exp_best_effort(jwt: str):
    try:
        parts = (jwt or "").split(".")
        if len(parts) < 2:
            return None
        import base64

        payload = parts[1]
        payload += "=" * (-len(payload) % 4)
        raw = base64.urlsafe_b64decode(payload.encode("utf-8"))
        obj = json.loads(raw.decode("utf-8", errors="ignore"))
        exp = obj.get("exp")
        if exp is None:
            return None
        return int(exp)
    except Exception:
        return None


def token_status() -> dict:
    user = (os.environ.get("MS365_SMTP_USER") or "").strip()
    if not user:
        return {"ok": False, "error": "MS365_SMTP_USER_not_set"}
    p = _token_path_for_user(user)
    try:
        txt = Path(p).read_text(encoding="utf-8")
        data = json.loads(txt)
    except Exception as e:
        # we only return mtime as a last resort
        try:
            st = os.stat(p)
            return {"ok": True, "token_exp_ts": int(st.st_mtime), "warning": "fallback_mtime"}
        except Exception:
            return {"ok": False, "error": f"cannot_read_token: {type(e).__name__}"}

    # common field
    exp = None
    try:
        exp0 = int(str(data.get("expiry", "") or 0))
        if exp0 > 0:
            exp = exp0
    except Exception:
        pass

    if not exp:
        jwt_exp = _jwt_exp_best_effort((data or {}).get("access_token", ""))
        if jwt_exp:
            exp = jwt_exp

    if not exp:
        # nested fields
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
                    exp = ts
                    break
            except Exception:
                pass

    return {"ok": True, "token_exp_ts": exp}


def refresh_token() -> str:
    user = os.environ.get("MS365_SMTP_USER", "")
    if not user:
        return "Missing MS365_SMTP_USER"
    tok_path = _token_path_for_user(user)
    if not Path(tok_path).exists():
        return f"Token file not found: {tok_path}"

    if not Path(TEST_CONFIG).exists():
        return f"test-config not found: {TEST_CONFIG}"

    cmd = [
        TEST_CONFIG,
        "--config",
        SASL_XOAUTH2_CONFIG,
        "--token",
        tok_path,
    ]
    out = sh(cmd, check=False).strip()
    # store a short log record
    import time as _time

    _append_log(TOKEN_REFRESH_LOG, f"[{_time.strftime('%Y-%m-%d %H:%M:%S')}] refresh_token\n{_redact_sensitive(out)}\n")
    return out or "ok"


def _ensure_sasldb_ok() -> None:
    """If /data/sasl/sasldb2 exists but is not a readable Berkeley DB for this image,
    move it aside so saslpasswd2 can recreate it."""
    db = DATA_DIR / "sasl" / "sasldb2"
    if not db.exists():
        return
    try:
        # If it's not a regular file, quarantine it.
        if not db.is_file():
            raise RuntimeError("not a file")
        # If Cyrus can't read it, it's likely a format mismatch.
        out = sh(["sasldblistusers2", "-f", str(db)], check=False)
        if "unexpected file type" in out.lower() or "listusers failed" in out.lower() or "invalid" in out.lower():
            raise RuntimeError(out.strip()[:200])
    except Exception:
        import time as _time

        ts = int(_time.time())
        try:
            db.rename(db.with_name(f"sasldb2.bad.{ts}"))
        except Exception:
            try:
                db.unlink(missing_ok=True)
            except Exception:
                pass


def start_device_flow_background() -> None:
    global _device_running
    with _device_lock:
        if _device_running:
            return
        _device_running = True

    DEVICE_FLOW_LOG.parent.mkdir(parents=True, exist_ok=True)
    DEVICE_FLOW_LOG.write_text("", encoding="utf-8")

    def run():
        global _device_running
        try:
            cfg = load_cfg()
            tenant = (cfg.get("oauth") or {}).get("tenant_id") or os.environ.get("MS365_TENANT_ID", "")
            client_id = (cfg.get("oauth") or {}).get("client_id") or os.environ.get("MS365_CLIENT_ID", "")
            user = os.environ.get("MS365_SMTP_USER", "")
            if not (tenant and client_id and user):
                DEVICE_FLOW_LOG.write_text("Missing tenant_id/client_id (OAuth settings) or MS365_SMTP_USER\n", encoding="utf-8")
                return
            tok_path = _token_path_for_user(user)
            Path(tok_path).parent.mkdir(parents=True, exist_ok=True)

            cmd = [
                "sasl-xoauth2-tool",
                "get-token",
                "outlook",
                tok_path,
                f"--client-id={client_id}",
                "--use-device-flow",
                f"--tenant={tenant}",
            ]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            with open(DEVICE_FLOW_LOG, "a", encoding="utf-8") as f:
                for line in proc.stdout or []:
                    f.write(_redact_sensitive(line))
                    f.flush()
            proc.wait()
            with open(DEVICE_FLOW_LOG, "a", encoding="utf-8") as f:
                f.write(f"\n[exit {proc.returncode}]\n")
        finally:
            with _device_lock:
                _device_running = False

    threading.Thread(target=run, daemon=True).start()


class H(BaseHTTPRequestHandler):
    # When served over a unix socket, BaseHTTPRequestHandler's default
    # logging tries to index client_address[0], which breaks.
    def address_string(self) -> str:  # pragma: no cover
        try:
            ca = getattr(self, "client_address", None)
            if isinstance(ca, (tuple, list)) and ca:
                return str(ca[0])
        except Exception:
            pass
        return "local"

    def _require_auth(self) -> bool:
        # /health is intentionally unauthenticated for basic liveness checks.
        if self.path == "/health":
            return True

        tok = _get_control_token()
        hdr = (self.headers.get("X-Control-Token") or "").strip()
        if not tok:
            # Should never happen, but fail closed.
            self._json(503, {"error": "control_token_unavailable"})
            return False
        if not hdr or not _timing_safe_eq(hdr, tok):
            self._json(403, {"error": "forbidden"})
            return False
        return True

    def _json(self, code, obj):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self):
        try:
            ln = int(self.headers.get("Content-Length", "0"))
        except Exception:
            ln = 0
        if ln <= 0:
            return {}
        raw = self.rfile.read(ln)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def do_GET(self):
        if self.path == "/health":
            return self._json(200, {"ok": True})
        if not self._require_auth():
            return
        if self.path == "/mailq":
            out = sh(["mailq"], check=False)
            return self._json(200, {"mailq": out})
        if self.path == "/maillog":
            out = tail(DATA_DIR / "log" / "maillog", 200)
            return self._json(200, {"maillog": out})
        if self.path == "/device-flow-log":
            return self._json(200, {"log": _redact_sensitive(tail(DEVICE_FLOW_LOG, 200))})
        if self.path == "/token/status":
            return self._json(200, token_status())
        if self.path == "/token/refresh-log":
            return self._json(200, {"log": _redact_sensitive(tail(TOKEN_REFRESH_LOG, 200))})
        if self.path == "/users":
            db = DATA_DIR / "sasl" / "sasldb2"
            if not db.exists():
                return self._json(200, {"users": ""})
            out = sh(["sasldblistusers2", "-f", str(db)], check=False)
            return self._json(200, {"users": out})
        self._json(404, {"error": "not_found"})

    def do_POST(self):
        if not self._require_auth():
            return
        if self.path == "/render-reload":
            out = render_and_reload()
            return self._json(200, {"output": out})
        if self.path == "/reload":
            out = sh(["postfix", "reload"], check=False)
            return self._json(200, {"output": out})
        if self.path == "/token/start":
            start_device_flow_background()
            return self._json(200, {"ok": True})
        if self.path == "/token/refresh":
            out = refresh_token()
            return self._json(200, {"output": out})
        if self.path == "/users/add":
            body = self._read_json()
            login = (body.get("login") or "").strip()
            pw = body.get("password") or ""
            realm = os.environ.get("RELAY_DOMAIN", "local")
            if not login or not pw:
                return self._json(400, {"error": "missing login/password"})

            _ensure_sasldb_ok()

            p = subprocess.run(
                ["saslpasswd2", "-p", "-c", "-u", realm, "-f", str(DATA_DIR / "sasl" / "sasldb2"), login],
                input=pw + "\n",
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            out = (p.stdout or "").strip()
            if p.returncode != 0:
                return self._json(400, {"error": out or f"saslpasswd2 exit {p.returncode}"})
            return self._json(200, {"output": out or "ok"})
        if self.path == "/users/delete":
            body = self._read_json()
            login = (body.get("login") or "").strip()
            realm = os.environ.get("RELAY_DOMAIN", "local")
            if not login:
                return self._json(400, {"error": "missing login"})

            _ensure_sasldb_ok()

            out = sh(["saslpasswd2", "-d", "-u", realm, "-f", str(DATA_DIR / "sasl" / "sasldb2"), login], check=False).strip()
            return self._json(200, {"output": out or "ok"})
        if self.path == "/testmail":
            body = self._read_json()
            to_addr = (body.get("to_addr") or "").strip()
            from_addr = (body.get("from_addr") or "").strip()
            subject = (body.get("subject") or "Test message").strip()
            mail_body = body.get("body") or "Does it work?"
            if not to_addr or not from_addr:
                return self._json(400, {"error": "missing to_addr/from_addr"})
            try:
                out = send_test_mail(to_addr, from_addr, subject, mail_body)
            except Exception as e:
                return self._json(400, {"error": str(e)})
            return self._json(200, {"output": out})
        self._json(404, {"error": "not_found"})


def _auto_refresh_loop():
    import time as _time

    last_run = 0
    while True:
        mins = get_auto_refresh_minutes()
        if mins <= 0:
            _time.sleep(5)
            continue

        # run at most once per interval
        now = _time.time()
        if now - last_run >= mins * 60:
            try:
                refresh_token()
            except Exception as e:
                _append_log(TOKEN_REFRESH_LOG, f"[{_time.strftime('%Y-%m-%d %H:%M:%S')}] auto-refresh error: {e}\n")
            last_run = now

        _time.sleep(5)


class _UnixHTTPServer(socketserver.UnixStreamServer, HTTPServer):
    # allow immediate restart
    allow_reuse_address = True


def main():
    # always start loop; it self-disables when interval <= 0
    threading.Thread(target=_auto_refresh_loop, daemon=True).start()

    if SOCKET_PATH:
        sock = Path(SOCKET_PATH)
        try:
            if sock.exists():
                sock.unlink()
        except Exception:
            pass
        sock.parent.mkdir(parents=True, exist_ok=True)
        httpd = _UnixHTTPServer(str(sock), H)
        # Make the socket usable by the non-root UI container (uid/gid 10001).
        try:
            import os as _os

            ui_uid = int(_os.environ.get("UI_UID", "10001"))
            ui_gid = int(_os.environ.get("UI_GID", "10001"))
            _os.chown(str(sock), ui_uid, ui_gid)
            _os.chmod(str(sock), 0o660)
        except Exception:
            try:
                import os as _os

                _os.chmod(str(sock), 0o666)
            except Exception:
                pass
    else:
        httpd = HTTPServer((BIND, PORT), H)

    httpd.serve_forever()


if __name__ == "__main__":
    main()
