#!/usr/bin/env python3
import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
CFG_JSON = DATA_DIR / "config" / "config.json"
DEVICE_FLOW_LOG = DATA_DIR / "state" / "device_flow.log"
TOKEN_REFRESH_LOG = DATA_DIR / "state" / "token_refresh.log"

AUTO_REFRESH_MIN = int(os.environ.get("AUTO_TOKEN_REFRESH_MINUTES", "0") or "0")
TEST_CONFIG = os.environ.get("SASL_XOAUTH2_TEST_CONFIG", "/usr/lib/x86_64-linux-gnu/sasl-xoauth2/test-config")
SASL_XOAUTH2_CONFIG = os.environ.get("SASL_XOAUTH2_CONFIG", "/etc/sasl-xoauth2.conf")

BIND = os.environ.get("CONTROL_BIND", "0.0.0.0")
PORT = int(os.environ.get("CONTROL_PORT", "18080"))

_device_lock = threading.Lock()
_device_running = False


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


def refresh_token() -> str:
    user = os.environ.get("MS365_SMTP_USER", "")
    if not user:
        return "Missing MS365_SMTP_USER"
    tok_path = str(DATA_DIR / "tokens" / user)
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

    _append_log(TOKEN_REFRESH_LOG, f"[{_time.strftime('%Y-%m-%d %H:%M:%S')}] refresh_token\n{out}\n")
    return out or "ok"


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
            tenant = os.environ.get("MS365_TENANT_ID", "")
            client_id = os.environ.get("MS365_CLIENT_ID", "")
            user = os.environ.get("MS365_SMTP_USER", "")
            if not (tenant and client_id and user):
                DEVICE_FLOW_LOG.write_text("Missing MS365_TENANT_ID, MS365_CLIENT_ID or MS365_SMTP_USER\n", encoding="utf-8")
                return
            tok_path = str(DATA_DIR / "tokens" / user)
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
                    f.write(line)
                    f.flush()
            proc.wait()
            with open(DEVICE_FLOW_LOG, "a", encoding="utf-8") as f:
                f.write(f"\n[exit {proc.returncode}]\n")
        finally:
            with _device_lock:
                _device_running = False

    threading.Thread(target=run, daemon=True).start()


class H(BaseHTTPRequestHandler):
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
        if self.path == "/mailq":
            out = sh(["mailq"], check=False)
            return self._json(200, {"mailq": out})
        if self.path == "/maillog":
            out = tail(DATA_DIR / "log" / "maillog", 200)
            return self._json(200, {"maillog": out})
        if self.path == "/device-flow-log":
            return self._json(200, {"log": tail(DEVICE_FLOW_LOG, 200)})
        if self.path == "/token/refresh-log":
            return self._json(200, {"log": tail(TOKEN_REFRESH_LOG, 200)})
        if self.path == "/users":
            db = DATA_DIR / "sasl" / "sasldb2"
            if not db.exists():
                return self._json(200, {"users": ""})
            out = sh(["sasldblistusers2", "-f", str(db)], check=False)
            return self._json(200, {"users": out})
        self._json(404, {"error": "not_found"})

    def do_POST(self):
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
            p = subprocess.run(
                ["saslpasswd2", "-p", "-c", "-u", realm, "-f", str(DATA_DIR / "sasl" / "sasldb2"), login],
                input=pw + "\n",
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            return self._json(200, {"output": p.stdout.strip() or "ok"})
        if self.path == "/users/delete":
            body = self._read_json()
            login = (body.get("login") or "").strip()
            realm = os.environ.get("RELAY_DOMAIN", "local")
            if not login:
                return self._json(400, {"error": "missing login"})
            out = sh(["saslpasswd2", "-d", "-u", realm, "-f", str(DATA_DIR / "sasl" / "sasldb2"), login], check=False)
            return self._json(200, {"output": out.strip() or "ok"})
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
    if AUTO_REFRESH_MIN <= 0:
        return
    import time as _time

    while True:
        try:
            # refresh token in the background
            refresh_token()
        except Exception as e:
            _append_log(TOKEN_REFRESH_LOG, f"[{_time.strftime('%Y-%m-%d %H:%M:%S')}] auto-refresh error: {e}\n")
        _time.sleep(max(60, AUTO_REFRESH_MIN * 60))


def main():
    if AUTO_REFRESH_MIN > 0:
        threading.Thread(target=_auto_refresh_loop, daemon=True).start()
    httpd = HTTPServer((BIND, PORT), H)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
