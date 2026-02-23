from __future__ import annotations

import json
import re
import time
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar


class HttpClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return self.base_url + path

    def get(self, path: str, headers: dict | None = None) -> tuple[int, dict, bytes]:
        req = urllib.request.Request(self._url(path), method="GET", headers=headers or {})
        with self.opener.open(req, timeout=10) as resp:
            return resp.status, dict(resp.headers), resp.read()

    def post_form(self, path: str, fields: dict, headers: dict | None = None) -> tuple[int, dict, bytes]:
        data = urllib.parse.urlencode(fields).encode("utf-8")
        hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(self._url(path), method="POST", data=data, headers=hdrs)
        with self.opener.open(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read()

    def post_empty(self, path: str, headers: dict | None = None) -> tuple[int, dict, bytes]:
        req = urllib.request.Request(self._url(path), method="POST", data=b"", headers=headers or {})
        with self.opener.open(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read()


def parse_meta_csrf(html: str) -> str:
    # <meta name="csrf-token" content="..." />
    m = re.search(r"<meta[^>]+name=\"csrf-token\"[^>]+content=\"([^\"]+)\"", html, re.I)
    if not m:
        return ""
    return m.group(1)


def parse_setup_csrf(html: str) -> str:
    # setup/login forms put csrf token in hidden field named csrf_token
    m = re.search(r"name=\"csrf_token\"\s+value=\"([^\"]+)\"", html, re.I)
    if not m:
        return ""
    return m.group(1)


def wait_for_health(client: HttpClient, timeout_s: int = 45):
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout_s:
        try:
            st, _, body = client.get("/healthz")
            last = (st, body)
            if st == 200 and (body or b"").strip() == b"ok":
                return
        except Exception as e:
            last = str(e)
        time.sleep(1)
    raise RuntimeError(f"healthz not OK: {last}")


def setup_admin(client: HttpClient, username: str, password: str):
    st, _, body = client.get("/setup")
    assert st == 200
    html = body.decode("utf-8", errors="replace")
    tok = parse_setup_csrf(html)
    assert tok, "missing setup csrf token"

    st2, hdrs2, _ = client.post_form(
        "/setup",
        {
            "username": username,
            "password": password,
            "password2": password,
            "csrf_token": tok,
        },
    )
    # Redirect to /
    assert st2 in (200, 303)


def get_session_csrf(client: HttpClient) -> str:
    # Any HTML page with meta csrf-token uses request.state.csrf.
    st, _, body = client.get("/onboarding")
    assert st == 200
    return parse_meta_csrf(body.decode("utf-8", errors="replace"))


def api_post_form(client: HttpClient, path: str, csrf: str, fields: dict) -> dict:
    st, _, body = client.post_form(path, fields, headers={"x-csrf-token": csrf})
    if st < 200 or st >= 300:
        raise RuntimeError(f"POST {path} -> {st}: {body[:400]!r}")
    return json.loads(body.decode("utf-8"))


def api_get_json(client: HttpClient, path: str) -> dict:
    st, _, body = client.get(path, headers={"Cache-Control": "no-store"})
    if st < 200 or st >= 300:
        raise RuntimeError(f"GET {path} -> {st}: {body[:400]!r}")
    return json.loads(body.decode("utf-8"))
