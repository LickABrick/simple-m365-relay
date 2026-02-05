from __future__ import annotations

from typing import Optional

from fastapi import HTTPException, Request


def _truthy(v: str) -> bool:
    return (v or "").strip().lower() in ("1", "true", "yes", "on")


def client_ip(request: Request) -> str:
    """Return best-effort client IP.

    We only trust X-Forwarded-For when TRUST_PROXY_HEADERS is enabled.
    """
    import os

    trust = _truthy(os.environ.get("TRUST_PROXY_HEADERS", ""))
    if trust:
        xff = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
        if xff:
            return xff
    return request.client.host if request.client else ""


def is_https_request(request: Request) -> bool:
    # Allow forcing secure cookies when behind a TLS terminator.
    try:
        import os

        if (os.environ.get("FORCE_SECURE_COOKIES") or "").strip() in ("1", "true", "yes", "on"):
            return True
    except Exception:
        pass

    xf = (request.headers.get("x-forwarded-proto") or "").lower().strip()
    if xf == "https":
        return True
    # Starlette's request.url.scheme may be correct when running behind proxy_headers middleware.
    try:
        return (request.url.scheme or "").lower() == "https"
    except Exception:
        return False


def require_csrf(request: Request, provided: str) -> None:
    expected = getattr(request.state, "csrf", None)
    if not expected:
        raise HTTPException(status_code=403, detail="CSRF not initialized")
    if not provided or str(provided) != str(expected):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


def get_csrf_from_request(request: Request) -> Optional[str]:
    # Prefer header for AJAX.
    h = request.headers.get("x-csrf-token")
    if h:
        return h
    return None
