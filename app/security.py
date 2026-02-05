from __future__ import annotations

from typing import Optional

from fastapi import HTTPException, Request


def is_https_request(request: Request) -> bool:
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
