import base64
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
STATE_DIR = DATA_DIR / "state"
AUTH_PATH = STATE_DIR / "auth.json"
SECRET_PATH = STATE_DIR / "secret.key"

SESSION_COOKIE = "sm365r_session"
SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 7  # 7 days
LOCKOUT_PATH = STATE_DIR / "lockout.json"


@dataclass
class AuthState:
    username: str
    password_hash: str
    created_at: int


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def admin_exists() -> bool:
    return AUTH_PATH.exists() and AUTH_PATH.stat().st_size > 0


def load_admin() -> Optional[AuthState]:
    if not admin_exists():
        return None
    try:
        d = _read_json(AUTH_PATH)
        return AuthState(
            username=str(d.get("username") or "").strip(),
            password_hash=str(d.get("password_hash") or "").strip(),
            created_at=int(d.get("created_at") or 0),
        )
    except Exception:
        return None


def save_admin(username: str, password_hash: str) -> None:
    _write_json(
        AUTH_PATH,
        {
            "username": username,
            "password_hash": password_hash,
            "created_at": int(time.time()),
        },
    )


def ensure_secret() -> bytes:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if SECRET_PATH.exists() and SECRET_PATH.stat().st_size > 0:
        return SECRET_PATH.read_bytes()
    key = secrets.token_bytes(32)
    SECRET_PATH.write_bytes(key)
    try:
        os.chmod(SECRET_PATH, 0o600)
    except Exception:
        pass
    return key


def _serializer() -> URLSafeTimedSerializer:
    secret = ensure_secret()
    return URLSafeTimedSerializer(secret_key=base64.urlsafe_b64encode(secret).decode("ascii"), salt="sm365r")


def new_csrf_token() -> str:
    return secrets.token_urlsafe(24)


def make_session(username: str, csrf_token: str) -> str:
    return _serializer().dumps({"u": username, "c": csrf_token})


def read_session(token: str) -> Optional[dict]:
    if not token:
        return None
    try:
        data = _serializer().loads(token, max_age=SESSION_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        return None
    if not isinstance(data, dict):
        return None
    u = str(data.get("u") or "").strip()
    c = str(data.get("c") or "").strip()
    if not u:
        return None
    if not c:
        # legacy session tokens (pre-csrf)
        c = new_csrf_token()
    return {"u": u, "c": c}


def session_user(token: str) -> Optional[str]:
    d = read_session(token)
    return str(d.get("u")) if d else None


def session_csrf(token: str) -> Optional[str]:
    d = read_session(token)
    return str(d.get("c")) if d else None


def verify_password(password: str, password_hash: str) -> bool:
    # Prefer Argon2 when available.
    try:
        from argon2 import PasswordHasher

        ph = PasswordHasher()
        ph.verify(password_hash, password)
        return True
    except Exception:
        return False


def hash_password(password: str) -> str:
    from argon2 import PasswordHasher

    ph = PasswordHasher()
    return ph.hash(password)


def validate_new_password(pw: str) -> Tuple[bool, str]:
    pw = pw or ""
    if len(pw) < 12:
        return False, "Password must be at least 12 characters."
    if pw.lower() == pw or pw.upper() == pw:
        return False, "Password must include both lower and upper case characters."
    if not any(c.isdigit() for c in pw):
        return False, "Password must include at least one number."
    if not any(not c.isalnum() for c in pw):
        return False, "Password must include at least one symbol."
    return True, ""
