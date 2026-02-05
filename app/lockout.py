import json
import os
import time
from pathlib import Path
from typing import Optional, Tuple

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
STATE_DIR = DATA_DIR / "state"
LOCKOUT_PATH = STATE_DIR / "lockout.json"

# policy
WINDOW_SECONDS = 15 * 60
LOCK_1_COUNT = 5
LOCK_1_SECONDS = 5 * 60
LOCK_2_COUNT = 10
LOCK_2_SECONDS = 30 * 60


def _load() -> dict:
    try:
        if LOCKOUT_PATH.exists():
            return json.loads(LOCKOUT_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return {}


def _save(d: dict) -> None:
    LOCKOUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOCKOUT_PATH.write_text(json.dumps(d, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def get_lock_remaining(ip: str) -> int:
    d = _load()
    rec = (d.get(ip) or {}) if isinstance(d, dict) else {}
    until = int(rec.get("locked_until") or 0)
    now = int(time.time())
    return max(0, until - now)


def record_failure(ip: str) -> Tuple[int, int]:
    """Returns (count_in_window, lock_seconds_set)."""
    now = int(time.time())
    d = _load()
    rec = (d.get(ip) or {}) if isinstance(d, dict) else {}

    first = int(rec.get("first") or now)
    count = int(rec.get("count") or 0)
    locked_until = int(rec.get("locked_until") or 0)

    # reset window
    if now - first > WINDOW_SECONDS:
        first = now
        count = 0

    count += 1

    lock_for = 0
    if count >= LOCK_2_COUNT:
        lock_for = LOCK_2_SECONDS
    elif count >= LOCK_1_COUNT:
        lock_for = LOCK_1_SECONDS

    if lock_for:
        locked_until = max(locked_until, now + lock_for)

    d[ip] = {"first": first, "count": count, "locked_until": locked_until}

    # prune old entries
    for k in list(d.keys()):
        r = d.get(k) or {}
        if not isinstance(r, dict):
            d.pop(k, None)
            continue
        u = int(r.get("locked_until") or 0)
        f = int(r.get("first") or 0)
        if (u and now - u > 24 * 3600) or (now - f > 24 * 3600):
            d.pop(k, None)

    _save(d)
    return count, lock_for


def clear(ip: str) -> None:
    d = _load()
    if isinstance(d, dict) and ip in d:
        d.pop(ip, None)
        _save(d)
