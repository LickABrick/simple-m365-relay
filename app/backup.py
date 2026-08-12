from __future__ import annotations

import base64
import json
from typing import Any, Dict

from .config import validate_cfg_obj


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode((s or "").encode("ascii"))


def dumps_cfg(cfg: Dict[str, Any]) -> bytes:
    validate_cfg_obj(cfg)
    return (json.dumps(cfg, indent=2, sort_keys=True) + "\n").encode("utf-8")
