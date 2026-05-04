"""Config validation helpers (UI side).

validate_cfg_obj is used by the settings API to validate imported config.
Kept separate from app.backup to avoid import confusion.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode((s or "").encode("ascii"))


def validate_cfg_obj(cfg: Any) -> Dict[str, Any]:
    """Validate and normalize imported config.

    We only validate the parts we actively use. Unknown keys are preserved.
    """
    if not isinstance(cfg, dict):
        raise ValueError("config.json must be a JSON object")

    # Shallow type checks
    if "mynetworks" in cfg and cfg["mynetworks"] is not None:
        if not isinstance(cfg["mynetworks"], (list, str)):
            raise ValueError("config.mynetworks must be a list or string")
    if "allowed_from" in cfg and cfg["allowed_from"] is not None:
        if not isinstance(cfg["allowed_from"], dict):
            raise ValueError("config.allowed_from must be an object")
    if "default_from" in cfg and cfg["default_from"] is not None:
        if not isinstance(cfg["default_from"], dict):
            raise ValueError("config.default_from must be an object")

    return cfg