"""Config validation helpers (UI side).

validate_cfg_obj is used by the settings API to validate imported config.
Kept separate from app.backup to avoid import confusion.
"""

from __future__ import annotations

import base64
import json
import re
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

    def clean_string(value: Any, field: str, max_length: int = 512) -> str:
        if not isinstance(value, str):
            raise ValueError(f"config.{field} must be a string")
        if len(value) > max_length or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            raise ValueError(f"config.{field} contains invalid characters")
        return value.strip()

    for key in ("hostname", "domain", "relayhost", "ms365_smtp_user"):
        if key in cfg and cfg[key] is not None:
            clean_string(cfg[key], key)

    if "mynetworks" in cfg and cfg["mynetworks"] is not None:
        if not isinstance(cfg["mynetworks"], list):
            raise ValueError("config.mynetworks must be a list")
        if len(cfg["mynetworks"]) > 128:
            raise ValueError("config.mynetworks has too many entries")
        for index, network in enumerate(cfg["mynetworks"]):
            clean_string(network, f"mynetworks[{index}]", 128)
    if "tls" in cfg and cfg["tls"] is not None:
        if not isinstance(cfg["tls"], dict):
            raise ValueError("config.tls must be an object")
        for key in ("smtpd_25", "smtpd_587"):
            if key in cfg["tls"] and cfg["tls"][key] not in ("none", "may", "encrypt"):
                raise ValueError(f"config.tls.{key} is invalid")
    if "oauth" in cfg and cfg["oauth"] is not None:
        if not isinstance(cfg["oauth"], dict):
            raise ValueError("config.oauth must be an object")
        for key in ("tenant_id", "client_id"):
            if key in cfg["oauth"]:
                value = clean_string(cfg["oauth"][key], f"oauth.{key}", 128)
                if value and not re.fullmatch(r"[A-Za-z0-9._-]+", value):
                    raise ValueError(f"config.oauth.{key} is invalid")
        if "auto_refresh_minutes" in cfg["oauth"]:
            minutes = cfg["oauth"]["auto_refresh_minutes"]
            if isinstance(minutes, bool) or not isinstance(minutes, int) or not 0 <= minutes <= 1440:
                raise ValueError("config.oauth.auto_refresh_minutes must be an integer from 0 to 1440")
    if "allowed_from" in cfg and cfg["allowed_from"] is not None:
        if not isinstance(cfg["allowed_from"], dict):
            raise ValueError("config.allowed_from must be an object")
        for login, addresses in cfg["allowed_from"].items():
            clean_string(login, "allowed_from login", 254)
            if not isinstance(addresses, list) or len(addresses) > 256:
                raise ValueError("config.allowed_from values must be address lists")
            for address in addresses:
                clean_string(address, "allowed_from address", 254)
    if "default_from" in cfg and cfg["default_from"] is not None:
        if not isinstance(cfg["default_from"], dict):
            raise ValueError("config.default_from must be an object")
        for login, address in cfg["default_from"].items():
            clean_string(login, "default_from login", 254)
            clean_string(address, "default_from address", 254)

    return cfg
