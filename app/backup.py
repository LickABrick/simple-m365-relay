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
    if "mynetworks" in cfg and cfg["mynetworks"] is not None and not isinstance(cfg["mynetworks"], list):
        raise ValueError("config.mynetworks must be a list")
    if "tls" in cfg and cfg["tls"] is not None and not isinstance(cfg["tls"], dict):
        raise ValueError("config.tls must be an object")
    if "oauth" in cfg and cfg["oauth"] is not None and not isinstance(cfg["oauth"], dict):
        raise ValueError("config.oauth must be an object")
    if "allowed_from" in cfg and cfg["allowed_from"] is not None and not isinstance(cfg["allowed_from"], dict):
        raise ValueError("config.allowed_from must be an object")
    if "default_from" in cfg and cfg["default_from"] is not None and not isinstance(cfg["default_from"], dict):
        raise ValueError("config.default_from must be an object")

    # Ensure new keys exist
    cfg.setdefault("ms365_smtp_user", "")
    cfg.setdefault("tls", {"smtpd_25": "may", "smtpd_587": "encrypt"})
    cfg.setdefault("oauth", {"tenant_id": "", "client_id": "", "auto_refresh_minutes": 30})
    cfg.setdefault("allowed_from", {})
    cfg.setdefault("default_from", {})

    return cfg


def dumps_cfg(cfg: Dict[str, Any]) -> bytes:
    validate_cfg_obj(cfg)
    return (json.dumps(cfg, indent=2, sort_keys=True) + "\n").encode("utf-8")
