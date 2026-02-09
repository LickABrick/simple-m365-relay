#!/usr/bin/env python3
"""Backup import/export helpers (Postfix container side).

We export/import ONLY:
- /data/config/config.json
- /data/sasl/sasldb2  (SMTP AUTH users)

We intentionally do NOT include:
- /data/state/auth.json (admin user)
- /data/tokens/* (OAuth tokens)

Bundle format:
- zip containing:
  - config/config.json
  - sasl/sasldb2  (optional)
  - meta.json

This module is stdlib-only.
"""

from __future__ import annotations

import base64
import datetime as dt
import io
import json
import zipfile
from pathlib import Path
from typing import Any, Dict, Tuple


def export_bundle(data_dir: Path) -> Tuple[bytes, Dict[str, Any]]:
    cfg_path = data_dir / "config" / "config.json"
    sasl_path = data_dir / "sasl" / "sasldb2"

    meta: Dict[str, Any] = {
        "format": "simple-m365-relay-backup",
        "version": 1,
        "created_at": dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "includes": {"config": bool(cfg_path.exists()), "smtp_auth_users": bool(sasl_path.exists())},
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("meta.json", json.dumps(meta, indent=2, sort_keys=True) + "\n")
        if cfg_path.exists():
            z.writestr("config/config.json", cfg_path.read_bytes())
        if sasl_path.exists():
            z.writestr("sasl/sasldb2", sasl_path.read_bytes())

    return buf.getvalue(), meta


def parse_bundle_zip(zip_bytes: bytes) -> Dict[str, bytes]:
    out: Dict[str, bytes] = {}
    with zipfile.ZipFile(io.BytesIO(zip_bytes), mode="r") as z:
        for name in z.namelist():
            if name.endswith("/"):
                continue
            out[name] = z.read(name)
    return out


def validate_and_extract_bundle(zip_bytes: bytes) -> Dict[str, Any]:
    files = parse_bundle_zip(zip_bytes)
    meta_raw = files.get("meta.json")
    meta = None
    if meta_raw:
        try:
            meta = json.loads(meta_raw.decode("utf-8"))
        except Exception:
            meta = None

    cfg_raw = files.get("config/config.json")
    sasl_raw = files.get("sasl/sasldb2")

    if not cfg_raw and not sasl_raw:
        raise ValueError("Backup bundle is empty (missing config and sasl).")

    cfg_obj = None
    if cfg_raw:
        try:
            cfg_obj = json.loads(cfg_raw.decode("utf-8"))
        except Exception:
            raise ValueError("config/config.json is not valid JSON")
        if not isinstance(cfg_obj, dict):
            raise ValueError("config/config.json must be a JSON object")

    return {
        "meta": meta,
        "has_config": bool(cfg_raw),
        "has_sasl": bool(sasl_raw),
        "config_obj": cfg_obj,
        "config_bytes": cfg_raw,
        "sasl_bytes": sasl_raw,
    }


def import_bundle(data_dir: Path, zip_bytes: bytes) -> Dict[str, Any]:
    info = validate_and_extract_bundle(zip_bytes)

    cfg_bytes = info.get("config_bytes")
    sasl_bytes = info.get("sasl_bytes")

    # Write config.json atomically-ish
    if cfg_bytes:
        cfg_path = data_dir / "config" / "config.json"
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = cfg_path.with_name(cfg_path.name + ".tmp")
        tmp.write_bytes(cfg_bytes)
        tmp.replace(cfg_path)

    # Write sasldb2 atomically-ish
    if sasl_bytes is not None:
        sasl_path = data_dir / "sasl" / "sasldb2"
        sasl_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = sasl_path.with_name(sasl_path.name + ".tmp")
        tmp.write_bytes(sasl_bytes)
        tmp.replace(sasl_path)

    return {
        "ok": True,
        "imported": {"config": bool(cfg_bytes), "smtp_auth_users": bool(sasl_bytes is not None and len(sasl_bytes) > 0)},
    }


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode((s or "").encode("ascii"))
