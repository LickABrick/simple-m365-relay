#!/usr/bin/env python3
"""Backup import/export helpers (Postfix container side).

We export/import ONLY:
- the SQLite-backed relay configuration (portable JSON inside the archive)
- /data/sasl/users  (Dovecot passwd-file SMTP AUTH users)

We intentionally do NOT include:
- /data/state/auth.json (admin user)
- /data/tokens/* (OAuth tokens)

Bundle format:
- zip containing:
  - config/config.json
  - sasl/users  (optional)
  - meta.json

This module is stdlib-only.
"""

from __future__ import annotations

import base64
import datetime as dt
import io
import json
import sqlite3
import zipfile
from pathlib import Path
from typing import Any, Dict, Tuple

# Hard limits to reduce DoS risk from crafted ZIPs.
MAX_ZIP_BYTES = 10 * 1024 * 1024  # 10 MiB (compressed)
MAX_ENTRIES = 25
MAX_META_BYTES = 256 * 1024
MAX_CONFIG_BYTES = 1 * 1024 * 1024
MAX_USERS_BYTES = 5 * 1024 * 1024

ALLOWED_NAMES = {
    "meta.json": MAX_META_BYTES,
    "config/config.json": MAX_CONFIG_BYTES,
    "sasl/users": MAX_USERS_BYTES,
    # Read-only compatibility with pre-Dovecot backup bundles.
    "sasl/sasldb2": MAX_USERS_BYTES,
}


def export_bundle(data_dir: Path) -> Tuple[bytes, Dict[str, Any]]:
    db_path = data_dir / "state" / "relay.db"
    users_path = data_dir / "sasl" / "users"

    cfg_bytes = None
    if db_path.exists():
        with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
            row = conn.execute("SELECT config FROM settings WHERE id = 1").fetchone()
        if row:
            cfg_bytes = (json.dumps(json.loads(row[0]), indent=2, sort_keys=True) + "\n").encode("utf-8")

    meta: Dict[str, Any] = {
        "format": "simple-m365-relay-backup",
        "version": 2,
        "created_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "includes": {"config": bool(cfg_bytes), "smtp_auth_users": bool(users_path.exists())},
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("meta.json", json.dumps(meta, indent=2, sort_keys=True) + "\n")
        if cfg_bytes:
            z.writestr("config/config.json", cfg_bytes)
        if users_path.exists():
            z.writestr("sasl/users", users_path.read_bytes())

    return buf.getvalue(), meta


def parse_bundle_zip(zip_bytes: bytes) -> Dict[str, bytes]:
    """Parse a bundle ZIP safely.

    We *never* extract to disk and we only read a strict allowlist of members.
    This mitigates common ZIP attacks (path traversal, zip bombs, memory blowups).
    """
    if len(zip_bytes) > MAX_ZIP_BYTES:
        raise ValueError(f"Backup bundle too large (>{MAX_ZIP_BYTES} bytes)")

    out: Dict[str, bytes] = {}
    with zipfile.ZipFile(io.BytesIO(zip_bytes), mode="r") as z:
        infos = z.infolist()
        if len(infos) > MAX_ENTRIES:
            raise ValueError(f"Backup bundle has too many entries ({len(infos)} > {MAX_ENTRIES})")

        for zi in infos:
            name = zi.filename
            if name.endswith("/"):
                continue
            if name not in ALLOWED_NAMES:
                # Ignore unknown entries; the bundle is a whitelist format.
                continue
            max_bytes = int(ALLOWED_NAMES[name])
            # zipfile reports uncompressed file size here.
            if zi.file_size > max_bytes:
                raise ValueError(f"Backup member too large: {name} ({zi.file_size} > {max_bytes})")
            out[name] = z.read(zi)

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
    users_raw = files.get("sasl/users")
    legacy_sasldb_raw = files.get("sasl/sasldb2")

    if not cfg_raw and users_raw is None and legacy_sasldb_raw is None:
        raise ValueError("Backup bundle is empty (missing config and SMTP AUTH users).")

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
        "has_users": users_raw is not None,
        "has_legacy_sasldb": legacy_sasldb_raw is not None,
        "config_obj": cfg_obj,
        "config_bytes": cfg_raw,
        "users_bytes": users_raw,
    }


def import_bundle(data_dir: Path, zip_bytes: bytes) -> Dict[str, Any]:
    info = validate_and_extract_bundle(zip_bytes)

    cfg_bytes = info.get("config_bytes")
    users_bytes = info.get("users_bytes")
    if info.get("has_legacy_sasldb") and users_bytes is None:
        raise ValueError("Legacy sasldb2 backups cannot be imported after the Dovecot migration; recreate SMTP AUTH users in the UI.")

    # Import v1/v2 portable JSON configuration into the canonical SQLite row.
    if cfg_bytes:
        db_path = data_dir / "state" / "relay.db"
        with sqlite3.connect(db_path, timeout=10) as conn:
            conn.execute("UPDATE settings SET config = ?, updated_at = ? WHERE id = 1", (json.dumps(info["config_obj"], separators=(",", ":")), int(dt.datetime.now(dt.timezone.utc).timestamp())))
            conn.commit()

    # Write the Dovecot passwd-file atomically. It contains plaintext SMTP AUTH
    # passwords by design, so never leave it group/world-readable during import.
    if users_bytes is not None:
        users_path = data_dir / "sasl" / "users"
        users_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = users_path.with_name(users_path.name + ".tmp")
        tmp.write_bytes(users_bytes)
        tmp.chmod(0o600)
        tmp.replace(users_path)

    return {
        "ok": True,
        "imported": {"config": bool(cfg_bytes), "smtp_auth_users": bool(users_bytes)},
    }


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode((s or "").encode("ascii"))
