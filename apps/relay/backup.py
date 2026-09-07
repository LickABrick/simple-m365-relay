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
import os
import re
import subprocess
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

GUID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.I)


def validate_config(config: Any) -> Dict[str, Any]:
    if not isinstance(config, dict):
        raise ValueError("config/config.json must be a JSON object")
    allowed = {"hostname", "domain", "mynetworks", "relayhost", "ms365_smtp_user", "tls", "oauth", "allowed_from", "default_from", "onboarding_complete"}
    unknown = set(config) - allowed
    if unknown:
        raise ValueError(f"Unknown configuration fields: {', '.join(sorted(unknown))}")
    def clean(value: Any, name: str, maximum: int = 512) -> str:
        if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError(f"Invalid {name}")
        return value.strip()
    for key in ("hostname", "domain", "relayhost"):
        if key in config:
            clean(config[key], key)
    networks = config.get("mynetworks", ["127.0.0.0/8"])
    if not isinstance(networks, list) or not networks or any(not isinstance(v, str) or not re.fullmatch(r"[0-9a-fA-F:./]+", v) for v in networks):
        raise ValueError("Invalid mynetworks")
    user = config.get("ms365_smtp_user", "")
    if not isinstance(user, str) or any(ord(c) < 32 or ord(c) == 127 for c in user):
        raise ValueError("Invalid ms365_smtp_user")
    tls = config.get("tls", {})
    if not isinstance(tls, dict) or set(tls) - {"smtpd_25", "smtpd_587", "smtp_out"} or any(v not in {"none", "may", "encrypt", "verify", "secure"} for v in tls.values()):
        raise ValueError("Invalid TLS configuration")
    oauth = config.get("oauth", {})
    if not isinstance(oauth, dict) or set(oauth) - {"tenant_id", "client_id", "auto_refresh_minutes"}:
        raise ValueError("Invalid OAuth configuration")
    for key in ("tenant_id", "client_id"):
        value = oauth.get(key, "")
        if value and (not isinstance(value, str) or not GUID.fullmatch(value)):
            raise ValueError(f"Invalid OAuth {key}")
    refresh = oauth.get("auto_refresh_minutes", 30)
    if not isinstance(refresh, int) or not 0 <= refresh <= 1440:
        raise ValueError("Invalid OAuth refresh interval")
    allowed_from = config.get("allowed_from", {})
    default_from = config.get("default_from", {})
    safe_token = re.compile(r"^[^\s/\\\x00-\x1f\x7f]+$")
    if not isinstance(allowed_from, dict) or any(
        not isinstance(login, str)
        or not safe_token.fullmatch(login)
        or not isinstance(addresses, list)
        or any(not isinstance(address, str) or not safe_token.fullmatch(address) for address in addresses)
        for login, addresses in allowed_from.items()
    ):
        raise ValueError("Invalid allowed_from")
    if not isinstance(default_from, dict) or any(
        not isinstance(login, str)
        or not safe_token.fullmatch(login)
        or not isinstance(address, str)
        or not safe_token.fullmatch(address)
        for login, address in default_from.items()
    ):
        raise ValueError("Invalid default_from")
    if "onboarding_complete" in config and not isinstance(config["onboarding_complete"], bool):
        raise ValueError("Invalid onboarding_complete")
    return config


def normalize_users(data: bytes) -> bytes:
    output = []
    for line in data.decode("utf-8").splitlines():
        if not line.strip():
            continue
        if ":" not in line:
            raise ValueError("Invalid SMTP user record")
        login, verifier = line.split(":", 1)
        if not re.fullmatch(r"[A-Za-z0-9._%+@-]{1,254}", login):
            raise ValueError("Invalid SMTP user login")
        if verifier.startswith("{PLAIN}"):
            password = verifier.removeprefix("{PLAIN}")
            verifier = subprocess.run(["doveadm", "pw", "-s", "ARGON2ID", "-p", password], check=True, text=True, stdout=subprocess.PIPE).stdout.strip()
        if not verifier.startswith("{ARGON2ID}"):
            raise ValueError("Unsupported SMTP password verifier")
        output.append(f"{login}:{verifier}\n")
    return "".join(output).encode("utf-8")


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
        cfg_obj = validate_config(cfg_obj)

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
        users_bytes = normalize_users(users_bytes)
        tmp = users_path.with_name(f".{users_path.name}.import-{os.getpid()}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(users_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, users_path)
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass

    return {
        "ok": True,
        "imported": {"config": bool(cfg_bytes), "smtp_auth_users": bool(users_bytes)},
    }


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode((s or "").encode("ascii"))
