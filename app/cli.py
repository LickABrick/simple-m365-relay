"""Simple M365 Relay CLI utilities.

Run inside the UI container, e.g.:

  /opt/venv/bin/python -m app.cli admin reset

We keep this CLI local-only (docker exec) so we can do break-glass operations
without adding network endpoints.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from . import auth
from . import lockout
from . import main


def _confirm(prompt: str) -> bool:
    try:
        ans = input(prompt).strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


def cmd_admin_reset(args: argparse.Namespace) -> int:
    """Reset admin + sessions.

    Implementation detail:
    - delete auth.json (admin creds)
    - rotate secret.key so all existing signed sessions become invalid
    - clear lockout state

    We intentionally do NOT wipe config.json unless explicitly requested.
    """

    if not args.yes:
        ok = _confirm(
            "This will reset the admin account and sign everyone out. Continue? [y/N] "
        )
        if not ok:
            print("Aborted.")
            return 2

    paths = [auth.AUTH_PATH, auth.SECRET_PATH, lockout.LOCKOUT_PATH]

    for p in paths:
        try:
            if p.exists():
                p.unlink()
        except Exception as e:
            print(f"WARN: could not delete {p}: {e}", file=sys.stderr)

    # Optionally wipe config
    if args.wipe_config:
        try:
            if main.CFG_JSON.exists():
                main.CFG_JSON.unlink()
        except Exception as e:
            print(f"WARN: could not delete {main.CFG_JSON}: {e}", file=sys.stderr)

    # Optionally wipe pending/applied state
    if args.wipe_state:
        try:
            if main.APPLIED_HASH_PATH.exists():
                main.APPLIED_HASH_PATH.unlink()
        except Exception as e:
            print(f"WARN: could not delete {main.APPLIED_HASH_PATH}: {e}", file=sys.stderr)

    print("OK: admin reset. Next web request should redirect to /setup.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    # Minimal health info that doesn't need the web UI.
    cfg = main.load_cfg()
    relayhost = cfg.get("relayhost") or os.environ.get("RELAYHOST", "")
    ms365_user = os.environ.get("MS365_SMTP_USER", "")

    # Ask postfix control for token status. This keeps least-privilege (UI container
    # doesn't read the token file directly).
    token_exp_ts = None
    try:
        token_exp_ts = (main._control_get("/token/status") or {}).get("token_exp_ts")
    except Exception:
        token_exp_ts = None

    print("Simple M365 Relay status")
    print(f"- relayhost: {relayhost or '(unknown)'}")
    print(f"- ms365_user: {ms365_user or '(unset)'}")

    if token_exp_ts:
        try:
            # token timestamps are epoch seconds
            dt = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(int(token_exp_ts)))
            print(f"- token_expiry: {dt}")
        except Exception:
            print(f"- token_expiry_ts: {token_exp_ts}")
    else:
        print("- token_expiry: (unknown)")

    print(f"- admin_configured: {'yes' if auth.admin_exists() else 'no'}")
    print(f"- onboarding_complete: {'yes' if main.onboarding_complete(cfg) else 'no'}")
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    """Render config and reload postfix (same as UI's Apply Changes)."""

    out = main.render_and_reload()

    cfg = main.load_cfg()
    main.set_applied_hash(main.cfg_hash(cfg))

    msg = (out or "ok").strip() or "ok"
    print(msg)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="simple-m365-relay", add_help=True)
    sub = p.add_subparsers(dest="cmd", required=True)

    # admin
    pa = sub.add_parser("admin", help="Admin operations")
    suba = pa.add_subparsers(dest="admin_cmd", required=True)

    pr = suba.add_parser("reset", help="Reset admin account + sessions")
    pr.add_argument("--yes", action="store_true", help="Skip confirmation prompt")
    pr.add_argument(
        "--wipe-config",
        action="store_true",
        help="Also delete /data/config/config.json (factory-ish)",
    )
    pr.add_argument(
        "--wipe-state",
        action="store_true",
        help="Also delete applied/pending state (applied.hash)",
    )
    pr.set_defaults(func=cmd_admin_reset)

    # status
    ps = sub.add_parser("status", help="Show current status")
    ps.set_defaults(func=cmd_status)

    # apply
    pap = sub.add_parser("apply", help="Render + reload postfix (apply saved config)")
    pap.set_defaults(func=cmd_apply)

    return p


def main_cli(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main_cli())
