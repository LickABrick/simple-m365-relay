import importlib
import os
from pathlib import Path

import pytest


def _reload_app_modules(tmp_path: Path):
    os.environ["DATA_DIR"] = str(tmp_path)
    # reload modules so they pick up DATA_DIR
    import app.auth as auth
    import app.lockout as lockout
    import app.main as main
    import app.cli as cli

    importlib.reload(auth)
    importlib.reload(lockout)
    importlib.reload(main)
    importlib.reload(cli)
    return auth, lockout, main, cli


def test_admin_reset_deletes_auth_and_secret(tmp_path, capsys, monkeypatch):
    auth, lockout, main, cli = _reload_app_modules(tmp_path)

    # create fake admin + secret + lockout
    auth.AUTH_PATH.parent.mkdir(parents=True, exist_ok=True)
    auth.AUTH_PATH.write_text('{"username":"a","password_hash":"x","created_at":1}', encoding="utf-8")
    auth.SECRET_PATH.write_bytes(b"k" * 32)
    lockout.LOCKOUT_PATH.write_text('{"1.2.3.4": {"count": 9}}', encoding="utf-8")

    rc = cli.main_cli(["admin", "reset", "--yes"])
    assert rc == 0

    assert not auth.AUTH_PATH.exists()
    assert not auth.SECRET_PATH.exists()
    assert not lockout.LOCKOUT_PATH.exists()

    out = capsys.readouterr().out
    assert "admin reset" in out.lower()


def test_status_prints_expected_fields(tmp_path, capsys, monkeypatch):
    auth, lockout, main, cli = _reload_app_modules(tmp_path)

    # avoid hitting postfix control in unit test
    monkeypatch.setattr(main, "_control_get", lambda path: {"token_exp_ts": 1700000000} if path == "/token/status" else {})
    monkeypatch.setenv("MS365_SMTP_USER", "user@example.com")

    rc = cli.main_cli(["status"])
    assert rc == 0

    out = capsys.readouterr().out
    assert "relayhost" in out
    assert "ms365_user" in out
    assert "token_expiry" in out


def test_apply_calls_render_and_updates_applied_hash(tmp_path, capsys, monkeypatch):
    auth, lockout, main, cli = _reload_app_modules(tmp_path)

    # ensure there is a config
    cfg = main.load_cfg()
    main.save_cfg(cfg)

    called = {"render": 0}

    def fake_render_and_reload():
        called["render"] += 1
        return "ok"

    monkeypatch.setattr(main, "render_and_reload", fake_render_and_reload)

    rc = cli.main_cli(["apply"])
    assert rc == 0
    assert called["render"] == 1
    assert main.APPLIED_HASH_PATH.exists()

    out = capsys.readouterr().out.strip().lower()
    assert out == "ok"
