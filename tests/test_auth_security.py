import importlib
import os
import stat

from starlette.requests import Request


def _reload_auth(tmp_path):
    os.environ["DATA_DIR"] = str(tmp_path)
    import app.auth as auth

    return importlib.reload(auth)


def test_auth_state_files_are_private(tmp_path):
    auth = _reload_auth(tmp_path)

    auth.save_admin("admin", "hash")
    auth.ensure_secret()

    assert stat.S_IMODE(auth.AUTH_PATH.stat().st_mode) == 0o600
    assert stat.S_IMODE(auth.SECRET_PATH.stat().st_mode) == 0o600


def test_setup_rejects_missing_csrf_cookie(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    import app.auth as auth
    import app.main as main

    importlib.reload(auth)
    importlib.reload(main)
    request = Request({"type": "http", "method": "POST", "path": "/setup", "headers": []})
    request.state.csp_nonce = "test-nonce"
    response = main.setup_post(
        request=request,
        username="admin",
        password="Strong-password1",
        password2="Strong-password1",
        csrf_token="attacker-token",
    )

    assert response.status_code == 403
    assert not auth.admin_exists()
