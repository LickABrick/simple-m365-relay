import importlib
import base64
import json
import time


def test_runtime_mailbox_overrides_bootstrap_environment(monkeypatch):
    import postfix.control as control

    importlib.reload(control)
    monkeypatch.setenv("MS365_SMTP_USER", "bootstrap@example.com")

    assert control._ms365_user({"ms365_smtp_user": "configured@example.com"}) == "configured@example.com"


def test_environment_is_used_as_headless_fallback(monkeypatch):
    import postfix.control as control

    importlib.reload(control)
    monkeypatch.setenv("MS365_SMTP_USER", "bootstrap@example.com")

    assert control._ms365_user({}) == "bootstrap@example.com"


def _jwt(claims):
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"header.{payload}.signature"


def test_delegated_smtp_token_capabilities_are_reported_without_secrets():
    import postfix.control as control

    data = {
        "access_token": _jwt({
            "aud": "https://outlook.office365.com",
            "scp": "SMTP.Send",
            "preferred_username": "relay@example.com",
            "tid": "tenant-id",
        }),
        "refresh_token": "do-not-return",
    }
    result = control._token_capabilities(data, int(time.time()) + 3600)

    assert result["smtp_ready"] is True
    assert result["token_type"] == "delegated"
    assert result["identity"] == "relay@example.com"
    assert "do-not-return" not in json.dumps(result)


def test_missing_smtp_scope_is_an_actionable_error():
    import postfix.control as control

    data = {
        "access_token": _jwt({"aud": "https://outlook.office365.com", "scp": "User.Read"}),
        "refresh_token": "present",
    }
    result = control._token_capabilities(data, int(time.time()) + 3600)

    assert result["smtp_ready"] is False
    assert any(issue["code"] == "missing_smtp_send" for issue in result["issues"])
