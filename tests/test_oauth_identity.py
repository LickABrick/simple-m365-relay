import importlib


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
