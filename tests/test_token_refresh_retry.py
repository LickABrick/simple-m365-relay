import importlib


def test_next_refresh_delay_success_uses_normal_interval():
    import apps.relay.control as control

    importlib.reload(control)
    d = control._next_refresh_delay_seconds("Token refresh succeeded. New expiry=123", 1800, 60)
    assert d == 1800


def test_next_refresh_delay_failure_uses_fast_retry():
    import apps.relay.control as control

    importlib.reload(control)
    d = control._next_refresh_delay_seconds("Token refresh failed: URLError", 1800, 60)
    assert d == 60


def test_next_refresh_delay_retry_is_capped_by_interval():
    import apps.relay.control as control

    importlib.reload(control)
    d = control._next_refresh_delay_seconds("Token refresh failed: URLError", 45, 60)
    assert d == 45
