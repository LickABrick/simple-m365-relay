import importlib


def test_main_bootstraps_control_token_before_serving(monkeypatch):
    import apps.relay.control as control

    importlib.reload(control)
    events = []

    class FakeThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            events.append("thread")

    class FakeServer:
        def __init__(self, *args, **kwargs):
            events.append("server")

        def serve_forever(self):
            events.append("serve")

    monkeypatch.setattr(control, "_get_control_token", lambda: events.append("token") or "secret")
    monkeypatch.setattr(control.threading, "Thread", FakeThread)
    monkeypatch.setattr(control, "_ThreadingHTTPServer", FakeServer)
    monkeypatch.setattr(control, "SOCKET_PATH", "")

    control.main()

    assert events == ["token", "thread", "server", "serve"]
