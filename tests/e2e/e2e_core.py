from __future__ import annotations

import json
import re

from e2e_common import HttpClient, api_get_json, api_post_form, get_session_csrf, setup_admin, wait_for_health

import time


def _extract_config_from_diagnostics(txt: str) -> dict:
    m = re.search(r"## config\.json\n(\{[\s\S]*?\})\n\n## mailq", txt)
    if not m:
        raise RuntimeError("could not parse config.json from diagnostics")
    return json.loads(m.group(1))


def main():
    base = "http://ui:8000"
    c = HttpClient(base)
    wait_for_health(c)

    setup_admin(c, "admin", "Adminadmin123!")
    csrf = get_session_csrf(c)
    assert csrf

    # Save enough settings to complete onboarding gate
    r = api_post_form(
        c,
        "/api/settings",
        csrf,
        {
            "relayhost": "[smtp.office365.com]:587",
            "ms365_smtp_user": "postfix@example.com",
            "tenant_id": "00000000-0000-0000-0000-000000000000",
            "client_id": "11111111-1111-1111-1111-111111111111",
        },
    )
    assert r.get("ok") is True

    # Load dashboard once (ensures applied snapshot exists)
    # Wait until postfix control health is reachable to avoid flakes.
    for _ in range(30):
        stj = api_get_json(c, "/api/status")
        if stj.get("ok") is True:
            break
        time.sleep(1)
    st, _, body = c.get("/")
    assert st == 200

    # Change a setting to create pending
    r2 = api_post_form(c, "/api/settings", csrf, {"hostname": "relay.changed.local", "relayhost": "[smtp.office365.com]:587"})
    assert r2.get("ok") is True

    stj = api_get_json(c, "/api/status")
    assert stj.get("pending") is True, f"expected pending true, got: {stj}"

    # Discard and check pending clears
    d = api_post_form(c, "/api/discard", csrf, {})
    assert d.get("ok") is True

    stj2 = api_get_json(c, "/api/status")
    assert stj2.get("pending") is False

    # Verify config restored by reading diagnostics
    st3, _, body3 = c.get("/diagnostics.txt")
    assert st3 == 200
    cfg = _extract_config_from_diagnostics(body3.decode("utf-8", errors="replace"))
    assert cfg.get("hostname") != "relay.changed.local"

    # Allowed From UX: users datalist should contain the SMTP user after adding it.
    # Add an SMTP AUTH user
    u = api_post_form(c, "/api/users/add", csrf, {"login": "testuser", "password": "pw123"})
    assert u.get("ok") is True

    # Fetch dashboard HTML and check datalist exists
    st4, _, body4 = c.get("/#senders")
    assert st4 == 200
    html = body4.decode("utf-8", errors="replace")
    assert "smtpUsersDatalist" in html

    print("OK: core e2e")


if __name__ == "__main__":
    main()
