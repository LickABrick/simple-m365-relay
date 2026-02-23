from __future__ import annotations

from e2e_common import HttpClient, api_get_json, api_post_form, get_session_csrf, setup_admin, wait_for_health

import time


def main():
    base = "http://ui:8000"
    c = HttpClient(base)
    wait_for_health(c)

    setup_admin(c, "admin", "Adminadmin123!")
    csrf = get_session_csrf(c)
    assert csrf

    # Wait for control API to be ready (avoid flakes).
    for _ in range(30):
        stj = api_get_json(c, "/api/status")
        if stj.get("ok") is True:
            break
        time.sleep(1)

    # In MailHog mode we typically do NOT have an MS365 identity configured.
    # So we must provide an explicit From.
    j = api_post_form(
        c,
        "/api/testmail",
        csrf,
        {
            "to_addr": "to@example.com",
            "from_addr": "from@example.com",
            "subject": "e2e mailhog",
            "body": "hello",
            "verify": "1",
        },
    )

    assert j.get("ok") is True, j

    delivery = j.get("delivery") or {}
    st = delivery.get("state")
    assert st in (None, "unknown", "seen", "queued", "sent", "deferred"), delivery

    print("OK: mailhog testmail", st)


if __name__ == "__main__":
    main()
