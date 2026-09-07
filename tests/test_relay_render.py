import pytest

from apps.relay.render import render_sender_login_map


def test_shared_sender_aggregates_all_authorized_logins_into_one_lmdb_key():
    rendered = render_sender_login_map(
        {
            "dockhand": ["no-reply@example.com"],
            "infra": ["NO-REPLY@example.com"],
            "kopia": ["no-reply@example.com"],
            "teampass": ["no-reply@example.com"],
        }
    )

    assert rendered == "no-reply@example.com dockhand,infra,kopia,teampass\n"


def test_sender_map_preserves_unique_addresses_and_deduplicates_same_login():
    rendered = render_sender_login_map(
        {
            "scanner": [
                "alerts@example.com",
                "alerts@example.com",
                "reports@example.com",
            ],
            "service": ["reports@example.com"],
        }
    )

    assert rendered == (
        "alerts@example.com scanner\n"
        "reports@example.com scanner,service\n"
    )


@pytest.mark.parametrize(
    "allowed_from",
    [
        [],
        {"bad login": ["sender@example.com"]},
        {"login": "sender@example.com"},
        {"login": ["bad address@example.com"]},
    ],
)
def test_sender_map_rejects_invalid_shapes_and_tokens(allowed_from):
    with pytest.raises(ValueError):
        render_sender_login_map(allowed_from)
