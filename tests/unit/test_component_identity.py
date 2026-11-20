"""Tests for upstream component identity evidence."""

from firmware_scanner.extraction.models import Component


def test_confirmed_upstream_identity_prefers_a_specific_component():
    component = Component(
        name="libft2.so",
        properties=[
            {
                "name": "firmware:blintdb:identity-confirmed",
                "value": '{"components": ["freetype"], "projects": ["aggregate"]}',
            }
        ],
    )

    from firmware_scanner.extraction.component_identity import confirmed_upstream_identity

    assert confirmed_upstream_identity(component) == "freetype"


def test_confirmed_upstream_identity_falls_back_to_the_raw_name():
    component = Component(
        name="libcustom.so",
        properties=[
            {
                "name": "firmware:blintdb:identity-confirmed",
                "value": "not-json",
            }
        ],
    )

    from firmware_scanner.extraction.component_identity import confirmed_upstream_identity

    assert confirmed_upstream_identity(component) == "libcustom.so"
