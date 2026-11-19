"""Tests for conservative Android NOTICE license attribution."""

from firmware_scanner.extraction.models import Component


def test_notice_html_maps_strong_license_text_to_files():
    from firmware_scanner.android.notice_licenses import parse_notice_licenses

    document = b"""
    <html><body>
      <tr id="id1"><td class="same-license">
        <div class="file-list">/system/lib/libft2.so</div>
        <pre class="license-text">
The FreeType Project LICENSE
Copyright 1996-2002 David Turner, Robert Wilhelm, and Werner Lemberg.
        </pre>
      </td></tr>
      <tr id="id2"><td class="same-license">
        <div class="file-list">/system/lib/libfoo.so<br>/system/lib/libbar.so</div>
        <pre class="license-text">
Apache License
Version 2.0, January 2004
http://www.apache.org/licenses/
        </pre>
      </td></tr>
      <tr id="id3"><td class="same-license">
        <div class="file-list">/system/lib/libunknown.so</div>
        <pre class="license-text">Copyright 2020 Example. All rights reserved.</pre>
      </td></tr>
    </body></html>
    """

    parsed = parse_notice_licenses(document)

    assert parsed["/system/lib/libft2.so"] == {"FTL"}
    assert parsed["/system/lib/libfoo.so"] == {"Apache-2.0"}
    assert parsed["/system/lib/libbar.so"] == {"Apache-2.0"}
    assert "/system/lib/libunknown.so" not in parsed


def test_notice_license_attribution_handles_system_root_alias_without_overwriting():
    from firmware_scanner.android.notice_licenses import apply_notice_licenses

    freetype = Component(
        name="libft2.so",
        properties=[
            {
                "name": "firmware:evidence:location",
                "value": "/lib/libft2.so",
            }
        ],
    )
    explicit = Component(
        name="libfoo.so",
        licenses=["MIT"],
        properties=[
            {
                "name": "firmware:evidence:location",
                "value": "/lib/libfoo.so",
            }
        ],
    )

    stats = apply_notice_licenses(
        [freetype, explicit],
        {
            "/system/lib/libft2.so": {"FTL"},
            "/system/lib/libfoo.so": {"Apache-2.0"},
        },
        source="NOTICE.html.gz",
    )

    assert freetype.licenses == ["FTL"]
    assert explicit.licenses == ["MIT"]
    assert {
        "name": "firmware:license:evidence",
        "value": "NOTICE.html.gz:/system/lib/libft2.so",
    } in freetype.properties
    assert stats == {
        "notice_files_matched": 2,
        "components_licensed": 1,
        "existing_licenses_preserved": 1,
    }
