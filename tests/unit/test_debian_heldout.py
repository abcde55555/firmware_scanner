"""Debian held-out truth normalization and identity aliases."""


def test_debian_package_versions_normalize_to_upstream_releases():
    from experiments.version_coverage.debian_heldout import normalize_upstream_version

    assert normalize_upstream_version("libpng16-16t64", "1.6.55-1") == "1.6.55"
    assert normalize_upstream_version("libssl3t64", "3.6.3-1") == "3.6.3"
    assert normalize_upstream_version("libjpeg62-turbo", "1:3.1.3-4") == "3.1.3"
    assert normalize_upstream_version("zlib1g", "1:1.3.dfsg+really1.3.1-3") == "1.3.1"
    assert normalize_upstream_version(
        "libevent-2.1-7t64",
        "2.1.12-stable-10+b2",
    ) == "2.1.12-stable"


def test_heldout_catalog_uses_explicit_upstream_aliases():
    from experiments.version_coverage.debian_heldout import CATALOG

    pcre2 = next(item for item in CATALOG if item.package == "libpcre2-8-0")
    openssl = next(item for item in CATALOG if item.package == "libssl3t64")
    opus = next(item for item in CATALOG if item.package == "libopus0")

    assert len(CATALOG) >= 50
    assert pcre2.library == "libpcre2-8.so.0"
    assert "pcre2" in pcre2.aliases
    assert openssl.library == "libcrypto.so.3"
    assert {"openssl", "libcrypto"} <= set(openssl.aliases)
    assert opus.library == "libopus.so.0"


def test_independent_catalog_remains_a_separate_twenty_library_suite():
    from experiments.version_coverage.debian_heldout import INDEPENDENT_CATALOG

    assert len(INDEPENDENT_CATALOG) == 20
    assert len({item.library for item in INDEPENDENT_CATALOG}) == 20
