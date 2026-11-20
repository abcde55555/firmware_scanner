"""Debian held-out truth normalization and identity aliases."""

import subprocess
from pathlib import Path


def test_debian_package_versions_normalize_to_upstream_releases():
    from experiments.version_coverage.debian_heldout import normalize_upstream_version

    assert normalize_upstream_version("libpng16-16t64", "1.6.55-1") == "1.6.55"
    assert normalize_upstream_version("libssl3t64", "3.6.3-1") == "3.6.3"
    assert normalize_upstream_version("libjpeg62-turbo", "1:3.1.3-4") == "3.1.3"
    assert normalize_upstream_version("zlib1g", "1:1.3.dfsg+really1.3.1-3") == "1.3.1"
    assert (
        normalize_upstream_version(
            "libevent-2.1-7t64",
            "2.1.12-stable-10+b2",
        )
        == "2.1.12-stable"
    )


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


def test_second_independent_catalog_is_disjoint_and_has_twenty_libraries():
    from experiments.version_coverage.debian_heldout import (
        CATALOG,
        INDEPENDENT_2_CATALOG,
        INDEPENDENT_CATALOG,
    )

    second = {item.library for item in INDEPENDENT_2_CATALOG}
    existing = {item.library for item in (*CATALOG, *INDEPENDENT_CATALOG)}
    assert len(INDEPENDENT_2_CATALOG) == 20
    assert len(second) == 20
    assert second.isdisjoint(existing)


def test_fifth_independent_catalog_is_disjoint_and_has_twenty_libraries():
    from experiments.version_coverage.debian_heldout import (
        CATALOG,
        INDEPENDENT_2_CATALOG,
        INDEPENDENT_5_CATALOG,
        INDEPENDENT_CATALOG,
    )

    fifth = {item.library for item in INDEPENDENT_5_CATALOG}
    existing = {
        item.library
        for item in (*CATALOG, *INDEPENDENT_CATALOG, *INDEPENDENT_2_CATALOG)
    }
    assert len(INDEPENDENT_5_CATALOG) == 20
    assert len(fifth) == 20
    assert fifth.isdisjoint(existing)


def test_heldout_run_provenance_binds_rules_and_source_hashes():
    from experiments.version_coverage.debian_heldout import _run_provenance

    provenance = _run_provenance()

    assert len(provenance["git_head"]) == 40
    assert provenance["rules_release"] == "builtin-2026.11.20.7"
    assert len(provenance["rules_lock_sha256"]) == 64
    assert {
        "src/firmware_scanner/extraction/static_version.py",
        "src/firmware_scanner/extraction/semantic_version.py",
        "src/firmware_scanner/extraction/public_version.py",
        "src/firmware_scanner/extraction/filename_release.py",
        "src/firmware_scanner/data/rules.lock.json",
    }.issubset(provenance["source_sha256"])


def test_sixth_independent_catalog_is_disjoint_and_has_twenty_libraries():
    from experiments.version_coverage.debian_heldout import (
        CATALOG,
        INDEPENDENT_2_CATALOG,
        INDEPENDENT_5_CATALOG,
        INDEPENDENT_6_CATALOG,
        INDEPENDENT_CATALOG,
    )

    sixth = {item.library for item in INDEPENDENT_6_CATALOG}
    existing = {
        item.library
        for item in (
            *CATALOG,
            *INDEPENDENT_CATALOG,
            *INDEPENDENT_2_CATALOG,
            *INDEPENDENT_5_CATALOG,
        )
    }
    assert len(INDEPENDENT_6_CATALOG) == 20
    assert len(sixth) == 20
    assert sixth.isdisjoint(existing)


def test_heldout_adjacent_versions_are_separate_from_wrong_estimates():
    from experiments.version_coverage.debian_heldout import _adjacent, _classify_outcome

    assert _adjacent("5.46", "5.47")
    assert not _adjacent("5.45", "5.47")
    assert not _adjacent("5.46", "6.47")
    assert _classify_outcome(set(), {"5.46"}, "5.47") == "adjacent"
    assert _classify_outcome({"4.0"}, {"5.0"}, "5.0") == "wrong"
    assert _classify_outcome(set(), {"4.0", "5.0"}, "5.0") == "estimated"
    assert _classify_outcome(set(), {"4.0", "5.1"}, "5.0") == "wrong_estimate"


def test_path_ownership_requires_the_declared_package(monkeypatch):
    from experiments.version_coverage import debian_heldout

    def owned(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="libdemo:amd64: /usr/lib/libdemo.so\n",
            stderr="",
        )

    monkeypatch.setattr(debian_heldout.subprocess, "run", owned)
    assert debian_heldout._path_owned_by_package(Path("/usr/lib/libdemo.so"), "libdemo")
    assert not debian_heldout._path_owned_by_package(
        Path("/usr/lib/libdemo.so"),
        "libdifferent",
    )
