from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import tarfile
from pathlib import Path
from urllib.error import URLError

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "experiments/version_coverage/collect_rust_sources.py"
TEST_PIN = "a" * 40


def _module():
    spec = importlib.util.spec_from_file_location("collect_rust_sources", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tar(crate: str, version: str, files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(f"{crate}-{version}/{name}")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def test_selects_pin_and_nearest_stable_versions_across_minor_boundaries():
    mod = _module()
    records = [
        {"vers": v, "cksum": "a" * 64, "yanked": False}
        for v in ("1.0.0", "1.0.2", "1.1.0", "1.2.0", "2.0.0", "2.1.0-alpha.1")
    ]
    assert mod.select_versions(records, "1.1.0", radius=2) == [
        ("1.0.0", "a" * 64), ("1.0.2", "a" * 64),
        ("1.1.0", "a" * 64), ("1.2.0", "a" * 64), ("2.0.0", "a" * 64),
    ]


def test_sparse_index_url_preserves_official_underscore_spelling():
    mod = _module()
    assert mod.sparse_index_path("serde_json") == "se/rd/serde_json"
    assert mod.sparse_index_url("serde_json") == "https://index.crates.io/se/rd/serde_json"
    assert mod.normalize_package_name("serde_json") == mod.normalize_package_name("serde-json")


@pytest.mark.parametrize("pin", ["pin", "a" * 39, "g" * 40])
def test_manifest_url_rejects_non_commit_pins(pin):
    with pytest.raises(ValueError, match="40-character Git commit"):
        _module().android_manifest_url("sample-crate", pin)


def test_archive_reader_returns_only_requested_regular_files_and_rejects_unsafe_members():
    mod = _module()
    good = _tar("sample-crate", "1.2.3", {
        "src/lib.rs": b"upstream source\n",
        "src/unused.rs": b"not requested",
    })
    assert mod.read_archive_sources(good, "sample-crate", "1.2.3", {"src/lib.rs"}) == {
        "src/lib.rs": b"upstream source\n",
    }

    for member in ("/src/lib.rs", "../escape.rs", "src/../escape.rs"):
        bad = _tar("sample-crate", "1.2.3", {member: b"unsafe"})
        with pytest.raises(ValueError, match="unsafe archive path"):
            mod.read_archive_sources(bad, "sample-crate", "1.2.3", {member})

    link = io.BytesIO()
    with tarfile.open(fileobj=link, mode="w:gz") as archive:
        info = tarfile.TarInfo("sample-crate-1.2.3/src/lib.rs")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../outside"
        archive.addfile(info)
    with pytest.raises(ValueError, match="non-regular archive member"):
        mod.read_archive_sources(link.getvalue(), "sample-crate", "1.2.3", {"src/lib.rs"})


def test_cached_archive_is_rehashed_and_corrupt_entry_is_removed(tmp_path):
    mod = _module()
    path = tmp_path / "cached.crate"
    valid = b"verified archive bytes"
    path.write_bytes(valid)
    assert mod._cache_archive(path, hashlib.sha256(valid).hexdigest()) == valid
    path.write_bytes(b"corrupt cached bytes")
    assert mod._cache_archive(path, hashlib.sha256(valid).hexdigest()) is None
    assert not path.exists()


def test_collects_sources_only_after_official_checksum_matches_and_records_provenance(tmp_path, monkeypatch):
    mod = _module()
    manifest = base64.b64encode(b'[package]\nname = "sample-crate"\nversion = "1.1.0"\n')
    source_files = {"src/lib.rs": b"line one\nline two\n"}
    archives = {
        "1.0.0": _tar("sample-crate", "1.0.0", source_files),
        "1.1.0": _tar("sample-crate", "1.1.0", source_files),
        "1.2.0": _tar("sample-crate", "1.2.0", source_files),
    }
    index = b"".join(
        json.dumps({"name": "sample-crate", "vers": v,
                    "cksum": hashlib.sha256(archives[v]).hexdigest(), "yanked": False}).encode() + b"\n"
        for v in archives
    )
    replies = {
        "https://android.googlesource.com/platform/external/rust/android-crates-io/+/c991cad10330f37e93d82926bd6dae7f4f6647f6/crates/sample-crate/Cargo.toml?format=TEXT": manifest,
        "https://index.crates.io/sa/mp/sample-crate": index,
        "https://android.googlesource.com/platform/external/rust/android-crates-io/+/c991cad10330f37e93d82926bd6dae7f4f6647f6/crates/sample-crate/src/lib.rs?format=TEXT": base64.b64encode(source_files["src/lib.rs"]),
    }
    replies.update({
        f"https://static.crates.io/crates/sample-crate/sample-crate-{v}.crate": body
        for v, body in archives.items()
    })
    requested = []

    class Response:
        def __init__(self, data):
            self.data = data

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self, size=-1):
            if size < 0:
                return self.data
            return self.data[:size]

    def urlopen(request, timeout):
        url = request.full_url
        requested.append(url)
        if url not in replies:
            raise URLError(f"unexpected URL {url}")
        return Response(replies[url])

    monkeypatch.setattr(mod.urllib.request, "urlopen", urlopen)
    locations_json = tmp_path / "locations.json"
    locations_json.write_text(json.dumps({"rows": [
        {"locations": [{"crate": "sample-crate", "source_file": "src/lib.rs", "code_references": [{"vaddr": "0x1"}]}]}
    ]}))
    result = mod.collect(locations_json, ["sample-crate"], tmp_path / "out", radius=1,
                         pin="c991cad10330f37e93d82926bd6dae7f4f6647f6")
    crate = result["crates"][0]
    assert result["warning"] == "reference candidates, not binary exact versions"
    assert crate["declared_version"] == "1.1.0"
    assert {row["version"] for row in crate["versions"]} == {"1.0.0", "1.1.0", "1.2.0"}
    assert all(not row["errors"] and row["files"]["src/lib.rs"]["sha256"] == hashlib.sha256(source_files["src/lib.rs"]).hexdigest()
               for row in crate["versions"])
    assert crate["pinned_files"]["src/lib.rs"]["path"]
    assert len(requested) == 6
    output_dir = tmp_path / "out"
    cached_archive = output_dir / ".cache/crates/sample-crate-1.1.0.crate"
    cached_archive.write_bytes(b"corrupt archive cache")
    pinned_path = output_dir / crate["pinned_files"]["src/lib.rs"]["path"]
    pinned_path.write_bytes(b"corrupt pinned source")
    release_path = output_dir / crate["versions"][1]["files"]["src/lib.rs"]["path"]
    release_path.write_bytes(b"corrupt extracted source")

    resumed = mod.collect(locations_json, ["sample-crate"], output_dir, radius=0,
                          pin="c991cad10330f37e93d82926bd6dae7f4f6647f6")
    resumed_crate = resumed["crates"][0]
    assert [row["version"] for row in resumed_crate["versions"]] == ["1.1.0"]
    assert len(requested) == 10  # manifest, index, pinned source, and invalidated archive
    assert requested[6:] == [
        mod.android_manifest_url("sample-crate", "c991cad10330f37e93d82926bd6dae7f4f6647f6"),
        mod.sparse_index_url("sample-crate"),
        mod.android_source_url("sample-crate", "c991cad10330f37e93d82926bd6dae7f4f6647f6", "src/lib.rs"),
        "https://static.crates.io/crates/sample-crate/sample-crate-1.1.0.crate",
    ]
    assert hashlib.sha256(cached_archive.read_bytes()).hexdigest() == hashlib.sha256(archives["1.1.0"]).hexdigest()
    assert pinned_path.read_bytes() == source_files["src/lib.rs"]
    assert hashlib.sha256(pinned_path.read_bytes()).hexdigest() == resumed_crate["pinned_files"]["src/lib.rs"]["sha256"]
    resumed_file = output_dir / resumed_crate["versions"][0]["files"]["src/lib.rs"]["path"]
    assert resumed_file.read_bytes() == source_files["src/lib.rs"]
    assert hashlib.sha256(resumed_file.read_bytes()).hexdigest() == resumed_crate["versions"][0]["files"]["src/lib.rs"]["sha256"]


def test_network_error_is_explicit_and_retried(tmp_path, monkeypatch):
    mod = _module()
    manifest_url = mod.android_manifest_url("sample-crate", TEST_PIN)
    index_url = mod.sparse_index_url("sample-crate")
    calls = []

    class Response:
        def __init__(self, data): self.data = data
        def __enter__(self): return self
        def __exit__(self, *_): return False
        def read(self, size=-1): return self.data[:size]

    def urlopen(request, timeout):
        calls.append(request.full_url)
        if request.full_url == manifest_url:
            return Response(base64.b64encode(b'[package]\nname="sample-crate"\nversion="1.0.0"\n'))
        if request.full_url == index_url:
            return Response(b'{"name":"sample-crate","vers":"1.0.0","cksum":"' + b"a" * 64 + b'","yanked":false}\n')
        raise URLError("offline")

    monkeypatch.setattr(mod.urllib.request, "urlopen", urlopen)
    result = mod.collect_from_locations({"sample-crate": {"src/lib.rs"}}, ["sample-crate"],
                                        tmp_path, radius=0, pin=TEST_PIN, retries=2, retry_delay=0)
    crate = result["crates"][0]
    assert len(crate["versions"]) == 1
    assert len(calls) == 6  # manifest, index, two failed pinned-source attempts, two archive attempts
    assert "network" in crate["versions"][0]["errors"][0].lower()


def test_registry_absence_never_guesses_a_version():
    mod = _module()
    assert mod.select_versions([
        {"vers": "1.0.0", "cksum": "a" * 64, "yanked": False},
    ], "9.9.9", radius=2) == []
