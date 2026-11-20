"""Reference source extraction cannot write outside its assigned directory."""
import importlib.util
import io
import tarfile
from pathlib import Path

import pytest


def _unpack(monkeypatch):
    root = Path(__file__).resolve().parents[2] / "experiments/version_coverage"
    monkeypatch.syspath_prepend(str(root))
    spec = importlib.util.spec_from_file_location("build_rust_refs", root / "build_rust_location_refs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.unpack_source


def _archive(tmp_path, name, *, symlink=False):
    path = tmp_path / "source.crate"
    with tarfile.open(path, "w:gz") as archive:
        item = tarfile.TarInfo(name)
        if symlink:
            item.type = tarfile.SYMTYPE
            item.linkname = "../../escaped"
            archive.addfile(item)
        else:
            item.size = 6
            archive.addfile(item, io.BytesIO(b"source"))
    return path


def test_only_expected_distribution_root_is_written(tmp_path, monkeypatch):
    output = tmp_path / "output"
    _unpack(monkeypatch)(_archive(tmp_path, "example-1.0.0/src/lib.rs"), output, "example-1.0.0")
    assert (output / "src/lib.rs").read_bytes() == b"source"


@pytest.mark.parametrize("name,symlink", [
    ("example-1.0.0/../escaped", False),
    ("different-1.0.0/src/lib.rs", False),
    ("/example-1.0.0/src/lib.rs", False),
    ("example-1.0.0/src/link.rs", True),
])
def test_archive_cannot_escape_or_install_symlinks(tmp_path, monkeypatch, name, symlink):
    output = tmp_path / "output"
    with pytest.raises(ValueError):
        _unpack(monkeypatch)(_archive(tmp_path, name, symlink=symlink), output, "example-1.0.0")
    assert not (tmp_path / "escaped").exists()
    assert not list(output.rglob("*"))
