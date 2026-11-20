"""Version reporting must follow the current source checkout."""

import importlib.util
import re
import shutil
import subprocess
import sys
from pathlib import Path


def test_source_checkout_version_matches_pyproject():
    import firmware_scanner

    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    match = re.search(r'^version = "([^"]+)"$', pyproject.read_text(), re.MULTILINE)

    assert match is not None
    assert firmware_scanner.__version__ == match.group(1)


def test_frozen_source_bundle_uses_its_bundled_pyproject_version(tmp_path):
    repo = Path(__file__).resolve().parents[2]
    package = tmp_path / "source" / "firmware_scanner"
    package.mkdir(parents=True)
    shutil.copy2(repo / "src" / "firmware_scanner" / "__init__.py", package / "__init__.py")
    (tmp_path / "source" / "pyproject.toml").write_text(
        '[project]\nversion = "9.8.7"\n',
        encoding="utf-8",
    )

    spec = importlib.util.spec_from_file_location(
        "frozen_firmware_scanner_version",
        package / "__init__.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module._source_checkout_version() == "9.8.7"


def test_scan_reproduction_bundle_includes_version_metadata(tmp_path):
    repo = Path(__file__).resolve().parents[2]
    image = tmp_path / "invalid.img"
    image.write_bytes(b"\0" * 4096)
    output = tmp_path / "scan"

    result = subprocess.run(
        [
            sys.executable,
            str(repo / "experiments" / "version_coverage" / "run_scan.py"),
            str(image),
            str(output),
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    bundled_pyproject = output / "source" / "pyproject.toml"
    assert bundled_pyproject.read_bytes() == (repo / "pyproject.toml").read_bytes()
