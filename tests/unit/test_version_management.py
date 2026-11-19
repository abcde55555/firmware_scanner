"""Version reporting must follow the current source checkout."""

import re
from pathlib import Path


def test_source_checkout_version_matches_pyproject():
    import firmware_scanner

    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    match = re.search(r'^version = "([^"]+)"$', pyproject.read_text(), re.MULTILINE)

    assert match is not None
    assert firmware_scanner.__version__ == match.group(1)
