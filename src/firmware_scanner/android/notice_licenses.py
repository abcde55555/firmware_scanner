"""Conservative SPDX license attribution from Android NOTICE HTML."""

from __future__ import annotations

import re
from html.parser import HTMLParser

from ..extraction.models import Component

_PATH_RE = re.compile(r"(?<!\S)(/[^\s<>]+)")
_SPACE_RE = re.compile(r"\s+")


def _normalise_text(value: str) -> str:
    return _SPACE_RE.sub(" ", value).strip().casefold()


def _detect_licenses(text: str) -> set[str]:
    value = _normalise_text(text)
    licenses: set[str] = set()
    if "the freetype project license" in value:
        licenses.add("FTL")
    if "apache license version 2.0" in value or (
        "apache license" in value and "version 2.0, january 2004" in value
    ):
        licenses.add("Apache-2.0")
    if (
        "redistribution and use in source and binary forms" in value
        and "this software is provided" in value
    ):
        licenses.add("BSD-3-Clause" if "neither the name" in value else "BSD-2-Clause")
    if (
        "permission is hereby granted, free of charge, to any person obtaining a copy" in value
        and "the software is provided" in value
    ):
        licenses.add("MIT")
    if (
        "permission to use, copy, modify, and/or distribute this software" in value
        and "with or without fee is hereby granted" in value
    ):
        licenses.add("ISC")
    if (
        "origin of this software must not be misrepresented" in value
        and "altered source versions must be plainly marked" in value
    ):
        licenses.add("Zlib")
    if "openssl license" in value and "eric young" in value:
        licenses.add("OpenSSL")
    return licenses


class _NoticeHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.result: dict[str, set[str]] = {}
        self._in_row = False
        self._in_file_list = False
        self._in_license = False
        self._files: list[str] = []
        self._license_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        attributes = dict(attrs)
        if tag == "tr":
            self._in_row = True
            self._files = []
            self._license_parts = []
        elif (
            self._in_row and tag == "div" and "file-list" in (attributes.get("class") or "").split()
        ):
            self._in_file_list = True
        elif (
            self._in_row
            and tag == "pre"
            and "license-text" in (attributes.get("class") or "").split()
        ):
            self._in_license = True
        elif self._in_file_list and tag == "br":
            self._files.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag == "div":
            self._in_file_list = False
        elif tag == "pre":
            self._in_license = False
        elif tag == "tr" and self._in_row:
            licenses = _detect_licenses(" ".join(self._license_parts))
            if licenses:
                for match in _PATH_RE.finditer("".join(self._files)):
                    self.result.setdefault(match.group(1), set()).update(licenses)
            self._in_row = False
            self._in_file_list = False
            self._in_license = False

    def handle_data(self, data: str) -> None:
        if self._in_file_list:
            self._files.append(data)
        if self._in_license:
            self._license_parts.append(data)


def parse_notice_licenses(data: bytes) -> dict[str, set[str]]:
    """Return SPDX IDs only for files in NOTICE rows with strong license markers."""
    if not isinstance(data, bytes):
        return {}
    parser = _NoticeHTMLParser()
    try:
        parser.feed(data.decode("utf-8", errors="replace"))
        parser.close()
    except (ValueError, AssertionError):
        return {}
    return parser.result


def _locations(component: Component) -> set[str]:
    return {
        str(prop.get("value", ""))
        for prop in component.properties
        if prop.get("name") == "firmware:evidence:location" and prop.get("value")
    }


def _notice_aliases(path: str) -> tuple[str, ...]:
    aliases = [path]
    if path.startswith("/system/"):
        aliases.append(path.removeprefix("/system"))
    return tuple(aliases)


def apply_notice_licenses(
    components: list[Component],
    attributions: dict[str, set[str]],
    *,
    source: str,
) -> dict[str, int]:
    """Fill missing component licenses from image-local NOTICE evidence."""
    lookup: dict[str, tuple[str, set[str]]] = {}
    for path, licenses in attributions.items():
        for alias in _notice_aliases(path):
            lookup[alias] = (path, set(licenses))

    matched = licensed = preserved = 0
    for component in components:
        binds = [
            lookup[location] for location in sorted(_locations(component)) if location in lookup
        ]
        if not binds:
            continue
        matched += 1
        if component.licenses:
            preserved += 1
            continue
        licenses = sorted({license for _, values in binds for license in values})
        if not licenses:
            continue
        component.licenses = licenses
        licensed += 1
        component.properties.append(
            {
                "name": "firmware:license:evidence",
                "value": f"{source}:{binds[0][0]}",
            }
        )
        component.properties.append(
            {
                "name": "firmware:license:match-confidence",
                "value": "0.95",
            }
        )
    return {
        "notice_files_matched": matched,
        "components_licensed": licensed,
        "existing_licenses_preserved": preserved,
    }
