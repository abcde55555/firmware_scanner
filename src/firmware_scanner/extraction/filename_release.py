"""Recover releases explicitly embedded in a binary's own filename."""

import re

_EXTENSION = r"(?:\.so|\.dylib|\.dll)"
_COMPONENT = r"(?P<component>lib[A-Za-z][A-Za-z0-9_+-]*?)"
_DOTTED_RELEASE = re.compile(
    rf"^{_COMPONENT}\.(?P<version>\d+(?:\.\d+)+){_EXTENSION}$",
    re.IGNORECASE,
)
_MARKED_RELEASE = re.compile(
    rf"^{_COMPONENT}[-_]v(?P<version>\d+(?:\.\d+)+){_EXTENSION}$",
    re.IGNORECASE,
)
_PLAIN_RELEASE = re.compile(
    rf"^{_COMPONENT}[-_](?P<version>\d+(?:\.\d+){{2,}}){_EXTENSION}$",
    re.IGNORECASE,
)
_TWO_PART_DOTTED_RELEASES = {"libchrome"}
_SONAME_FULL_RELEASE = re.compile(
    r"^(?P<component>lib[A-Za-z][A-Za-z0-9_+-]*?)"
    r"\.so\.(?P<version>\d+(?:\.\d+)+)$",
    re.IGNORECASE,
)
_SONAME_RELEASE_COMPONENTS = {
    "libcjson",
    "libfmt",
    "libhwy",
    "libjsoncpp",
    "libpugixml",
    "libspdlog",
    "libtinyxml2",
    "libyaml-cpp",
}
_PLAIN_TWO_PART_RELEASES = {"libelf"}
_NON_PRODUCT_MARKER = re.compile(
    r"(?:^|[_-])(?:abi|aidl|api|hal|hidl)(?:[_-]|$)", re.IGNORECASE
)


def extract_filename_release(filename: str) -> tuple[str, str, str] | None:
    """Return a component's own filename release, if the basename states one.

    Only release-like versions that are part of a library's basename are
    accepted. ELF SONAME suffixes (``.so.N``) and Android interface markers
    (``@N.N`` and ``-VN``) do not satisfy these anchored filename forms.
    """
    if not filename:
        return None

    basename = filename.rsplit("/", 1)[-1]
    match = _MARKED_RELEASE.fullmatch(basename) or _PLAIN_RELEASE.fullmatch(basename)
    if match is None:
        plain_two_part = re.fullmatch(
            rf"(?P<component>lib[A-Za-z][A-Za-z0-9_+-]*?)[-_]v?"
            rf"(?P<version>\d+\.\d+){_EXTENSION}",
            basename,
            re.IGNORECASE,
        )
        if (
            plain_two_part is not None
            and plain_two_part.group("component").lower() in _PLAIN_TWO_PART_RELEASES
        ):
            match = plain_two_part
    if match is None:
        match = _DOTTED_RELEASE.fullmatch(basename)
        if (
            match is not None
            and match.group("version").count(".") < 2
            and match.group("component").lower() not in _TWO_PART_DOTTED_RELEASES
        ):
            return None
    if match is None:
        soname = _SONAME_FULL_RELEASE.fullmatch(basename)
        if (
            soname is not None
            and soname.group("component").lower() in _SONAME_RELEASE_COMPONENTS
        ):
            match = soname
    if match is None:
        return None

    component = match.group("component")
    if _NON_PRODUCT_MARKER.search(component):
        return None

    release = match.group("version")
    return component, release, f"filename release: {basename}"
