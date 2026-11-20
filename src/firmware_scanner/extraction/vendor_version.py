"""Conservative, file-owned vendor build identifiers from Android native files."""
from __future__ import annotations

import json
import re
import struct

from capstone import CsError
from elftools.common.exceptions import ELFError

from .binary_reference import BinaryReferenceMatcher
from .semantic_version import ELFView, SemanticVersionExtractor
from .static_version import StaticVersionExtractor, StaticVersionMatch

_PVR_SOURCE = 'https://android.googlesource.com/kernel/x86_64/+/8ac3b7cbf14fa5d328213b1592efce6ae16f1167/drivers/staging/imgtec/pvrversion.h'
_PVR_BUILD = re.compile(rb'(?:OpenGL ES(?: GLSL ES)? [0-9.]+|1\.4) build (\d+\.\d+(?:\.\d+)*@\d+)(?=\x00|\s)')


def _returned_text(image, name):
    function = image.functions.get(name)
    if function is None or not 0 < function[1] <= 128:
        return None
    instructions = image.instructions(*function)
    if image.machine == 'EM_ARM':
        pointer = SemanticVersionExtractor._arm_return(image, instructions, bool(function[0] & 1))
    elif image.machine in ('EM_X86_64', 'EM_AARCH64'):
        extractor = (StaticVersionExtractor._x86_64_pointer if image.machine == 'EM_X86_64'
                     else StaticVersionExtractor._aarch64_pointer)
        result = extractor(instructions)
        if result is None or result[1]:
            return None
        pointer = result[0]
    else:
        return None
    text = image.c_string(pointer) if pointer is not None else None
    return (text, function, instructions) if text is not None else None


def extract_vendor_versions(data: bytes, filename: str) -> list[StaticVersionMatch]:
    """Require the vendor artifact identity in addition to a version observation.

    PowerVR records the DDK build after ``build``; EGL/GL language versions are
    separate interface fields. Widevine requires two agreeing defined getters,
    including their statically proven returned strings, rather than a loose banner.
    """
    if not isinstance(data, bytes) or not data.startswith(b'\x7fELF'):
        return []
    filename = filename.rsplit('/', 1)[-1]
    if filename == 'libIMGegl.so' or re.fullmatch(r'libGLESv2_POWERVR_[A-Za-z0-9_]+\.so', filename):
        if b'Imagination Technologies' not in data:
            return []
        symbols = BinaryReferenceMatcher._defined_elf_symbols(data)
        required = ({'IMGeglQueryString', 'IMGeglGetProcAddress'} if filename == 'libIMGegl.so'
                    else {'glGetString', 'glGetIntegerv'})
        if not required <= symbols:
            return []
        versions = {}
        for match in _PVR_BUILD.finditer(data):
            versions.setdefault(match.group(1).decode('ascii'), []).append({
                'offset': hex(match.start()), 'text': match.group(0).decode('ascii')})
        return [StaticVersionMatch(filename, version, json.dumps({
            'method': 'vendor-ddk-build-marker', 'vendor': 'Imagination Technologies PowerVR',
            'version_kind': 'vendor-build', 'markers': markers, 'defined_symbols': sorted(required),
            'source': _PVR_SOURCE,
        }, sort_keys=True), .96) for version, markers in sorted(versions.items())]

    if not re.fullmatch(r'libWVStreamControlAPI_L[123]\.so', filename):
        return []
    if b'WVGetVersion' not in data or b'WVGetBuild' not in data:
        return []
    try:
        image = ELFView(data)
        if not image.elf.little_endian:
            return []
        version_result = _returned_text(image, 'WVGetVersion')
        build_result = _returned_text(image, 'WVGetBuild')
        if version_result is None or build_result is None:
            return []
        text, function, instructions = version_result
        build, build_function, build_instructions = build_result
        banner = re.fullmatch(r'Version (\d+\.\d+\.\d+\.\d+)(?: [A-Za-z0-9_ .-]+)?\s*', text)
        if banner is None or banner.group(1) != build:
            return []
        evidence = {'method': 'two-agreeing-defined-vendor-getters', 'version_kind': 'vendor-build',
                    'vendor': 'Widevine', 'version_string': text, 'build_string': build,
                    'functions': [{'name': 'WVGetVersion', 'vaddr': hex(function[0]),
                                   'instructions': image.format_instructions(instructions)},
                                  {'name': 'WVGetBuild', 'vaddr': hex(build_function[0]),
                                   'instructions': image.format_instructions(build_instructions)}]}
        return [StaticVersionMatch(filename, build, json.dumps(evidence, sort_keys=True), .96)]
    except (ELFError, CsError, ValueError, TypeError, KeyError, IndexError, OSError, struct.error):
        return []
