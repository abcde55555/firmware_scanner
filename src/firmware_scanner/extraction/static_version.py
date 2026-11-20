"""Conservative static extraction from known version getter functions in ELF files.

This module never loads or executes firmware code. It follows only a small set of
straight-line return-pointer instruction sequences and rejects everything else.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from io import BytesIO

from capstone import (
    CS_ARCH_ARM,
    CS_ARCH_ARM64,
    CS_ARCH_X86,
    CS_MODE_64,
    CS_MODE_ARM,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_THUMB,
    Cs,
    CsError,
)
from capstone.arm import (
    ARM_INS_ADD,
    ARM_INS_BX,
    ARM_INS_LDR,
    ARM_INS_MOV,
    ARM_OP_IMM,
    ARM_OP_MEM,
    ARM_OP_REG,
)
from capstone.arm64 import (
    ARM64_INS_ADD,
    ARM64_INS_ADR,
    ARM64_INS_ADRP,
    ARM64_INS_LDR,
    ARM64_INS_MOV,
    ARM64_INS_MOVZ,
    ARM64_INS_RET,
    ARM64_OP_IMM,
    ARM64_OP_REG,
)
from capstone.x86 import (
    X86_INS_ENDBR64,
    X86_INS_LEA,
    X86_INS_MOV,
    X86_INS_NOP,
    X86_INS_RET,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
)
from elftools.elf.constants import P_FLAGS
from elftools.elf.gnuversions import GNUVerDefSection

try:
    from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
except ImportError:  # pyelftools is optional in the existing project dependency set.
    ELFError = Exception
    ELFFile = None
    SymbolTableSection = ()


@dataclass(frozen=True)
class StaticVersionMatch:
    name: str
    version: str
    evidence: str
    confidence: float = 0.95


_GETTERS: dict[str, tuple[str, str]] = {
    "LZ4_versionString": ("LZ4", "direct"),
    "ZSTD_versionString": ("zstd", "direct"),
    "hb_version_string": ("HarfBuzz", "direct"),
    "sqlite3_libversion": ("SQLite", "direct"),
    "pcap_lib_version": ("libpcap", "prefixed"),
    "cJSON_Version": ("cJSON", "direct"),
    "uv_version_string": ("libuv", "direct"),
    "opus_get_version_string": ("Opus", "prefixed"),
    "vpx_codec_version_str": ("libvpx", "vpx"),
    "event_get_version": ("libevent", "direct"),
    "libbpf_version_string": ("libbpf", "libbpf_generation"),
    "dav1d_version": ("dav1d", "direct"),
    "opj_version": ("OpenJPEG", "direct"),
    "heif_get_version": ("libheif", "direct"),
    "avifVersion": ("libavif", "direct"),
    "sf_version_string": ("libsndfile", "prefixed"),
    "src_get_version": ("libsamplerate", "prefixed"),
    "soxr_version": ("libsoxr", "prefixed"),
    "yaml_get_version_string": ("libyaml", "direct"),
    "lzo_version_string": ("liblzo2", "direct"),
    "_lzo_version_string": ("liblzo2", "direct"),
    "zip_libzip_version": ("libzip", "direct"),
    "aom_codec_version_str": ("libaom", "leading_v"),
    "pango_version_string": ("Pango", "direct"),
    "cairo_version_string": ("Cairo", "direct"),
    "pixman_version_string": ("Pixman", "direct"),
    "psl_get_version": ("libpsl", "leading"),
    "lzma_version_string": ("XZ Utils", "direct"),
    "BZ2_bzlibVersion": ("bzip2", "bz2"),
    "ffi_get_version": ("libffi", "direct"),
    "fuse_pkgversion": ("libfuse", "direct"),
    "archive_version_string": ("libarchive", "prefixed"),
    "json_c_version": ("json-c", "direct"),
    "srtp_get_version_string": ("libsrtp", "prefixed"),
    "atk_get_version": ("ATK", "direct"),
    "jansson_version_str": ("Jansson", "direct"),
    "MMDB_lib_version": ("libmaxminddb", "direct"),
    "orc_version_string": ("liborc", "direct"),
    "sodium_version_string": ("libsodium", "direct"),
    "NSS_GetVersion": ("NSS", "direct"),
    "PR_GetVersion": ("NSPR", "direct"),
    "nng_version": ("NNG", "direct"),
    "amqp_version": ("librabbitmq", "direct"),
    "QRcode_APIVersionString": ("libqrencode", "direct"),
    "sp_get_package_version_string": ("libserialport", "direct"),
    "mysql_get_client_info": ("libmariadb", "direct"),
    "mpfr_get_version": ("MPFR", "direct"),
    "mpc_get_version": ("MPC", "direct"),
    "Pa_GetVersionText": ("PortAudio", "portaudio"),
    "ffado_get_version": ("libffado", "prefixed"),
}
_INTEGER_GETTERS: dict[str, tuple[str, tuple[int, int, int], str]] = {
    "yajl_version": (
        "YAJL",
        (10000, 100, 1),
        "https://github.com/lloyd/yajl/blob/master/src/api/yajl_version.c",
    ),
}
_VERSION_DEFINITION_RULES: dict[
    str, tuple[str, str, frozenset[str], str]
] = {
    "LIBSEPOL_3.11": (
        "libsepol",
        "3.11",
        frozenset(
            {
                "cil_check_neverallows_against_pdb",
                "sepol_kernel_policydb_decls_to_cil",
            }
        ),
        "https://github.com/SELinuxProject/selinux/blob/3.11/libsepol/src/libsepol.map.in",
    ),
}
_SUPPORT_SYMBOLS = {
    "NSS_GetVersion": {"NSS_VersionCheck"},
    "PR_GetVersion": {"PR_VersionCheck"},
}
_VERSION = re.compile(r"v?(\d+\.\d+(?:\.\d+)*[A-Za-z0-9.+_-]*)\Z")


def _vaddr_to_offset(
    load_segments: list[tuple[int, int, int, int]],
    address: int,
    size: int,
    *,
    executable: bool = False,
    readonly: bool = False,
) -> int | None:
    """Map a VA only when the complete range is backed by bytes in a PT_LOAD."""
    for vaddr, offset, filesz, flags in load_segments:
        if executable and not flags & P_FLAGS.PF_X:
            continue
        if readonly and flags & P_FLAGS.PF_W:
            continue
        if vaddr <= address and address + size <= vaddr + filesz:
            return offset + (address - vaddr)
    return None


def _version_from_text(name: str, style: str, text: str) -> str | None:
    value = text.strip()
    if style == "portaudio":
        match = re.match(r"PortAudio\s+V(\d+\.\d+(?:\.\d+)*)(?:-devel)?(?:,|$)", value)
        return match.group(1) if match else None
    if style in {"vpx", "leading_v"}:
        # VERSION_STRING_NOSP starts with 'v'; the integer API encodes the
        # same release without it. Preserve all development/vendor suffixes.
        match = _VERSION.fullmatch(value)
        if match and value.startswith("v"):
            return match.group(1)
        return match.group(1) if style == "leading_v" and match else None
    if style == "libbpf_generation":
        match = re.fullmatch(r"v?(\d+\.\d+)", value)
        return f"{match.group(1)}.x" if match else None
    if style == "leading":
        match = re.match(r"v?(\d+\.\d+(?:\.\d+)*[A-Za-z0-9.+_-]*)", value)
        return match.group(1) if match else None
    if style == "bz2":
        match = re.match(r"(\d+\.\d+(?:\.\d+)*),\s+\d{1,2}-[A-Za-z]{3}-\d{4}", value)
        return match.group(1) if match else None
    if style == "prefixed":
        prefixes = {
            "libpcap": r"libpcap version\s+",
            "Opus": r"libopus\s+",
            "libsndfile": r"libsndfile-",
            "libsamplerate": r"libsamplerate-",
            "libsoxr": r"libsoxr-",
            "libarchive": r"libarchive\s+",
            "libsrtp": r"libsrtp2\s+",
            "libffado": r"libffado\s+",
        }
        prefix = prefixes[name]
        match = re.match(prefix + r"(v?\d+\.\d+(?:\.\d+)*[A-Za-z0-9.+_-]*)", value, re.IGNORECASE)
        return match.group(1) if match else None
    match = _VERSION.fullmatch(value)
    return match.group(0) if match else None


class StaticVersionExtractor:
    """Extract versions exposed by a known getter with a provable pointer return."""

    def extract(self, data: bytes) -> list[StaticVersionMatch]:
        if (
            ELFFile is None
            or not isinstance(data, bytes)
            or len(data) < 64
            or data[:4] != b"\x7fELF"
        ):
            return []
        getter_names = {*_GETTERS, *_INTEGER_GETTERS, *_VERSION_DEFINITION_RULES}
        if not any(name.encode("ascii") in data for name in getter_names):
            return []
        try:
            elf = ELFFile(BytesIO(data))
            machine = elf.header["e_machine"]
            if machine == "EM_AARCH64" and elf.elfclass == 64 and elf.little_endian:
                architecture = "aarch64"
                disassembler = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
                disassembler.detail = True
            elif machine == "EM_X86_64" and elf.elfclass == 64 and elf.little_endian:
                architecture = "x86_64"
                disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
                disassembler.detail = True
            elif machine == "EM_ARM" and elf.elfclass == 32 and elf.little_endian:
                architecture = "arm"
                disassembler = None
            else:
                return []

            load_segments = [
                (
                    int(segment["p_vaddr"]),
                    int(segment["p_offset"]),
                    int(segment["p_filesz"]),
                    int(segment["p_flags"]),
                )
                for segment in elf.iter_segments()
                if segment["p_type"] == "PT_LOAD"
            ]
            functions: dict[str, tuple[int, int, bool]] = {}
            defined_functions: set[str] = set()
            defined_versions: set[str] = set()
            version_definition = elf.get_section_by_name(".gnu.version_d")
            if isinstance(version_definition, GNUVerDefSection):
                for _version, auxiliaries in version_definition.iter_versions():
                    defined_versions.update(auxiliary.name for auxiliary in auxiliaries)
            for section in elf.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue
                for symbol in section.iter_symbols():
                    if symbol["st_info"]["type"] != "STT_FUNC":
                        continue
                    if not symbol["st_shndx"] or symbol["st_shndx"] == "SHN_UNDEF":
                        continue
                    defined_functions.add(symbol.name)
                    if symbol.name not in _GETTERS and symbol.name not in _INTEGER_GETTERS:
                        continue
                    address = int(symbol["st_value"])
                    size = int(symbol["st_size"])
                    if 0 <= size <= 256:
                        thumb = architecture == "arm" and bool(address & 1)
                        functions.setdefault(symbol.name, (address, size, thumb))

            matches: list[StaticVersionMatch] = []
            for version_name, (
                component,
                release,
                required_symbols,
                source,
            ) in _VERSION_DEFINITION_RULES.items():
                if (
                    version_name not in defined_versions
                    or not required_symbols.issubset(defined_functions)
                ):
                    continue
                matches.append(
                    StaticVersionMatch(
                        component,
                        release,
                        (
                            f"ELF version definition {version_name!r} and required "
                            f"symbols {sorted(required_symbols)} are present; source {source}"
                        ),
                        0.93,
                    )
                )
            for getter, (address, size, thumb) in functions.items():
                if not _SUPPORT_SYMBOLS.get(getter, set()).issubset(defined_functions):
                    continue
                if architecture == "arm":
                    mode = CS_MODE_THUMB if thumb else CS_MODE_ARM
                    function_disassembler = Cs(
                        CS_ARCH_ARM,
                        mode | CS_MODE_LITTLE_ENDIAN,
                    )
                    function_disassembler.detail = True
                    code_address = address & ~1
                else:
                    function_disassembler = disassembler
                    code_address = address
                requested_size = size or 4
                code_offset = _vaddr_to_offset(
                    load_segments,
                    code_address,
                    requested_size,
                    executable=True,
                )
                if code_offset is None or code_offset + requested_size > len(data):
                    continue
                if size:
                    code = data[code_offset : code_offset + size]
                else:
                    window = data[code_offset : min(len(data), code_offset + 64)]
                    instructions = list(function_disassembler.disasm(window, code_address))
                    terminal = next(
                        (
                            insn
                            for insn in instructions
                            if insn.id in (X86_INS_RET, ARM64_INS_RET, ARM_INS_BX)
                        ),
                        None,
                    )
                    if terminal is None:
                        continue
                    code = window[: terminal.address + terminal.size - code_address]
                if getter in _INTEGER_GETTERS:
                    component, weights, source = _INTEGER_GETTERS[getter]
                    encoded = self._returned_integer(
                        function_disassembler,
                        architecture,
                        code,
                        code_address,
                    )
                    if encoded is None or encoded < weights[0]:
                        continue
                    major, remainder = divmod(encoded, weights[0])
                    minor, patch = divmod(remainder, weights[1])
                    version = f"{major}.{minor}.{patch}"
                    evidence = (
                        f"defined function {getter} at VA 0x{address:x} returns "
                        f"encoded release integer {encoded}; straight-line "
                        f"{architecture} return path; source {source}"
                    )
                    matches.append(
                        StaticVersionMatch(component, version, evidence, 0.95)
                    )
                    continue
                component, style = _GETTERS[getter]
                result_pointer = self._returned_pointer(
                    function_disassembler,
                    architecture,
                    code,
                    code_address,
                )
                if result_pointer is None:
                    continue
                pointer, is_literal = result_pointer
                if is_literal:
                    pointer_size = 8 if architecture == "aarch64" else 4
                    literal_offset = _vaddr_to_offset(
                        load_segments,
                        pointer,
                        pointer_size,
                        readonly=True,
                    )
                    if literal_offset is None or literal_offset + pointer_size > len(data):
                        continue
                    pointer = int.from_bytes(
                        data[literal_offset : literal_offset + pointer_size], "little"
                    )
                text = self._read_c_string(data, load_segments, pointer)
                if text is None:
                    continue
                version = _version_from_text(component, style, text)
                if version is None:
                    continue
                string_offset = _vaddr_to_offset(
                    load_segments,
                    pointer,
                    len(text) + 1,
                    readonly=True,
                )
                if string_offset is None:
                    continue
                evidence = (
                    f"defined function {getter} at VA 0x{address:x} returns a pointer to "
                    f"NUL-terminated string at VA 0x{pointer:x} (file offset 0x{string_offset:x}): "
                    f"{text!r}; straight-line {architecture} return path"
                )
                confidence = 0.84 if style == "libbpf_generation" else 0.95
                matches.append(StaticVersionMatch(component, version, evidence, confidence))
            return matches
        except (
            ELFError,
            CsError,
            OSError,
            ValueError,
            TypeError,
            KeyError,
            IndexError,
            struct.error,
            OverflowError,
        ):
            return []

    @staticmethod
    def _returned_integer(
        disassembler: Cs,
        architecture: str,
        code: bytes,
        address: int,
    ) -> int | None:
        instructions = list(disassembler.disasm(code, address))
        if not instructions or sum(insn.size for insn in instructions) != len(code):
            return None
        value: int | None = None
        for index, insn in enumerate(instructions):
            operands = insn.operands
            if insn.id in (X86_INS_ENDBR64, X86_INS_NOP):
                continue
            if architecture == "x86_64":
                if (
                    insn.id == X86_INS_MOV
                    and value is None
                    and len(operands) == 2
                    and operands[0].type == X86_OP_REG
                    and insn.reg_name(operands[0].reg) == "eax"
                    and operands[1].type == X86_OP_IMM
                ):
                    value = int(operands[1].imm)
                    continue
                if (
                    insn.id == X86_INS_RET
                    and index == len(instructions) - 1
                    and value is not None
                ):
                    return value
                return None
            if architecture == "aarch64":
                if (
                    insn.id in (ARM64_INS_MOV, ARM64_INS_MOVZ)
                    and value is None
                    and len(operands) == 2
                    and operands[0].type == ARM64_OP_REG
                    and insn.reg_name(operands[0].reg) in {"w0", "x0"}
                    and operands[1].type == ARM64_OP_IMM
                ):
                    value = int(operands[1].imm)
                    continue
                if (
                    insn.id == ARM64_INS_RET
                    and index == len(instructions) - 1
                    and value is not None
                ):
                    return value
                return None
            if architecture == "arm":
                if (
                    insn.id == ARM_INS_MOV
                    and value is None
                    and len(operands) == 2
                    and operands[0].type == ARM_OP_REG
                    and insn.reg_name(operands[0].reg) == "r0"
                    and operands[1].type == ARM_OP_IMM
                ):
                    value = int(operands[1].imm)
                    continue
                if (
                    insn.id == ARM_INS_BX
                    and index == len(instructions) - 1
                    and value is not None
                    and len(operands) == 1
                    and operands[0].type == ARM_OP_REG
                    and insn.reg_name(operands[0].reg) == "lr"
                ):
                    return value
                return None
        return None

    @staticmethod
    def _read_c_string(
        data: bytes, load_segments: list[tuple[int, int, int, int]], address: int
    ) -> str | None:
        offset = _vaddr_to_offset(load_segments, address, 1, readonly=True)
        if offset is None:
            return None
        limit = min(len(data), offset + 4097)
        end = data.find(b"\0", offset, limit)
        if end < 0 or end == offset:
            return None
        raw = data[offset:end]
        if any(byte < 0x20 or byte > 0x7E for byte in raw):
            return None
        return raw.decode("ascii")

    @staticmethod
    def _returned_pointer(
        disassembler: Cs, architecture: str, code: bytes, address: int
    ) -> tuple[int, bool] | None:
        instructions = list(disassembler.disasm(code, address))
        if not instructions or sum(insn.size for insn in instructions) != len(code):
            return None

        if architecture == "aarch64":
            return StaticVersionExtractor._aarch64_pointer(instructions)
        if architecture == "arm":
            return StaticVersionExtractor._arm_pointer(instructions, code, address)
        return StaticVersionExtractor._x86_64_pointer(instructions)

    @staticmethod
    def _x86_64_pointer(instructions) -> tuple[int, bool] | None:
        pointer: int | None = None
        for index, insn in enumerate(instructions):
            if insn.id in (X86_INS_ENDBR64, X86_INS_NOP):
                continue
            if insn.id == X86_INS_LEA and pointer is None:
                operands = insn.operands
                if (
                    len(operands) != 2
                    or operands[0].type != X86_OP_REG
                    or insn.reg_name(operands[0].reg) != "rax"
                    or operands[1].type != X86_OP_MEM
                    or insn.reg_name(operands[1].mem.base) != "rip"
                    or operands[1].mem.index != 0
                    or operands[1].mem.scale != 1
                ):
                    return None
                pointer = insn.address + insn.size + int(operands[1].mem.disp)
                continue
            if insn.id == X86_INS_RET and index == len(instructions) - 1 and pointer is not None:
                return pointer, False
            return None
        return None

    @staticmethod
    def _aarch64_pointer(instructions) -> tuple[int, bool] | None:
        base: int | None = None
        pointer: int | None = None
        literal = False
        for index, insn in enumerate(instructions):
            operands = insn.operands
            if insn.id == ARM64_INS_RET:
                if index != len(instructions) - 1 or base is not None or pointer is None:
                    return None
                return pointer, literal
            if index == len(instructions) - 1:
                return None

            if insn.id == ARM64_INS_ADR and len(operands) == 2 and operands[0].type == ARM64_OP_REG:
                if (
                    insn.reg_name(operands[0].reg) != "x0"
                    or operands[1].type != ARM64_OP_IMM
                    or pointer is not None
                ):
                    return None
                pointer = int(operands[1].imm)
                continue
            if (
                insn.id == ARM64_INS_ADRP
                and len(operands) == 2
                and operands[0].type == ARM64_OP_REG
            ):
                if (
                    insn.reg_name(operands[0].reg) != "x0"
                    or operands[1].type != ARM64_OP_IMM
                    or pointer is not None
                ):
                    return None
                base = int(operands[1].imm)
                continue
            if insn.id == ARM64_INS_ADD and len(operands) >= 3:
                if (
                    operands[0].type != ARM64_OP_REG
                    or insn.reg_name(operands[0].reg) != "x0"
                    or operands[1].type != ARM64_OP_REG
                    or insn.reg_name(operands[1].reg) != "x0"
                    or operands[2].type != ARM64_OP_IMM
                    or base is None
                    or pointer is not None
                ):
                    return None
                pointer = base + int(operands[2].imm)
                base = None
                continue
            if insn.id == ARM64_INS_LDR and len(operands) == 2 and operands[0].type == ARM64_OP_REG:
                if (
                    insn.reg_name(operands[0].reg) != "x0"
                    or operands[1].type != ARM64_OP_IMM
                    or pointer is not None
                ):
                    return None
                # The literal is an address holding the pointer, not the string itself.
                pointer = int(operands[1].imm)
                literal = True
                continue
            return None
        return None

    @staticmethod
    def _arm_pointer(instructions, code: bytes, address: int) -> tuple[int, bool] | None:
        pointer: int | None = None
        pointer_from_literal = False
        for index, insn in enumerate(instructions):
            operands = insn.operands
            if insn.id == ARM_INS_BX:
                if (
                    pointer is None
                    or len(operands) != 1
                    or operands[0].type != ARM_OP_REG
                    or insn.reg_name(operands[0].reg) != "lr"
                ):
                    return None
                if pointer_from_literal:
                    literal_offset = pointer - address
                    if literal_offset < 0 or literal_offset + 4 > len(code):
                        return None
                    pointer = int.from_bytes(
                        code[literal_offset : literal_offset + 4],
                        "little",
                    )
                return pointer, False
            if insn.id == ARM_INS_LDR and pointer is None:
                if (
                    len(operands) != 2
                    or operands[0].type != ARM_OP_REG
                    or insn.reg_name(operands[0].reg) != "r0"
                    or operands[1].type != ARM_OP_MEM
                    or insn.reg_name(operands[1].mem.base) != "pc"
                ):
                    return None
                pc = (insn.address + 4) & ~3
                pointer = pc + int(operands[1].mem.disp)
                pointer_from_literal = True
                continue
            if insn.id == ARM_INS_ADD and pointer is not None:
                if (
                    len(operands) != 2
                    or operands[0].type != ARM_OP_REG
                    or insn.reg_name(operands[0].reg) != "r0"
                    or operands[1].type != ARM_OP_REG
                    or insn.reg_name(operands[1].reg) != "pc"
                ):
                    return None
                if pointer_from_literal:
                    literal_offset = pointer - address
                    if literal_offset < 0 or literal_offset + 4 > len(code):
                        return None
                    pointer = int.from_bytes(
                        code[literal_offset : literal_offset + 4],
                        "little",
                    )
                pointer += insn.address + 4
                pointer_from_literal = False
                continue
            return None
        return None
