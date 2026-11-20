"""Portable ELF32 controls. No fixture ELF is loaded or executed."""

import importlib
import json
import struct

import pytest

from firmware_scanner.extraction.semantic_version import VERIFY, VERSION_STRING, ELFView


def _module():
    return importlib.import_module("firmware_scanner.extraction.protobuf_version")


def _elf(code, *, arm=False, thumb=False, imported=False, plt=False, version=4_008_013):
    """Small ELF with real PT_LOAD, symbols, PLT/GOT and relocation sections."""
    base = 0x10000
    data = bytearray(0x1000)
    data[0x100 : 0x100 + len(code)] = code
    data[0x300:0x304] = bytes.fromhex("1eff2fe1") if arm else bytes.fromhex("c2040090")
    data[0x500 : 0x500 + 30] = b"This program requires version \0"
    message = b" but the installed version is \0"
    data[0x540 : 0x540 + len(message)] = message
    struct.pack_into("<I", data, 0x280, version)
    names = b"\0" + VERIFY.encode() + b"\0" + VERSION_STRING.encode() + b"\0"
    data[0x600 : 0x600 + len(names)] = names
    # The relocation points at the defined VersionString; imports are a separate control.
    symbols = bytes(16) + struct.pack(
        "<IIIBBH", 1, base + 0x100 + thumb, len(code), 0x12, 0, 0 if imported else 1
    )
    symbols += struct.pack(
        "<IIIBBH", len(VERIFY) + 2, base + 0x300, 4, 0x12, 0, 0 if imported else 1
    )
    data[0x700 : 0x700 + len(symbols)] = symbols
    got, stub = base + 0x900, base + 0x810
    if plt:
        data[0x810:0x820] = bytes.fromhex("ffa30c0000006800000000e9e0ffffff")
        struct.pack_into("<II", data, 0xA00, got + 12, (2 << 8) | 7)
    labels = b"\0.text\0.dynstr\0.dynsym\0.plt\0.got.plt\0.rel.plt\0.shstrtab\0"
    data[0xB00 : 0xB00 + len(labels)] = labels
    sections = [bytes(40)]
    for name, kind, flags, offset, size, link, info, alignment, entsize in [
        (".text", 1, 6, 0x100, 0x480, 0, 0, 4, 0),
        (".dynstr", 3, 2, 0x600, len(names), 0, 0, 1, 0),
        (".dynsym", 11, 2, 0x700, len(symbols), 2, 1, 4, 16),
        (".plt", 1, 6, 0x800, 32 if plt else 0, 0, 0, 16, 16),
        (".got.plt", 1, 3, 0x900, 16 if plt else 0, 0, 0, 4, 4),
        (".rel.plt", 9, 2, 0xA00, 8 if plt else 0, 3, 5, 4, 8),
        (".shstrtab", 3, 0, 0xB00, len(labels), 0, 0, 1, 0),
    ]:
        sections.append(
            struct.pack(
                "<10I",
                labels.index(name.encode() + b"\0"),
                kind,
                flags,
                base + offset,
                offset,
                size,
                link,
                info,
                alignment,
                entsize,
            )
        )
    table = b"".join(sections)
    data[0xC00 : 0xC00 + len(table)] = table
    ident = b"\x7fELF\x01\x01\x01" + bytes(9)
    data[:52] = struct.pack(
        "<16sHHIIIIIHHHHHH",
        ident,
        3,
        40 if arm else 3,
        1,
        0,
        52,
        0xC00,
        0,
        52,
        32,
        2,
        40,
        len(sections),
        7,
    )
    data[52:84] = struct.pack("<8I", 1, 0, base, base, 0x900, 0x900, 5, 0x1000)
    data[84:116] = struct.pack(
        "<8I", 1, 0x900, base + 0x900, base + 0x900, len(data) - 0x900, len(data) - 0x900, 6, 0x1000
    )
    return bytes(data), got, stub


def _arm(version=4_008_013, prefix=b"", before_branch=b"", before_installed=b""):
    address = 0x10100
    code = bytearray(prefix)

    def emit(word):
        code.extend(struct.pack("<I", word))

    def literal(rd, target):
        emit(0xE59F0000 | rd << 12 | (target - (address + len(code) + 8)))

    def call():
        emit(0xEB000000 | (((0x10300 - (address + len(code) + 8)) // 4) & 0xFFFFFF))

    literal(4, 0x10280)
    emit(0xE1A05001)  # mov r5,r1
    emit(0xE1510004)  # cmp r1,r4
    code.extend(before_branch)
    branch = len(code)
    emit(0)
    literal(2, 0x10284)
    emit(0xE082200F)  # add r2,r2,pc; literal below is a relative pointer
    emit(0xE1A01005)
    call()
    literal(2, 0x10288)
    emit(0xE082200F)
    emit(0xE1A01004)
    code.extend(before_installed)
    call()
    end = address + len(code)
    emit(0xE12FFF1E)
    struct.pack_into("<I", code, branch, 0xDA000000 | ((end - (address + branch + 8)) // 4))
    data, _, _ = _elf(code, arm=True, version=version)
    patched = bytearray(data)
    # Resolve two PC-relative message literals from the actual add instructions.
    image = ELFView(data)
    adds = [i for i in image.instructions(address, len(code)) if i.mnemonic == "add"]
    for offset, target, insn in zip((0x284, 0x288), (0x10500, 0x10540), adds):
        struct.pack_into("<I", patched, offset, target - (insn.address + 8))
    return bytes(patched)


def _x86(version=4_008_013, before_branch=b"", frame_mutation=b"", stack_mutation=b"", plt=True):
    address, got = 0x10100, 0x10900
    code = bytearray.fromhex("5589e5")
    code.extend(frame_mutation)
    code.extend(bytes.fromhex("8b7d0c"))
    code.extend(b"\xe8" + bytes(4))
    pic_return = address + len(code)
    code.extend(b"\x5b\x81\xc3" + struct.pack("<I", got - pic_return))
    code.extend(b"\x81\xff" + struct.pack("<I", version + 1))
    code.extend(before_branch)
    branch = len(code)
    code.extend(b"\x7c\x00")

    def pointer(target):
        code.extend(b"\x8d\x83" + struct.pack("<i", target - got))

    def call():
        target = 0x10810 if plt else 0x10300
        code.extend(b"\xe8" + struct.pack("<i", target - (address + len(code) + 5)))

    pointer(0x10500)
    code.extend(bytes.fromhex("8d74241057"))  # lea esi,[esp+16]; push edi
    code.extend(stack_mutation)
    code.extend(b"\x56")
    call()
    code.extend(bytes.fromhex("83c404"))
    pointer(0x10540)
    code.extend(b"\x68" + struct.pack("<I", version) + b"\x56")
    call()
    code[branch + 1] = len(code) - branch - 2
    code.extend(b"\xc3")
    return _elf(code, plt=plt, version=version)[0]


def test_arm_pc_literal_in_writable_segment_is_not_a_library_version():
    data = bytearray(_arm())
    assert _module().extract_protobuf_versions(bytes(data))[0].version == "4.8.13"
    struct.pack_into("<I", data, 52 + 24, 7)  # RX -> RWX, including version literal
    assert _module().extract_protobuf_versions(bytes(data)) == []


@pytest.mark.parametrize("stage", ["prefix", "failure"])
@pytest.mark.parametrize(
    "factory,trap",
    [
        (_x86, bytes.fromhex("0f0b")),  # UD2 is not in Capstone's control groups
        (_x86, bytes.fromhex("f4")),  # HLT is privileged, not a fallthrough proof
        (_arm, bytes.fromhex("f000f0e7")),  # ARM UDF
    ],
)
def test_trap_cannot_be_skipped_to_reach_later_version_evidence(factory, trap, stage):
    from firmware_scanner.extraction.binary_inventory import BinaryInventory

    argument = (
        ("prefix" if stage == "prefix" else "before_installed")
        if factory is _arm
        else ("frame_mutation" if stage == "prefix" else "stack_mutation")
    )
    data = factory(**{argument: trap})
    assert _module().extract_protobuf_versions(data) == []
    components = BinaryInventory().extract(data, "libvendor.so", "/lib/libvendor.so")
    assert not any(c.name == "Protobuf" and c.resolved_version for c in components)


def test_inventory_attributes_protobuf_version_to_its_own_library():
    from firmware_scanner.extraction.binary_inventory import BinaryInventory

    inventory = BinaryInventory()
    data = _arm()
    own = inventory.extract(data, "libprotobuf-cpp-lite.so", "/lib/libprotobuf-cpp-lite.so")
    assert [(c.name, c.resolved_version) for c in own] == [("libprotobuf-cpp-lite.so", "4.8.13")]
    wrapped = inventory.extract(data, "libvendor.so", "/lib/libvendor.so")
    assert [(c.name, c.resolved_version) for c in wrapped] == [
        ("libvendor.so", ""),
        ("Protobuf", "4.8.13"),
    ]


@pytest.mark.parametrize("factory", [_arm, _x86])
@pytest.mark.parametrize("version", [2_003_000, 4_008_013, 7_041_006])
def test_portable_elf_recovers_each_elfs_library_constant(factory, version):
    hits = _module().extract_protobuf_versions(factory(version))
    assert [(h.name, h.version) for h in hits] == [
        ("Protobuf", f"{version // 1000000}.{version // 1000 % 1000}.{version % 1000}")
    ]
    proof = json.loads(hits[0].evidence)
    assert proof["comparison_role"] == "min_library_version"
    assert proof["version_string_inputs"] == ["min_library_version", version]


@pytest.mark.parametrize(
    "payload", [b"", b"not ELF", b"\x7fELF" + VERIFY.encode() + VERSION_STRING.encode()]
)
def test_incomplete_or_unrelated_input_fails_closed(payload):
    assert _module().extract_protobuf_versions(payload) == []


@pytest.mark.parametrize("names", [b"", VERIFY.encode(), VERSION_STRING.encode()])
def test_prefilter_avoids_elf_parse(monkeypatch, names):
    def unexpected(_data):
        pytest.fail("ELF parser called before symbol byte prefilter")

    monkeypatch.setattr(_module(), "ELFView", unexpected)
    assert _module().extract_protobuf_versions(b"\x7fELF" + bytes(80) + names) == []


@pytest.mark.parametrize("failure", [ValueError, OverflowError, RuntimeError])
def test_parser_exceptions_fail_closed(monkeypatch, failure):
    def broken(_data):
        raise failure("malformed ELF")

    monkeypatch.setattr(_module(), "ELFView", broken)
    assert _module().extract_protobuf_versions(_x86()) == []


def test_direct_x86_call_needs_no_plt_guess():
    assert _module().extract_protobuf_versions(_x86(plt=False))[0].version == "4.8.13"


@pytest.mark.parametrize("factory", [_arm, _x86])
def test_header_input_and_minimum_boundary_are_not_the_library_version(factory):
    good = factory()
    image = ELFView(good)
    instructions = image.instructions(*image.functions[VERIFY])
    if factory is _arm:
        compare = next(i for i in instructions if i.mnemonic == "cmp")
        offset, patch = compare.address - 0x10000, bytes.fromhex("040050e1")  # cmp r0,r4
    else:
        argument = next(
            i for i in instructions if i.mnemonic == "mov" and "[ebp + 0xc]" in i.op_str
        )
        offset, patch = argument.address - 0x10000 + 2, b"\x08"
    mutant = bytearray(good)
    mutant[offset : offset + len(patch)] = patch
    assert _module().extract_protobuf_versions(bytes(mutant)) == []


def test_imported_symbols_and_wrong_abi_are_not_library_proofs():
    good = _arm()
    for offset in (0x700 + 16 + 14, 0x700 + 32 + 14):
        patched = bytearray(good)
        struct.pack_into("<H", patched, offset, 0)
        assert _module().extract_protobuf_versions(bytes(patched)) == []
    wrong = bytearray(good)
    struct.pack_into("<H", wrong, 18, 62)
    assert _module().extract_protobuf_versions(bytes(wrong)) == []
    assert _module().extract_protobuf_versions(good[:0x900]) == []


@pytest.mark.parametrize(
    "mutation",
    [
        bytes.fromhex("010091e2"),
        bytes.fromhex("000057e3"),
        bytes.fromhex("00f028e1"),  # msr APSR; Capstone does not report a flags write
    ],
)
def test_arm_flags_changed_between_compare_and_branch_reject(mutation):
    assert _module().extract_protobuf_versions(_arm(before_branch=mutation)) == []


@pytest.mark.parametrize(
    "mutation",
    [
        bytes.fromhex("00109de5"),  # ldr r1,[sp] overwrites the installed version
        bytes.fromhex("011021e0"),  # eor r1,r1,r1
        bytes.fromhex("1e1040e3"),  # movt r1,#30 changes the installed value
    ],
)
def test_arm_failure_register_writes_cannot_reuse_old_constant(mutation):
    # Insert after the previous value assignment; every write must invalidate it.
    assert _module().extract_protobuf_versions(_arm(before_installed=mutation)) == []


@pytest.mark.parametrize(
    "prefix",
    [
        bytes.fromhex("0200bde8"),  # pop {r1}; writes the second argument
        bytes.fromhex("020090e8"),  # ldm r0,{r1}
        bytes.fromhex("0010a001"),  # moveq r1,r0; unknown predicate
    ],
)
def test_arm_prefix_load_multiple_and_conditional_writes_lose_argument(prefix):
    assert _module().extract_protobuf_versions(_arm(prefix=prefix)) == []


def test_arm_movt_without_known_low_bits_cannot_fabricate_library_constant():
    good = _arm()
    image = ELFView(good)
    # In the failure block the first VersionString clobbered r1. Replacing the
    # installed-value copy with MOVT must not create a complete integer value.
    copy = next(
        i
        for i in image.instructions(*image.functions[VERIFY])
        if i.mnemonic == "mov" and i.op_str == "r1, r4"
    )
    mutant = bytearray(good)
    offset = copy.address - 0x10000
    mutant[offset : offset + 4] = bytes.fromhex("1e1040e3")
    assert _module().extract_protobuf_versions(bytes(mutant)) == []


def test_conditional_arm_call_is_not_the_proven_failure_branch():
    good = _arm()
    image = ELFView(good)
    branch = next(i for i in image.instructions(*image.functions[VERIFY]) if i.mnemonic == "ble")
    mutant = bytearray(good)
    # BLE -> BLLE has the same condition and target but call side effects.
    mutant[branch.address - 0x10000 + 3] |= 1
    assert _module().extract_protobuf_versions(bytes(mutant)) == []


@pytest.mark.parametrize(
    "mutation", [bytes.fromhex("7d01"), bytes.fromhex("40"), bytes.fromhex("85c0")]
)
def test_x86_flags_clobber_or_control_before_guard_reject(mutation):
    assert _module().extract_protobuf_versions(_x86(before_branch=mutation)) == []


@pytest.mark.parametrize(
    "mutation", [bytes.fromhex("8d6d04"), bytes.fromhex("83c504"), bytes.fromhex("31ed")]
)
def test_x86_ebp_frame_is_lost_on_any_other_write(mutation):
    assert _module().extract_protobuf_versions(_x86(frame_mutation=mutation)) == []


@pytest.mark.parametrize(
    "mutation",
    [
        bytes.fromhex("83c404"),
        bytes.fromhex("83ec04"),
        bytes.fromhex("89c4"),
        bytes.fromhex("890424"),
        bytes.fromhex("8900"),
        bytes.fromhex("b700"),
    ],
)
def test_x86_stack_or_partial_register_mutation_cannot_reuse_pushes(mutation):
    assert _module().extract_protobuf_versions(_x86(stack_mutation=mutation)) == []


def test_plt_callee_requires_exact_got_slot_alignment_and_known_base():
    good = _x86()
    assert _module().extract_protobuf_versions(good)
    for offset, patch in [
        (0x812, struct.pack("<I", 8)),  # wrong GOT slot
        (0x810, b"\x90"),  # no first jmp
        (0x10B, b"\x90"),
    ]:  # destroys the PIC pop
        mutant = bytearray(good)
        mutant[offset : offset + len(patch)] = patch
        assert _module().extract_protobuf_versions(bytes(mutant)) == []
    image = ELFView(good)
    call = next(
        i
        for i in image.instructions(*image.functions[VERIFY])
        if i.mnemonic == "call" and i.operands[0].imm == 0x10810
    )
    misaligned = bytearray(good)
    struct.pack_into(
        "<i", misaligned, call.address - 0x10000 + 1, 0x10811 - (call.address + call.size)
    )
    assert _module().extract_protobuf_versions(bytes(misaligned)) == []


@pytest.mark.parametrize(
    "offset,patch",
    [
        (0x10E, struct.pack("<I", 0)),  # wrong proven EBX base
        (0xA00, struct.pack("<I", 0x10908)),  # actual GOT relocation slot changed
        (0x817, struct.pack("<I", 8)),  # wrong lazy resolver relocation offset
        (0xA04, struct.pack("<I", (2 << 8) | 6)),  # not a JUMP_SLOT
    ],
)
def test_plt_wrong_base_slot_and_resolver_metadata_reject(offset, patch):
    mutant = bytearray(_x86())
    mutant[offset : offset + len(patch)] = patch
    assert _module().extract_protobuf_versions(bytes(mutant)) == []


def test_register_aliases_normalize_partial_x86_and_arm_abi_names():
    from capstone import CS_ARCH_X86, CS_MODE_32, Cs

    module = _module()
    assert [module._arm_register(name) for name in ("sb", "sl", "fp", "ip", "sp", "lr", "pc")] == [
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
    ]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    mov = next(decoder.disasm(bytes.fromhex("b700"), 0x1000))  # mov bh,0
    assert module._writes(mov, False) == {"ebx"}


def test_register_access_errors_reject_instead_of_reusing_state(monkeypatch):
    from capstone import CsInsn

    def broken(_self):
        raise ValueError("register access unavailable")

    monkeypatch.setattr(CsInsn, "regs_access", broken)
    assert _module().extract_protobuf_versions(_x86()) == []
    assert _module().extract_protobuf_versions(_arm()) == []
