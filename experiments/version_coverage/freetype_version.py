"""Conservative FreeType version recovery from its paired library API.

This probe never loads or executes the input.  It currently accepts only a
small x86-64 ELF shape: a defined ``FT_Library_Version`` must copy three
adjacent integer fields to the API's three output pointers, and a defined
``FT_New_Library`` must write one constant to each same field in a straight
line block reached only after a defined FreeType allocator returns non-NULL.
Unsupported layouts and control flow are rejected.
"""
from __future__ import annotations

from io import BytesIO
from itertools import pairwise

from capstone import CS_ARCH_X86, CS_MODE_64, Cs, CsError
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from elftools.common.exceptions import ELFError
from elftools.elf.constants import P_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from firmware_scanner.extraction.static_version import StaticVersionMatch

_GETTER = "FT_Library_Version"
_INITIALIZER = "FT_New_Library"
_ALLOCATOR_PREFIXES = ("FT_Memory_Alloc", "ft_mem_alloc")
_ARGUMENT_REGISTERS = ("rsi", "rdx", "rcx")
_MAX_FUNCTION_SIZE = 4096
_WRITES_FIRST_OPERAND = {
    "mov", "movabs", "lea", "xor", "add", "sub", "and", "or", "inc", "dec",
    "imul", "shl", "shr", "sar", "pop", "cmovbe", "cmove", "cmovne", "cmovns",
}


class _Image:
    def __init__(self, data: bytes):
        self.data = data
        self.elf = ELFFile(BytesIO(data))
        if (self.elf.elfclass != 64 or not self.elf.little_endian
                or self.elf.header["e_machine"] != "EM_X86_64"):
            raise ValueError("unsupported ELF ABI")
        self.loads = [
            (int(seg["p_vaddr"]), int(seg["p_offset"]), int(seg["p_filesz"]),
             int(seg["p_flags"]))
            for seg in self.elf.iter_segments()
            if seg["p_type"] == "PT_LOAD"
        ]
        self.functions: dict[str, tuple[int, int]] = {}
        self.names_at: dict[int, set[str]] = {}
        self._read_symbols()
        self.disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        self.disassembler.detail = True
        self.plt_imports = self._read_plt_imports()

    def _read_symbols(self) -> None:
        found: dict[str, set[tuple[int, int]]] = {}
        for section in self.elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if symbol["st_info"]["type"] != "STT_FUNC":
                    continue
                if symbol["st_shndx"] in ("SHN_UNDEF", 0):
                    continue
                address, size = int(symbol["st_value"]), int(symbol["st_size"])
                if not symbol.name or not 0 < size <= _MAX_FUNCTION_SIZE:
                    continue
                found.setdefault(symbol.name, set()).add((address, size))
                self.names_at.setdefault(address, set()).add(symbol.name)
        for name, definitions in found.items():
            if len(definitions) == 1:
                self.functions[name] = next(iter(definitions))

    def _read_plt_imports(self) -> dict[int, str]:
        relocations: list[tuple[int, str]] = []
        for section in self.elf.iter_sections():
            if not isinstance(section, RelocationSection) or ".plt" not in section.name:
                continue
            symbols = self.elf.get_section(section["sh_link"])
            for relocation in section.iter_relocations():
                symbol = symbols.get_symbol(relocation["r_info_sym"])
                if symbol.name:
                    relocations.append((int(relocation["r_offset"]), symbol.name.split("@", 1)[0]))
        if not relocations:
            return {}

        plt = next((s for s in self.elf.iter_sections() if s.name == ".plt.sec"), None)
        resolver_entry = 0
        if plt is None:
            plt = next((s for s in self.elf.iter_sections() if s.name == ".plt"), None)
            resolver_entry = 1
        if plt is None:
            return {}

        result: dict[int, str] = {}
        for index, (got_address, name) in enumerate(relocations):
            start = (index + resolver_entry) * 16
            raw = plt.data()[start:start + 16]
            stub_address = int(plt["sh_addr"]) + start
            instructions = list(self.disassembler.disasm(raw, stub_address))
            if not instructions:
                # The disassembler is initialized below; use the architectural
                # invariant of the first PLT instruction after setup instead.
                continue
            first = instructions[0]
            if first.mnemonic != "jmp" or len(first.operands) != 1:
                continue
            operand = first.operands[0]
            if operand.type != X86_OP_MEM or first.reg_name(operand.mem.base) != "rip":
                continue
            if first.address + first.size + int(operand.mem.disp) == got_address:
                result[stub_address] = name
        return result

    def _import_name(self, address: int) -> str | None:
        return self.plt_imports.get(address)

    def function(self, name: str):
        symbol = self.functions.get(name)
        if symbol is None:
            return None
        address, size = symbol
        for vaddr, offset, filesz, flags in self.loads:
            if (flags & P_FLAGS.PF_X and vaddr <= address
                    and address + size <= vaddr + filesz):
                start = offset + address - vaddr
                raw = self.data[start:start + size]
                if len(raw) != size:
                    return None
                instructions = list(self.disassembler.disasm(raw, address))
                if not instructions or sum(item.size for item in instructions) != size:
                    return None
                return address, instructions
        return None


def _reg_name(insn, register: int) -> str:
    return insn.reg_name(register)


def _register_family(name: str) -> str:
    aliases = {
        "edi": "rdi", "di": "rdi", "dil": "rdi",
        "esi": "rsi", "si": "rsi", "sil": "rsi",
        "edx": "rdx", "dx": "rdx", "dl": "rdx",
        "ecx": "rcx", "cx": "rcx", "cl": "rcx",
        "eax": "rax", "ax": "rax", "al": "rax",
    }
    return aliases.get(name, name)


def _writes_register_first(insn, family: str) -> bool:
    if (insn.mnemonic not in _WRITES_FIRST_OPERAND or not insn.operands
            or insn.operands[0].type != X86_OP_REG):
        return False
    return _register_family(_reg_name(insn, insn.operands[0].reg)) == family


def _reachable(instructions, start: int) -> set[int] | None:
    """Follow direct in-function x86 branches; refuse unresolved control flow."""
    by_address = {insn.address: insn for insn in instructions}
    pending = [start]
    seen: set[int] = set()
    while pending:
        address = pending.pop()
        if address in seen:
            continue
        insn = by_address.get(address)
        if insn is None:
            return None
        seen.add(address)
        next_address = insn.address + insn.size
        if insn.mnemonic.startswith("ret"):
            continue
        if insn.mnemonic.startswith("j"):
            if len(insn.operands) != 1 or insn.operands[0].type != X86_OP_IMM:
                return None
            target = int(insn.operands[0].imm)
            if target not in by_address:
                return None
            pending.append(target)
            if insn.mnemonic != "jmp":
                if next_address not in by_address:
                    return None
                pending.append(next_address)
            continue
        if next_address not in by_address:
            return None
        pending.append(next_address)
    return seen


def _getter_fields(instructions) -> dict[str, int] | None:
    if any(insn.mnemonic.startswith("call") for insn in instructions):
        return None
    if len(instructions) < 2:
        return None
    null_test, null_branch = instructions[:2]
    if not (
        null_test.mnemonic == "test" and len(null_test.operands) == 2
        and all(op.type == X86_OP_REG and _register_family(_reg_name(null_test, op.reg)) == "rdi"
                for op in null_test.operands)
        and null_branch.mnemonic == "je" and len(null_branch.operands) == 1
        and null_branch.operands[0].type == X86_OP_IMM
    ):
        return None
    null_reachable = _reachable(instructions, int(null_branch.operands[0].imm))
    nonnull_start = null_branch.address + null_branch.size
    nonnull_reachable = _reachable(instructions, nonnull_start)
    if null_reachable is None or nonnull_reachable is None:
        return None
    for insn in instructions:
        if any(_writes_register_first(insn, reg) for reg in ("rdi", *_ARGUMENT_REGISTERS)):
            return None
    result: dict[str, set[int]] = {name: set() for name in _ARGUMENT_REGISTERS}
    linked_stores: set[int] = set()
    linked_counts = {name: 0 for name in _ARGUMENT_REGISTERS}
    linked_pairs: dict[tuple[int, int], str] = {}
    for first, second in pairwise(instructions):
        if first.mnemonic != "mov" or second.mnemonic != "mov":
            continue
        if len(first.operands) != 2 or len(second.operands) != 2:
            continue
        dst, src = first.operands
        out, value = second.operands
        if not (dst.type == X86_OP_REG and src.type == X86_OP_MEM
                and _reg_name(first, src.mem.base) == "rdi"
                and src.mem.index == 0 and src.mem.disp >= 0 and src.size == 4
                and out.type == X86_OP_MEM and value.type == X86_OP_REG
                and out.mem.index == 0 and out.mem.disp == 0
                and _reg_name(second, out.mem.base) in result
                and dst.reg == value.reg and dst.size == 4 and value.size == 4):
            continue
        output_name = _register_family(_reg_name(second, out.mem.base))
        if first.address not in nonnull_reachable or second.address not in nonnull_reachable:
            continue
        result[output_name].add(int(src.mem.disp))
        linked_stores.add(second.address)
        linked_counts[output_name] += 1
        linked_pairs[(first.address, second.address)] = output_name

    # On the non-NULL-library region, every conditional must be the canonical
    # optional-output guard immediately before that output's field copy.  This
    # excludes extra branches that could return successfully without updating
    # a non-NULL output pointer.
    by_address = {insn.address: index for index, insn in enumerate(instructions)}
    for insn in instructions:
        if insn.address not in nonnull_reachable or not insn.mnemonic.startswith("j"):
            continue
        index = by_address[insn.address]
        if (insn.mnemonic != "je" or len(insn.operands) != 1
                or insn.operands[0].type != X86_OP_IMM or index < 1
                or index + 2 >= len(instructions)):
            return None
        test = instructions[index - 1]
        load, store = instructions[index + 1:index + 3]
        if (test.mnemonic != "test" or len(test.operands) != 2
                or any(op.type != X86_OP_REG for op in test.operands)):
            return None
        tested = {_register_family(_reg_name(test, op.reg)) for op in test.operands}
        if len(tested) != 1:
            return None
        output = next(iter(tested))
        target = int(insn.operands[0].imm)
        if (output not in result or linked_pairs.get((load.address, store.address)) != output
                or target <= store.address):
            return None

    # Reject a later overwrite or any other nonzero source reaching an API
    # output.  Zero stores are permitted for the library==NULL API path.
    for insn in instructions:
        if insn.mnemonic != "mov" or len(insn.operands) != 2:
            continue
        dst, src = insn.operands
        if dst.type != X86_OP_MEM or dst.mem.index != 0 or dst.mem.disp != 0:
            continue
        output = _register_family(_reg_name(insn, dst.mem.base))
        if output not in result:
            continue
        if insn.address in linked_stores:
            continue
        if (insn.address not in null_reachable or insn.address in nonnull_reachable
                or dst.size != 4 or src.type != X86_OP_IMM or int(src.imm) != 0):
            return None
    if any(len(offsets) != 1 for offsets in result.values()) or any(
        count != 1 for count in linked_counts.values()
    ):
        return None
    fields = {name: next(iter(offsets)) for name, offsets in result.items()}
    ordered = [fields[name] for name in _ARGUMENT_REGISTERS]
    if ordered[1:] != [ordered[0] + 4, ordered[0] + 8]:
        return None
    return fields


def _initializer_constants(image: _Image, instructions, offsets: set[int]):
    calls = [insn for insn in instructions if insn.mnemonic.startswith("call")]
    if len(calls) != 1 or len(calls[0].operands) != 1:
        return None
    call = calls[0]
    if call.operands[0].type != X86_OP_IMM:
        return None
    target = int(call.operands[0].imm)
    allocator_names = image.names_at.get(target, set())
    if not any(name.startswith(_ALLOCATOR_PREFIXES) for name in allocator_names):
        return None
    defined_allocator = next((name for name in allocator_names if name in image.functions), None)
    if defined_allocator is None or not _allocator_returns_malloc(image, defined_allocator):
        return None

    call_index = instructions.index(call)
    if call_index + 2 >= len(instructions):
        return None
    check, failure_branch = instructions[call_index + 1:call_index + 3]
    if not (
        check.mnemonic == "test" and len(check.operands) == 2
        and all(op.type == X86_OP_REG and _reg_name(check, op.reg) == "rax"
                for op in check.operands)
        and failure_branch.mnemonic in ("je", "jz")
        and len(failure_branch.operands) == 1
        and failure_branch.operands[0].type == X86_OP_IMM
    ):
        return None

    # The non-NULL edge is the fallthrough edge.  Accept only its uninterrupted
    # straight-line block through RET; this makes the check dominate every
    # candidate field store and excludes conditional initialization paths.
    block = []
    for insn in instructions[call_index + 3:]:
        if insn.mnemonic.startswith(("j", "call", "ret")):
            if insn.mnemonic.startswith("ret"):
                block.append(insn)
            break
        block.append(insn)
    if not block or not block[-1].mnemonic.startswith("ret"):
        return None
    block_addresses = {insn.address for insn in block}
    failure_target = int(failure_branch.operands[0].imm)
    if failure_target in block_addresses:
        return None

    writes: dict[int, list[int]] = {offset: [] for offset in offsets}
    for insn in instructions:
        if insn.mnemonic != "mov" or len(insn.operands) != 2:
            continue
        dst, src = insn.operands
        if dst.type != X86_OP_MEM or dst.mem.index != 0:
            continue
        displacement = int(dst.mem.disp)
        if displacement not in offsets:
            continue
        if _register_family(_reg_name(insn, dst.mem.base)) != "rax":
            if insn.address in block_addresses:
                return None
            continue
        if insn.address not in block_addresses:
            return None
        if src.type != X86_OP_IMM:
            return None
        writes[displacement].append(int(src.imm))
    if any(len(values) != 1 for values in writes.values()):
        return None
    last_store = max(
        insn.address for insn in block
        if insn.mnemonic == "mov" and len(insn.operands) == 2
        and insn.operands[0].type == X86_OP_MEM
        and int(insn.operands[0].mem.disp) in offsets
    )
    for insn in instructions:
        if insn.mnemonic.startswith("j") and insn.operands and insn.operands[0].type == X86_OP_IMM:
            target_address = int(insn.operands[0].imm)
            if call.address <= target_address <= last_store:
                return None
        if (check.address <= insn.address <= last_store
                and _writes_register_first(insn, "rax")):
            return None
    return {offset: values[0] for offset, values in writes.items()}


def _allocator_returns_malloc(image: _Image, name: str) -> bool:
    function = image.function(name)
    if function is None:
        return False
    instructions = function[1]
    allocator_transfers = []
    for insn in instructions:
        if insn.mnemonic not in ("call", "jmp"):
            continue
        if len(insn.operands) != 1:
            return False
        operand = insn.operands[0]
        if operand.type != X86_OP_IMM:
            return False
        imported = image._import_name(int(operand.imm))
        if insn.mnemonic == "call" or imported:
            if imported != "malloc":
                return False
            allocator_transfers.append(insn)
        elif not function[0] <= int(operand.imm) < function[0] + image.functions[name][1]:
            return False
    if len(allocator_transfers) != 1:
        return False
    transfer = allocator_transfers[0]
    reachable = _reachable_allocator(image, instructions)
    if reachable is None or transfer.address not in reachable:
        return False
    if transfer.mnemonic == "call":
        next_instructions = [i for i in instructions if i.address > transfer.address]
        if not next_instructions or next_instructions[0].mnemonic != "ret":
            return False
    elif transfer.mnemonic != "jmp":
        return False

    returns = [i for i in instructions if i.mnemonic.startswith("ret")
               and i.address in reachable]
    if not returns:
        return transfer.mnemonic == "jmp"
    for ret in returns:
        previous = [i for i in instructions if i.address < ret.address]
        if not previous:
            return False
        prior = previous[-1]
        zero_return = (
            prior.mnemonic == "xor" and len(prior.operands) == 2
            and all(op.type == X86_OP_REG and _register_family(_reg_name(prior, op.reg)) == "rax"
                    for op in prior.operands)
        ) or (
            prior.mnemonic == "mov" and len(prior.operands) == 2
            and prior.operands[0].type == X86_OP_REG
            and _register_family(_reg_name(prior, prior.operands[0].reg)) == "rax"
            and prior.operands[1].type == X86_OP_IMM and int(prior.operands[1].imm) == 0
        )
        next_after_transfer = next((i for i in instructions if i.address > transfer.address), None)
        if not zero_return and not (
            transfer.mnemonic == "call" and next_after_transfer is ret
        ):
            return False
    return True


def _reachable_allocator(image: _Image, instructions) -> set[int] | None:
    by_address = {insn.address: insn for insn in instructions}
    if not instructions:
        return None
    pending = [instructions[0].address]
    seen: set[int] = set()
    while pending:
        address = pending.pop()
        if address in seen:
            continue
        insn = by_address.get(address)
        if insn is None:
            return None
        seen.add(address)
        next_address = insn.address + insn.size
        if insn.mnemonic.startswith("ret"):
            continue
        if insn.mnemonic == "call":
            if len(insn.operands) != 1 or insn.operands[0].type != X86_OP_IMM:
                return None
            target = int(insn.operands[0].imm)
            if image._import_name(target) != "malloc" or next_address not in by_address:
                return None
            pending.append(next_address)
            continue
        if insn.mnemonic == "jmp":
            if len(insn.operands) != 1 or insn.operands[0].type != X86_OP_IMM:
                return None
            target = int(insn.operands[0].imm)
            if image._import_name(target) == "malloc":
                continue
            if target not in by_address:
                return None
            pending.append(target)
            continue
        if insn.mnemonic.startswith("j"):
            if len(insn.operands) != 1 or insn.operands[0].type != X86_OP_IMM:
                return None
            target = int(insn.operands[0].imm)
            if target not in by_address or next_address not in by_address:
                return None
            pending.extend((target, next_address))
            continue
        if next_address not in by_address:
            return None
        pending.append(next_address)
    return seen


def extract_freetype(data: bytes) -> list[StaticVersionMatch]:
    """Return a version only when the paired getter/initializer proof succeeds."""
    if not isinstance(data, bytes) or len(data) < 64 or data[:4] != b"\x7fELF":
        return []
    try:
        image = _Image(data)
        getter = image.function(_GETTER)
        initializer = image.function(_INITIALIZER)
        if getter is None or initializer is None:
            return []
        fields = _getter_fields(getter[1])
        if fields is None:
            return []
        constants = _initializer_constants(image, initializer[1], set(fields.values()))
        if constants is None:
            return []
        version = tuple(constants[fields[arg]] for arg in _ARGUMENT_REGISTERS)
        major, minor, patch = version
        if not (1 <= major <= 99 and 0 <= minor <= 999 and 0 <= patch <= 999):
            return []
        evidence = (
            "defined FT_Library_Version copies library fields at offsets "
            f"{fields['rsi']:#x}/{fields['rdx']:#x}/{fields['rcx']:#x} to major/minor/patch; "
            "defined FT_New_Library writes the linked constants once each in the "
            "straight-line allocation-success block after a defined FT_Memory_Alloc"
        )
        return [StaticVersionMatch("FreeType", ".".join(map(str, version)), evidence, 0.98)]
    except (ELFError, CsError, OSError, ValueError, TypeError, KeyError, IndexError,
            OverflowError, AttributeError):
        return []
