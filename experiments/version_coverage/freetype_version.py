"""Conservative FreeType version recovery from its paired library API.

This probe never loads or executes the input.  It accepts a deliberately small
set of paired getter/initializer instruction shapes used by the current Android
system FreeType libraries, plus the original x86-64 synthetic fixture shape.
Unsupported layouts and control flow are rejected.
"""
from __future__ import annotations

from io import BytesIO
from itertools import pairwise

from capstone import (
    CS_AC_WRITE,
    CS_ARCH_ARM,
    CS_ARCH_ARM64,
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    CS_MODE_ARM,
    CS_MODE_LITTLE_ENDIAN,
    Cs,
    CsError,
)
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
        self.machine = self.elf.header["e_machine"]
        architecture = {
            ("EM_X86_64", 64): (CS_ARCH_X86, CS_MODE_64),
            ("EM_386", 32): (CS_ARCH_X86, CS_MODE_32),
            ("EM_AARCH64", 64): (CS_ARCH_ARM64, 0),
            ("EM_ARM", 32): (CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN),
        }.get((self.machine, self.elf.elfclass))
        if not self.elf.little_endian or architecture is None:
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
        self.disassembler = Cs(*architecture)
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
        if self.machine not in ("EM_X86_64", "EM_386"):
            return {}
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

    def bytes_at(self, address: int, size: int) -> bytes | None:
        """Read a bounded file-backed virtual-address range without loading ELF code."""
        for vaddr, offset, filesz, _flags in self.loads:
            if vaddr <= address and address + size <= vaddr + filesz:
                start = offset + address - vaddr
                raw = self.data[start:start + size]
                return raw if len(raw) == size else None
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
    if name in aliases:
        return aliases[name]
    for suffix in ("d", "w", "b"):
        if name.startswith("r") and name.endswith(suffix) and name[1:-1].isdigit():
            return name[:-1]
    return name


def _register_key(name: str) -> str:
    """Canonicalize aliases that share storage across supported ABIs."""
    name = _register_family(name)
    if name.startswith("w") and name[1:].isdigit():
        return "x" + name[1:]
    if name[:1] in ("v", "q", "d", "s", "h", "b") and name[1:].isdigit():
        return "v" + name[1:]
    return name


def _written_registers(insn) -> set[str] | None:
    """Return explicit and implicit register writes, or fail closed."""
    try:
        _reads, writes = insn.regs_access()
    except Exception:  # noqa: BLE001 -- unavailable decoder metadata rejects the proof
        return None
    return {_register_key(insn.reg_name(register)) for register in writes}


def _register_width(name: str) -> int | None:
    if name.startswith("zmm"):
        return 64
    if name.startswith("ymm"):
        return 32
    if name.startswith(("q", "v", "xmm")):
        return 16
    if name.startswith(("x", "r")) and name[1:].isdigit():
        return 8 if name.startswith("x") else 4
    if name.startswith("w") and name[1:].isdigit():
        return 4
    if name.startswith("d") and name[1:].isdigit():
        return 8
    if name.startswith(("s",)) and name[1:].isdigit():
        return 4
    if name.startswith(("h",)) and name[1:].isdigit():
        return 2
    if name.startswith(("b",)) and name[1:].isdigit():
        return 1
    if name.startswith(("e",)) and name[1:].isalpha():
        return 4
    if name in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"):
        return 8
    if name.startswith("r") and name[1:].isdigit():
        return 8
    if name.startswith("xmm"):
        return 16
    if name.startswith("r") and name[1:].isalpha():
        return 4
    return None


def _memory_write_records(insn):
    """Describe explicit memory writes; unknown widths remain unknown."""
    if insn.mnemonic.startswith(("ldr", "ldp", "ldm", "ldrb", "ldrh", "ldrs", "ldrd")):
        return []
    records = []
    for index, operand in enumerate(insn.operands):
        if operand.type != X86_OP_MEM or not (getattr(operand, "access", 0) & CS_AC_WRITE):
            continue
        size = getattr(operand, "size", 0) or None
        if size is None:
            source_operands = [item for item in insn.operands[:index]
                               if item.type == X86_OP_REG]
            if insn.mnemonic in ("stp", "stnp"):
                widths = [_register_width(insn.reg_name(item.reg))
                          for item in source_operands[-2:]]
                size = sum(widths) if len(widths) == 2 and all(widths) else None
            elif source_operands:
                size = _register_width(insn.reg_name(source_operands[-1].reg))
        records.append((insn.reg_name(operand.mem.base),
                        insn.reg_name(operand.mem.index) if operand.mem.index else None,
                        int(operand.mem.disp), size, index))
    if insn.mnemonic.startswith("stm"):
        if insn.mnemonic != "stmib" or len(insn.operands) < 3:
            records.append((_reg(insn, insn.operands[0]) if insn.operands else None,
                            None, None, None, None))
        else:
            base = _reg(insn, insn.operands[0])
            widths = [_register_width(_reg(insn, operand)) for operand in insn.operands[1:]]
            size = sum(widths) if all(widths) else None
            records.append((base, None, 4, size, None))
    if insn.mnemonic.startswith("stos"):
        records.append((None, None, None, None, None))
    return records


def _overlapping_fields(start: int, size: int, fields: dict[str, int]) -> list[int]:
    end = start + size
    return [offset for offset in fields.values()
            if start < offset + 4 and offset < end]


def _fully_covers_fields(start: int, size: int, offsets: list[int]) -> bool:
    return all(start <= offset and offset + 4 <= start + size for offset in offsets)


def _aliases_before(instructions, stop: int, initial_register: str) -> set[str] | None:
    aliases = {_register_key(initial_register)}
    for insn in instructions[:stop]:
        written = _written_registers(insn)
        if written is None:
            return None
        prior = set(aliases)
        aliases.difference_update(written)
        if (insn.mnemonic.startswith("mov") and len(insn.operands) == 2
                and insn.operands[0].type == X86_OP_REG
                and insn.operands[1].type == X86_OP_REG):
            dst, src = insn.operands
            if _register_key(_reg(insn, src)) in prior:
                aliases.add(_register_key(_reg(insn, dst)))
        elif (insn.mnemonic == "mov" and len(insn.operands) == 2
              and insn.operands[0].type == X86_OP_REG
              and insn.operands[1].type == X86_OP_MEM
              and insn.reg_name(insn.operands[1].mem.base) == "ebp"
              and int(insn.operands[1].mem.disp) == 12
              and _register_key(_reg(insn, insn.operands[0])) == _register_key(initial_register)):
            aliases.add(_register_key(initial_register))
    return aliases


def _arm_rotated_immediate(insn, index: int) -> int | None:
    if index + 1 >= len(insn.operands):
        return None
    value, rotate = int(insn.operands[index].imm), int(insn.operands[index + 1].imm)
    rotate %= 32
    return value if rotate == 0 else ((value >> rotate) | (value << (32 - rotate))) & 0xffffffff


def _arm_plt_import(image: _Image, address: int) -> str | None:
    plt = image.elf.get_section_by_name(".plt")
    if plt is None:
        return None
    start = int(plt["sh_addr"])
    raw = plt.data()
    offset = address - start
    if offset < 0 or offset + 12 > len(raw):
        return None
    insns = list(image.disassembler.disasm(raw[offset:offset + 12], address))
    if len(insns) < 3:
        return None
    first, second, third = insns[:3]
    if (first.mnemonic != "add" or second.mnemonic != "add" or third.mnemonic != "ldr"
            or len(first.operands) < 4 or len(second.operands) < 4
            or len(third.operands) < 2):
        return None
    if (_reg(first, first.operands[0]) != "ip" or _reg(first, first.operands[1]) != "pc"
            or _reg(second, second.operands[0]) != "ip"
            or _reg(second, second.operands[1]) != "ip"
            or _reg(third, third.operands[0]) != "pc"
            or third.operands[1].type != X86_OP_MEM
            or third.reg_name(third.operands[1].mem.base) != "ip"):
        return None
    first_imm = _arm_rotated_immediate(first, 2)
    second_imm = _arm_rotated_immediate(second, 2)
    if first_imm is None or second_imm is None:
        return None
    got_address = (first.address + 8 + first_imm + second_imm
                   + int(third.operands[1].mem.disp))
    for section in image.elf.iter_sections():
        if not isinstance(section, RelocationSection) or ".plt" not in section.name:
            continue
        symbols = image.elf.get_section(section["sh_link"])
        for relocation in section.iter_relocations():
            if int(relocation["r_offset"]) == got_address:
                return symbols.get_symbol(relocation["r_info_sym"]).name.split("@", 1)[0]
    return None


def _arm_bzero_size(image: _Image, call) -> int | None:
    if call.mnemonic != "bl" or not call.operands or call.operands[0].type != X86_OP_IMM:
        return None
    target = int(call.operands[0].imm)
    raw = image.bytes_at(target, 12)
    if raw is None:
        return None
    insns = list(image.disassembler.disasm(raw, target))
    if (len(insns) < 3 or insns[0].mnemonic != "mov" or insns[1].mnemonic != "movs"
            or insns[2].mnemonic != "b" or len(insns[0].operands) != 2
            or _reg(insns[0], insns[0].operands[0]) != "r2"
            or _reg(insns[0], insns[0].operands[1]) != "r1"
            or _reg(insns[1], insns[1].operands[0]) != "r1"
            or int(insns[1].operands[1].imm) != 0
            or not insns[2].operands or insns[2].operands[0].type != X86_OP_IMM):
        return None
    return 0 if _arm_plt_import(image, int(insns[2].operands[0].imm)) == "memset" else None


def _audit_initializer_memory_writes(
    image: _Image, abi: str, instructions, call_index: int,
    fields: dict[str, int], store_addresses: list[int],
) -> bool:
    result_register, out_register = {
        "EM_X86_64": ("rax", "rsi"),
        "EM_386": ("eax", "esi"),
        "EM_AARCH64": ("x0", "x1"),
        "EM_ARM": ("r0", "r1"),
    }[abi]
    lib_aliases = {_register_key(result_register)}
    out_aliases = _aliases_before(instructions, call_index, out_register)
    if out_aliases is None:
        return False
    if abi == "EM_386" and any(
        insn.mnemonic == "mov" and len(insn.operands) == 2
        and insn.operands[0].type == X86_OP_REG and _reg(insn, insn.operands[0]) == "esi"
        and insn.operands[1].type == X86_OP_MEM
        and insn.reg_name(insn.operands[1].mem.base) == "ebp"
        and int(insn.operands[1].mem.disp) == 12
        for insn in instructions[:call_index]
    ):
        out_aliases.add("rsi")
    if abi == "EM_ARM" and any(
        insn.mnemonic == "movne" and len(insn.operands) == 2
        and _reg(insn, insn.operands[0]) == "r4"
        and _reg(insn, insn.operands[1]) == "r1"
        for insn in instructions[:call_index]
    ):
        out_aliases.add("r4")
    stack_registers = {
        "EM_X86_64": {"rsp", "rbp"}, "EM_386": {"esp", "ebp"},
        "EM_AARCH64": {"sp", "x29"}, "EM_ARM": {"sp", "r11", "fp"},
    }[abi]
    pointer_size = 8 if abi in ("EM_X86_64", "EM_AARCH64") else 4
    values: dict[str, int] = {}
    zero_registers: set[str] = set()
    filled_fields: set[int] = set()
    field_offsets = list(dict.fromkeys(fields.values()))
    for insn in instructions[call_index + 1:]:
        if insn.mnemonic in ("ret", "pop", "pop.w") or insn.mnemonic.startswith("ret"):
            break
        written = _written_registers(insn)
        if written is None:
            return False
        prior_lib_aliases = set(lib_aliases)
        prior_out_aliases = set(out_aliases)
        records = _memory_write_records(insn)

        if insn.mnemonic.startswith(("call", "bl", "blr", "blx")):
            memset_range = None
            if abi == "EM_X86_64" and insn.mnemonic == "call" and insn.operands:
                target = int(insn.operands[0].imm) if insn.operands[0].type == X86_OP_IMM else None
                if (target is not None and image._import_name(target) == "memset"
                        and "rdi" in prior_lib_aliases
                        and _register_key("rsi") in zero_registers
                        and values.get(_register_key("rdx"), 0) > 0):
                    memset_range = (0, values[_register_key("rdx")])
            elif abi == "EM_ARM" and insn.mnemonic == "bl":
                clear_size = _arm_bzero_size(image, insn)
                if (clear_size == 0 and "r0" in prior_lib_aliases
                        and values.get(_register_key("r1"), 0) > 0):
                    memset_range = (0, values[_register_key("r1")])
            if memset_range is None:
                return False
            start, size = memset_range
            overlap = _overlapping_fields(start, size, fields)
            if (not overlap or not _fully_covers_fields(start, size, overlap)
                    or any(address <= insn.address for address in store_addresses)):
                return False
            filled_fields.update(overlap)

        for base_name, index_name, displacement, size, operand_index in records:
            if base_name is None or displacement is None or size is None:
                return False
            if index_name not in (None, ""):
                return False
            base_key = _register_key(base_name)
            if base_key in prior_lib_aliases:
                overlap = _overlapping_fields(displacement, size, fields)
                if overlap:
                    exact = (
                        insn.address in store_addresses
                        and ((size == 4 and displacement in field_offsets)
                             or (size == 8 and displacement == fields["rsi"]
                                 and fields["rdx"] == displacement + 4)
                             or (abi == "EM_ARM" and insn.mnemonic == "stmib"
                                 and displacement == fields["rsi"]
                                 and size == 8 and fields["rdx"] == displacement + 4))
                    )
                    zero_fill = False
                    source_operands = []
                    if operand_index is not None:
                        memory_index = operand_index
                        source_operands = [op for op in insn.operands[:memory_index]
                                           if op.type == X86_OP_REG]
                        if not source_operands:
                            source_operands = [op for op in insn.operands[memory_index + 1:]
                                               if op.type == X86_OP_REG]
                    elif insn.mnemonic == "stmib":
                        source_operands = [op for op in insn.operands[1:]
                                           if op.type == X86_OP_REG]
                    if source_operands and all(
                        _register_key(_reg(insn, op)) in zero_registers
                        for op in source_operands
                    ) and _fully_covers_fields(displacement, size, overlap):
                        zero_fill = True
                    if exact:
                        filled_fields.update(
                            offset for offset in field_offsets
                            if displacement <= offset and offset + 4 <= displacement + size
                        )
                    elif zero_fill and all(address > insn.address for address in store_addresses):
                        filled_fields.update(overlap)
                    else:
                        return False
                continue
            if base_key in out_aliases:
                if displacement != 0 or size != pointer_size:
                    return False
                continue
            if base_key in {_register_key(name) for name in stack_registers}:
                continue
            return False

        values = {register: value for register, value in values.items()
                  if register not in written}
        zero_registers.difference_update(written)
        lib_aliases.difference_update(written)
        out_aliases.difference_update(written)
        if (insn.mnemonic in ("mov", "movabs") and len(insn.operands) == 2
                and all(op.type == X86_OP_REG for op in insn.operands)):
            dst, src = insn.operands
            source = _register_key(_reg(insn, src))
            destination = _register_key(_reg(insn, dst))
            if source in prior_lib_aliases:
                lib_aliases.add(destination)
            if source in prior_out_aliases:
                out_aliases.add(destination)
        if insn.mnemonic in ("mov", "movabs") and len(insn.operands) == 2:
            dst, src = insn.operands
            if dst.type == X86_OP_REG and src.type == X86_OP_IMM:
                values[_register_key(_reg(insn, dst))] = int(src.imm)
        if (insn.mnemonic in ("xor", "xorps", "xorpd") and len(insn.operands) == 2
                and all(op.type == X86_OP_REG for op in insn.operands)
                and _register_key(_reg(insn, insn.operands[0]))
                == _register_key(_reg(insn, insn.operands[1]))):
            key = _register_key(_reg(insn, insn.operands[0]))
            zero_registers.add(key)
            values[key] = 0
        if insn.mnemonic == "movi" and insn.operands and insn.operands[0].type == X86_OP_REG:
            immediates = [int(op.imm) for op in insn.operands if op.type == X86_OP_IMM]
            if immediates and all(value == 0 for value in immediates):
                zero_registers.add(_register_key(_reg(insn, insn.operands[0])))

    return filled_fields.issuperset(set(field_offsets))


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


def _reg(insn, operand) -> str:
    return insn.reg_name(operand.reg)


def _mem(insn, operand, base: str, displacement: int | None = None) -> bool:
    if operand.type != X86_OP_MEM:
        return False
    if insn.reg_name(operand.mem.base) != base:
        return False
    return displacement is None or int(operand.mem.disp) == displacement


def _getter_x64(instructions) -> dict[str, int] | None:
    if len(instructions) < 2 or instructions[0].mnemonic != "test":
        return None
    if (tuple(i.mnemonic for i in instructions[:2]) != ("test", "je")
            or len(instructions[0].operands) != 2
            or any(op.type != X86_OP_REG or _register_family(_reg(instructions[0], op)) != "rdi"
                   for op in instructions[0].operands)
            or len(instructions[1].operands) != 1
            or instructions[1].operands[0].type != X86_OP_IMM):
        return None
    valid_addresses = {insn.address for insn in instructions}
    for insn in instructions:
        if insn.mnemonic.startswith("j") and (
                len(insn.operands) != 1 or insn.operands[0].type != X86_OP_IMM
                or int(insn.operands[0].imm) not in valid_addresses):
            return None
    field_registers: dict[str, int] = {}
    for insn in instructions:
        if insn.mnemonic != "mov" or len(insn.operands) != 2:
            continue
        dst, src = insn.operands
        if (dst.type == X86_OP_REG and src.type == X86_OP_MEM
                and _mem(insn, src, "rdi") and src.size == 4):
            field_registers[_reg(insn, dst)] = int(src.mem.disp)
    output_registers = {"rsi": "rsi", "rdx": "rdx", "rcx": "rcx"}
    fields: dict[str, int] = {}
    for index, insn in enumerate(instructions):
        if insn.mnemonic != "mov" or len(insn.operands) != 2:
            continue
        dst, src = insn.operands
        if (dst.type != X86_OP_MEM or src.type != X86_OP_REG or dst.size != 4
                or int(dst.mem.disp) != 0 or dst.mem.index != 0):
            continue
        out = insn.reg_name(dst.mem.base)
        if out not in output_registers:
            continue
        value = _reg(insn, src)
        if value not in field_registers or src.size != 4:
            return None
        prior_writers = [candidate for candidate in instructions[:index]
                         if _register_key(value) in (_written_registers(candidate) or set())]
        if (not prior_writers or prior_writers[-1].mnemonic != "mov"
                or len(prior_writers[-1].operands) != 2
                or prior_writers[-1].operands[0].type != X86_OP_REG
                or _register_key(_reg(prior_writers[-1], prior_writers[-1].operands[0]))
                != _register_key(value)
                or prior_writers[-1].operands[1].type != X86_OP_MEM
                or prior_writers[-1].reg_name(
                    prior_writers[-1].operands[1].mem.base
                ) != "rdi"):
            return None
        if index < 2 or instructions[index - 1].mnemonic != "je":
            return None
        # A NULL optional output may skip only its own store. It must not
        # bypass subsequent outputs, which still need to receive their fields.
        branch = instructions[index - 1]
        if (len(branch.operands) != 1 or branch.operands[0].type != X86_OP_IMM
                or int(branch.operands[0].imm) != insn.address + insn.size):
            return None
        guard = instructions[index - 2]
        if (guard.mnemonic != "test" or len(guard.operands) != 2
                or any(op.type != X86_OP_REG for op in guard.operands)
                or {_reg(guard, op) for op in guard.operands} != {out}):
            return None
        if out in fields:
            return None
        fields[out] = field_registers[value]
    if set(fields) != set(output_registers):
        return None
    ordered = [fields[r] for r in ("rsi", "rdx", "rcx")]
    return dict(zip(_ARGUMENT_REGISTERS, ordered)) if ordered[1:] == [ordered[0] + 4, ordered[0] + 8] else None


def _getter_i386(instructions) -> dict[str, int] | None:
    # The ABI's four stack arguments are tracked through the actual loads and
    # stores; the null-library branch must remain present.
    if not any(i.mnemonic == "mov" and len(i.operands) == 2
               and i.operands[0].type == X86_OP_REG
               and i.operands[1].type == X86_OP_MEM
               and i.reg_name(i.operands[1].mem.base) == "ebp"
               and int(i.operands[1].mem.disp) == 8 for i in instructions):
        return None
    valid_addresses = {insn.address for insn in instructions}
    if any(insn.mnemonic.startswith("j") and (
        not insn.operands or insn.operands[-1].type != X86_OP_IMM
        or int(insn.operands[-1].imm) not in valid_addresses
    ) for insn in instructions):
        return None
    library_registers: set[str] = set()
    output_arguments: dict[str, int] = {}
    fields_by_register: dict[str, set[int]] = {}
    fields_by_output: dict[int, int] = {}
    for index, insn in enumerate(instructions):
        written = _written_registers(insn)
        if written is None:
            return None
        fields_by_register = {
            register: offsets for register, offsets in fields_by_register.items()
            if _register_key(register) not in written
        }
        library_registers = {
            register for register in library_registers
            if _register_key(register) not in written
        }
        if insn.mnemonic == "mov" and len(insn.operands) == 2:
            dst, src = insn.operands
            if dst.type == X86_OP_REG:
                name = _reg(insn, dst)
                if src.type == X86_OP_MEM and insn.reg_name(src.mem.base) == "ebp":
                    offset = int(src.mem.disp)
                    if offset == 8:
                        library_registers.add(name)
                    elif offset in (12, 16, 20):
                        output_arguments[name] = offset
                elif src.type == X86_OP_MEM and src.mem.base:
                    base = insn.reg_name(src.mem.base)
                    if base in library_registers and src.size == 4:
                        fields_by_register.setdefault(name, set()).add(int(src.mem.disp))
        if insn.mnemonic == "mov" and len(insn.operands) == 2:
            dst, src = insn.operands
            if (dst.type == X86_OP_MEM and src.type == X86_OP_REG
                    and int(dst.mem.disp) == 0 and dst.mem.base):
                output = output_arguments.get(insn.reg_name(dst.mem.base))
                value_fields = fields_by_register.get(_reg(insn, src), set())
                if output in (12, 16, 20) and len(value_fields) == 1:
                    if index < 2:
                        return None
                    guard, branch = instructions[index - 2:index]
                    output_register = insn.reg_name(dst.mem.base)
                    if (guard.mnemonic != "test" or guard.op_str.split(",", 1)[0].strip() != output_register
                            or branch.mnemonic != "je" or not branch.operands
                            or branch.operands[0].type != X86_OP_IMM
                            or int(branch.operands[0].imm) <= insn.address):
                        return None
                    if output in fields_by_output:
                        return None
                    fields_by_output[output] = next(iter(value_fields))
    if set(fields_by_output) != {12, 16, 20}:
        return None
    ordered = [fields_by_output[n] for n in (12, 16, 20)]
    return dict(zip(_ARGUMENT_REGISTERS, ordered)) if ordered[1:] == [ordered[0] + 4, ordered[0] + 8] else None


def _getter_aarch64(instructions) -> dict[str, int] | None:
    valid_addresses = {insn.address for insn in instructions}
    if (not instructions or instructions[0].mnemonic != "cbz"
            or len(instructions[0].operands) != 2
            or _reg(instructions[0], instructions[0].operands[0]) != "x0"
            or instructions[0].operands[1].type != X86_OP_IMM
            or int(instructions[0].operands[1].imm) not in valid_addresses
            or any(insn.mnemonic in ("cbz", "cbnz", "b") and (
                not insn.operands or insn.operands[-1].type != X86_OP_IMM
                or int(insn.operands[-1].imm) not in valid_addresses
            ) for insn in instructions)):
        return None
    fields: dict[str, int] = {}
    loaded: dict[str, int] = {}
    for insn in instructions:
        written = _written_registers(insn)
        if written is None:
            return None
        loaded = {register: offset for register, offset in loaded.items()
                  if _register_key(register) not in written}
        if insn.mnemonic == "ldp" and len(insn.operands) == 3:
            left, right, source = insn.operands
            if (source.type == X86_OP_MEM and insn.reg_name(source.mem.base) == "x0"
                    and left.type == right.type == X86_OP_REG
                    and insn.reg_name(left.reg).startswith("w")
                    and insn.reg_name(right.reg).startswith("w")):
                start = int(source.mem.disp)
                loaded[_reg(insn, left)] = start
                loaded[_reg(insn, right)] = start + 4
        elif insn.mnemonic == "ldr" and len(insn.operands) == 2:
            dst, src = insn.operands
            if (dst.type == X86_OP_REG and src.type == X86_OP_MEM
                    and insn.reg_name(src.mem.base) == "x0"
                    and insn.reg_name(dst.reg).startswith("w")):
                loaded[_reg(insn, dst)] = int(src.mem.disp)
        elif insn.mnemonic == "str" and len(insn.operands) == 2:
            value, out = insn.operands
            if value.type != X86_OP_REG or out.type != X86_OP_MEM or int(out.mem.disp) != 0:
                continue
            base = insn.reg_name(out.mem.base)
            if base not in ("x1", "x2", "x3") or _reg(insn, value) not in loaded:
                continue
            prior = instructions[max(0, instructions.index(insn) - 1)]
            if (prior.mnemonic != "cbz" or prior.op_str.split(",", 1)[0].strip() != base
                    or int(prior.operands[1].imm) != insn.address + insn.size):
                return None
            if base in fields:
                return None
            fields[base] = loaded[_reg(insn, value)]
    if set(fields) != {"x1", "x2", "x3"}:
        return None
    ordered = [fields[r] for r in ("x1", "x2", "x3")]
    return dict(zip(_ARGUMENT_REGISTERS, ordered)) if ordered[1:] == [ordered[0] + 4, ordered[0] + 8] else None


def _getter_arm(instructions) -> dict[str, int] | None:
    valid_addresses = {insn.address for insn in instructions}
    if (len(instructions) < 3 or instructions[1].mnemonic != "cmp"
            or instructions[2].mnemonic != "beq"
            or instructions[1].op_str != "r0, #0"
            or not instructions[2].operands
            or instructions[2].operands[-1].type != X86_OP_IMM
            or int(instructions[2].operands[-1].imm) not in valid_addresses
            or any(insn.mnemonic.startswith("b") and insn.mnemonic != "bl"
                   and insn.mnemonic != "blx" and insn.mnemonic != "bx"
                   and (not insn.operands or insn.operands[-1].type != X86_OP_IMM
                        or int(insn.operands[-1].imm) not in valid_addresses)
                   for insn in instructions)):
        return None
    loaded: dict[str, int] = {}
    fields: dict[str, int] = {}
    for insn in instructions:
        written = _written_registers(insn)
        if written is None:
            return None
        loaded = {register: offset for register, offset in loaded.items()
                  if _register_key(register) not in written}
        if insn.mnemonic == "ldr" and len(insn.operands) == 2:
            dst, src = insn.operands
            if (dst.type == X86_OP_REG and src.type == X86_OP_MEM
                    and insn.reg_name(src.mem.base) == "r0"):
                loaded[_reg(insn, dst)] = int(src.mem.disp)
        elif insn.mnemonic.startswith("str") and len(insn.operands) == 2:
            value, out = insn.operands
            if (value.type == X86_OP_REG and out.type == X86_OP_MEM
                    and int(out.mem.disp) == 0 and _reg(insn, value) in loaded):
                base = insn.reg_name(out.mem.base)
                if base not in ("r1", "r2", "r3"):
                    return None
                if insn.mnemonic != "strne":
                    return None
                index = instructions.index(insn)
                if (index == 0 or instructions[index - 1].mnemonic != "cmp"
                        or not instructions[index - 1].op_str.startswith(base + ", #0")):
                    return None
                if base in fields:
                    return None
                fields[base] = loaded[_reg(insn, value)]
    if set(fields) != {"r1", "r2", "r3"}:
        return None
    ordered = [fields[r] for r in ("r1", "r2", "r3")]
    return dict(zip(_ARGUMENT_REGISTERS, ordered)) if ordered[1:] == [ordered[0] + 4, ordered[0] + 8] else None


def _getter_fields_android(image: _Image, instructions) -> dict[str, int] | None:
    getter = {
        "EM_X86_64": _getter_x64,
        "EM_386": _getter_i386,
        "EM_AARCH64": _getter_aarch64,
        "EM_ARM": _getter_arm,
    }.get(image.machine)
    return getter(instructions) if getter else None


def _allocator_guard_details(instructions, call_mnemonic: str, result_register: str):
    """Return the allocator call and its explicit null-result branch.

    The branch must test the call's actual return register. In particular,
    ``cmp reg, reg`` is not a null check: it sets ZF for every possible value.
    """
    for index, call in enumerate(instructions):
        if call.mnemonic != call_mnemonic:
            continue
        check_index = index + 1
        if (check_index < len(instructions)
                and instructions[check_index].mnemonic == "add"
                and result_register == "eax"
                and len(instructions[check_index].operands) == 2
                and instructions[check_index].operands[0].type == X86_OP_REG
                and instructions[check_index].reg_name(
                    instructions[check_index].operands[0].reg
                ) == "esp"):
            check_index += 1
        if check_index >= len(instructions):
            continue
        check = instructions[check_index]

        # AArch64's CBZ directly tests the result register.
        if check.mnemonic == "cbz":
            if (len(check.operands) == 2
                    and check.operands[0].type == X86_OP_REG
                    and check.reg_name(check.operands[0].reg) == result_register
                    and check.operands[1].type == X86_OP_IMM
                    and int(check.operands[1].imm) > check.address):
                return index, check_index, int(check.operands[1].imm)
            continue

        if check_index + 1 >= len(instructions):
            continue
        branch = instructions[check_index + 1]
        if (branch.mnemonic not in ("je", "jz", "beq")
                or not branch.operands or branch.operands[-1].type != X86_OP_IMM
                or int(branch.operands[-1].imm) <= branch.address):
            continue

        valid_zero_check = False
        if check.mnemonic == "test" and len(check.operands) == 2:
            left, right = check.operands
            valid_zero_check = (
                left.type == X86_OP_REG and right.type == X86_OP_REG
                and check.reg_name(left.reg) == result_register
                and check.reg_name(right.reg) == result_register
            )
        elif check.mnemonic == "cmp" and len(check.operands) == 2:
            left, right = check.operands
            # ARM's CMP result,#0 is a valid zero test. Register-vs-register
            # comparisons such as CMP r0,r0 are always equal and are rejected.
            valid_zero_check = (
                left.type == X86_OP_REG and right.type == X86_OP_IMM
                and check.reg_name(left.reg) == result_register
                and int(right.imm) == 0
            )
        if valid_zero_check:
            return index, check_index + 1, int(branch.operands[-1].imm)
    return None


def _has_branch_before_store(instructions, guard_branch_index: int, store_addresses) -> bool:
    """Reject a linear store proof when control flow can skip part of it."""
    if not store_addresses:
        return True
    end_address = max(store_addresses)
    for insn in instructions[guard_branch_index + 1:]:
        if insn.address >= end_address:
            break
        mnemonic = insn.mnemonic
        if (mnemonic.startswith(("j", "cbz", "cbnz"))
                or (mnemonic.startswith("b") and mnemonic not in ("bl", "blx", "blr"))):
            return True
    return False


def _initializer_x64(image: _Image, instructions, fields: dict[str, int]) -> dict[int, int] | None:
    call_index = next((n for n, i in enumerate(instructions)
                       if i.mnemonic == "call" and i.operands
                       and i.operands[0].type == X86_OP_MEM
                       and i.reg_name(i.operands[0].mem.base) == "rdi"
                       and int(i.operands[0].mem.disp) == 8), None)
    if call_index is None:
        return None
    guard = _allocator_guard_details(instructions[call_index:], "call", "rax")
    if guard is None or guard[0] != 0:
        return None
    base = None
    values: dict[str, int] = {}
    stores: dict[int, int] = {}
    store_addresses: list[int] = []
    for insn in instructions[call_index + 3:]:
        if insn.mnemonic in ("ret", "jmp"):
            break
        written = _written_registers(insn)
        if written is None:
            return None
        values = {register: value for register, value in values.items()
                  if _register_key(register) not in written}
        if base is not None and _register_key(base) in written:
            base = None
        if insn.mnemonic in ("mov", "movabs") and len(insn.operands) == 2:
            dst, src = insn.operands
            if dst.type == X86_OP_REG and src.type == X86_OP_REG and _register_key(_reg(insn, src)) == "rax":
                base = _reg(insn, dst)
            elif dst.type == X86_OP_REG and src.type == X86_OP_IMM:
                values[_register_key(_reg(insn, dst))] = int(src.imm)
            elif dst.type == X86_OP_MEM and base and insn.reg_name(dst.mem.base) == base:
                offset = int(dst.mem.disp)
                if offset in (fields["rsi"], fields["rdx"], fields["rcx"]):
                    if offset in stores or (dst.size == 8 and offset + 4 in stores):
                        return None
                    if src.type == X86_OP_REG and _register_key(_reg(insn, src)) in values:
                        value = values[_register_key(_reg(insn, src))]
                        if dst.size == 8 and offset == fields["rsi"]:
                            stores[offset] = value & 0xffffffff
                            stores[offset + 4] = (value >> 32) & 0xffffffff
                            store_addresses.append(insn.address)
                        elif dst.size == 4 and src.type == X86_OP_IMM:
                            stores[offset] = int(src.imm) & 0xffffffff
                            store_addresses.append(insn.address)
                        else:
                            return None
                    elif dst.size == 4 and src.type == X86_OP_IMM:
                        stores[offset] = int(src.imm) & 0xffffffff
                        store_addresses.append(insn.address)
    failure = guard[2]
    if (not base or any(offset not in stores for offset in fields.values())
            or not store_addresses or failure <= max(store_addresses)
            or _has_branch_before_store(instructions[call_index:], guard[1], store_addresses)):
        return None
    if not _audit_initializer_memory_writes(
        image, image.machine, instructions, call_index, fields, store_addresses
    ):
        return None
    return stores


def _initializer_i386(image: _Image, instructions, fields: dict[str, int]) -> dict[int, int] | None:
    call_index = next((n for n, i in enumerate(instructions)
                       if i.mnemonic == "call" and i.operands
                       and i.operands[0].type == X86_OP_MEM
                       and i.reg_name(i.operands[0].mem.base) == "edi"
                       and int(i.operands[0].mem.disp) == 4), None)
    if call_index is None:
        return None
    guard = _allocator_guard_details(instructions[call_index:], "call", "eax")
    if guard is None or guard[0] != 0:
        return None
    stores: dict[int, int] = {}
    store_addresses: list[int] = []
    base_valid = True
    for insn in instructions[call_index + 3:]:
        if insn.mnemonic.startswith("ret"):
            break
        written = _written_registers(insn)
        if written is None:
            return None
        if _register_key("eax") in written and set(stores) != set(fields.values()):
            return None
        if (not base_valid and insn.operands and insn.operands[0].type == X86_OP_MEM
                and insn.reg_name(insn.operands[0].mem.base) == "eax"):
            return None
        if _register_key("eax") in written:
            base_valid = False
        if insn.mnemonic != "mov" or len(insn.operands) != 2:
            continue
        dst, src = insn.operands
        if (dst.type == X86_OP_MEM and insn.reg_name(dst.mem.base) == "eax"
                and src.type == X86_OP_IMM and dst.size == 4):
            if not base_valid:
                return None
            offset = int(dst.mem.disp)
            if offset in fields.values():
                if offset in stores:
                    return None
                stores[offset] = int(src.imm) & 0xffffffff
                store_addresses.append(insn.address)
    failure = guard[2]
    if not (set(stores) == set(fields.values()) and store_addresses
            and failure > max(store_addresses)
            and not _has_branch_before_store(
                instructions[call_index:], guard[1], store_addresses
            )):
        return None
    return stores if _audit_initializer_memory_writes(
        image, image.machine, instructions, call_index, fields, store_addresses
    ) else None


def _initializer_aarch64(image: _Image, instructions, fields: dict[str, int]) -> dict[int, int] | None:
    call_index = next((n for n, i in enumerate(instructions) if i.mnemonic == "blr"), None)
    if call_index is None:
        return None
    guard = _allocator_guard_details(instructions[call_index:], "blr", "x0")
    if guard is None or guard[0] != 0:
        return None
    if not any(i.mnemonic == "mov" and len(i.operands) == 2
               and _reg(i, i.operands[0]) == "x20" and _reg(i, i.operands[1]) == "x0"
               for i in instructions[:call_index]):
        return None
    if not any(i.mnemonic == "ldr" and len(i.operands) == 2
               and _reg(i, i.operands[0]) == "x8" and i.operands[1].type == X86_OP_MEM
               and i.reg_name(i.operands[1].mem.base) == "x20"
               and int(i.operands[1].mem.disp) == 8 for i in instructions[:call_index]):
        return None
    base = None
    page_registers: dict[str, int] = {}
    stores: dict[int, int] = {}
    store_addresses: list[int] = []
    for insn in instructions[call_index + 3:]:
        if insn.mnemonic in ("ret", "b"):
            break
        written = _written_registers(insn)
        if written is None:
            return None
        page_registers = {register: value for register, value in page_registers.items()
                          if _register_key(register) not in written}
        if base is not None and _register_key(base) in written:
            base = None
        if insn.mnemonic == "mov" and len(insn.operands) == 2:
            dst, src = insn.operands
            if dst.type == X86_OP_REG and src.type == X86_OP_REG and _register_key(_reg(insn, src)) == "x0":
                base = _reg(insn, dst)
        elif insn.mnemonic == "adrp" and len(insn.operands) == 2:
            page_registers[_reg(insn, insn.operands[0])] = int(insn.operands[1].imm) & ~0xfff
        elif insn.mnemonic == "ldr" and len(insn.operands) == 2:
            dst, src = insn.operands
            if dst.type == X86_OP_REG and src.type == X86_OP_MEM:
                literal_page = page_registers.get(insn.reg_name(src.mem.base))
                if literal_page is not None and insn.reg_name(dst.reg).startswith("d"):
                    literal_address = literal_page + int(src.mem.disp)
                    raw = image.bytes_at(literal_address, 8)
                    if raw is None:
                        return None
                    stores[-1] = int.from_bytes(raw, "little")
                    page_registers[_register_key(_reg(insn, dst))] = stores[-1]
        elif insn.mnemonic == "mov" and len(insn.operands) == 2:
            pass
        elif insn.mnemonic == "str" and len(insn.operands) == 2:
            value, target = insn.operands
            if (target.type != X86_OP_MEM or base is None
                    or insn.reg_name(target.mem.base) != base):
                continue
            offset = int(target.mem.disp)
            if offset not in fields.values():
                continue
            if value.type != X86_OP_REG:
                return None
            source = _register_key(_reg(insn, value))
            if source in page_registers:
                raw_value = page_registers[source]
                if insn.reg_name(value.reg).startswith("d") and offset == fields["rsi"]:
                    if offset in stores or offset + 4 in stores:
                        return None
                    stores[offset] = raw_value & 0xffffffff
                    stores[offset + 4] = (raw_value >> 32) & 0xffffffff
                    store_addresses.append(insn.address)
                else:
                    return None
            else:
                prior_writer = None
                for prior_candidate in reversed(instructions[:instructions.index(insn)]):
                    prior_writes = _written_registers(prior_candidate)
                    if prior_writes is None:
                        return None
                    if source in prior_writes:
                        prior_writer = prior_candidate
                        break
                if (prior_writer is None or prior_writer.mnemonic != "mov"
                        or len(prior_writer.operands) != 2
                        or prior_writer.operands[0].type != X86_OP_REG
                        or _register_key(_reg(prior_writer, prior_writer.operands[0])) != source
                        or prior_writer.operands[1].type not in (X86_OP_IMM, X86_OP_REG)):
                    return None
                if prior_writer.operands[1].type == X86_OP_IMM:
                    if offset in stores:
                        return None
                    stores[offset] = int(prior_writer.operands[1].imm) & 0xffffffff
                    store_addresses.append(insn.address)
                elif _register_key(_reg(prior_writer, prior_writer.operands[1])) in page_registers:
                    if offset in stores:
                        return None
                    stores[offset] = page_registers[
                        _register_key(_reg(prior_writer, prior_writer.operands[1]))
                    ] & 0xffffffff
                    store_addresses.append(insn.address)
                else:
                    return None
    failure = guard[2]
    return (stores if set(fields.values()).issubset(stores) and store_addresses
            and failure > max(store_addresses)
            and not _has_branch_before_store(
                instructions[call_index:], guard[1], store_addresses
            ) and _audit_initializer_memory_writes(
                image, image.machine, instructions, call_index, fields, store_addresses
            ) else None)


def _initializer_arm(image: _Image, instructions, fields: dict[str, int]) -> dict[int, int] | None:
    call_index = next((n for n, i in enumerate(instructions) if i.mnemonic == "blx"), None)
    if call_index is None:
        return None
    guard = _allocator_guard_details(instructions[call_index:], "blx", "r0")
    if guard is None or guard[0] != 0:
        return None
    if not any(i.mnemonic == "mov" and len(i.operands) == 2
               and _reg(i, i.operands[0]) == "r5" and _reg(i, i.operands[1]) == "r0"
               for i in instructions[:call_index]):
        return None
    if not any(i.mnemonic == "ldr" and len(i.operands) == 2
               and _reg(i, i.operands[0]) == "r2" and i.operands[1].type == X86_OP_MEM
               and i.reg_name(i.operands[1].mem.base) == "r5"
               and int(i.operands[1].mem.disp) == 4 for i in instructions[:call_index]):
        return None
    base = None
    values: dict[str, int] = {}
    stores: dict[int, int] = {}
    store_addresses: list[int] = []
    for insn in instructions[call_index + 3:]:
        if insn.mnemonic.startswith("pop"):
            break
        written = _written_registers(insn)
        if written is None:
            return None
        values = {register: value for register, value in values.items()
                  if _register_key(register) not in written}
        if base is not None and _register_key(base) in written:
            base = None
        if insn.mnemonic == "mov" and len(insn.operands) == 2:
            dst, src = insn.operands
            if dst.type == X86_OP_REG and src.type == X86_OP_REG and _register_key(_reg(insn, src)) == "r0":
                base = _reg(insn, dst)
            elif dst.type == X86_OP_REG and src.type == X86_OP_IMM:
                values[_register_key(_reg(insn, dst))] = int(src.imm)
        if insn.mnemonic == "stmib" and len(insn.operands) >= 3:
            target = insn.operands[0]
            if base and target.type == X86_OP_REG and _reg(insn, target) == base:
                names = [_register_key(_reg(insn, operand)) for operand in insn.operands[1:]]
                if len(names) != 2 or any(name not in values for name in names):
                    return None
                if fields["rsi"] in stores or fields["rdx"] in stores:
                    return None
                stores[fields["rsi"]] = values[names[0]]
                stores[fields["rdx"]] = values[names[1]]
                store_addresses.append(insn.address)
        elif insn.mnemonic == "str" and len(insn.operands) == 2:
            value, target = insn.operands
            if (base and value.type == X86_OP_REG and target.type == X86_OP_MEM
                    and _register_key(insn.reg_name(target.mem.base)) == _register_key(base)):
                offset = int(target.mem.disp)
                source = _register_key(_reg(insn, value))
                if offset in fields.values() and source in values:
                    if offset in stores:
                        return None
                    stores[offset] = values[source]
                    store_addresses.append(insn.address)
    failure = guard[2]
    return (stores if set(fields.values()).issubset(stores) and store_addresses
            and failure > max(store_addresses)
            and not _has_branch_before_store(
                instructions[call_index:], guard[1], store_addresses
            ) and _audit_initializer_memory_writes(
                image, image.machine, instructions, call_index, fields, store_addresses
            ) else None)


def _android_paired_version(image: _Image, getter_instructions, initializer_instructions):
    fields = _getter_fields_android(image, getter_instructions)
    if fields is None:
        return None
    initializer = {
        "EM_X86_64": lambda: _initializer_x64(image, initializer_instructions, fields),
        "EM_386": lambda: _initializer_i386(image, initializer_instructions, fields),
        "EM_AARCH64": lambda: _initializer_aarch64(image, initializer_instructions, fields),
        "EM_ARM": lambda: _initializer_arm(image, initializer_instructions, fields),
    }.get(image.machine)
    constants = initializer() if initializer else None
    if constants is None:
        return None
    return tuple(constants[fields[name]] for name in _ARGUMENT_REGISTERS), fields


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
        recovered = _android_paired_version(image, getter[1], initializer[1])
        if recovered is None:
            return []
        version, fields = recovered
        proof = (
            f"defined FT_Library_Version ({image.machine}) reads fields at offsets "
            f"{fields['rsi']:#x}/{fields['rdx']:#x}/{fields['rcx']:#x} and maps them "
            "to the three API outputs; defined FT_New_Library writes the matching "
            "constants only on the non-NULL result edge of its library-provided "
            "allocator (allocation-success); all modeled and unknown memory writes "
            "in the initializer are conservatively audited"
        )
        major, minor, patch = version
        if not (1 <= major <= 99 and 0 <= minor <= 999 and 0 <= patch <= 999):
            return []
        evidence = proof
        return [StaticVersionMatch("FreeType", ".".join(map(str, version)), evidence, 0.98)]
    except (ELFError, CsError, OSError, ValueError, TypeError, KeyError, IndexError,
            OverflowError, AttributeError):
        return []
