"""Bounded ELF32 VerifyVersion proofs. Firmware code is never loaded or executed.

Only a straight prefix, one signed minLibraryVersion guard and one straight
failure block are modeled. Unknown paths, operands and decoder errors fail closed.
"""

from __future__ import annotations

import json

from capstone import CS_AC_WRITE, CS_GRP_CALL, CS_GRP_INT, CS_GRP_IRET, CS_GRP_JUMP, CS_GRP_RET
from capstone.arm import (
    ARM_CC_AL,
    ARM_CC_GE,
    ARM_CC_GT,
    ARM_CC_LE,
    ARM_CC_LT,
    ARM_INS_B,
    ARM_OP_IMM,
    ARM_OP_MEM,
    ARM_OP_REG,
)
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from firmware_scanner.extraction.semantic_version import VERIFY, VERSION_STRING, ELFView
from firmware_scanner.extraction.static_version import StaticVersionMatch

_MINIMUM = ("parameter", "min_library_version")
_CONTROL = {CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_GRP_INT, CS_GRP_IRET}
# Decoder control groups omit some terminating/privileged instructions, including
# UD2 and UDF. Only these supported fallthrough forms may connect proof steps.
_FALLTHROUGH = {
    True: frozenset(
        (
            "mov",
            "movs",
            "movw",
            "movt",
            "ldr",
            "str",
            "add",
            "adds",
            "sub",
            "subs",
            "push",
            "pop",
            "ldm",
            "cmp",
            "cmn",
            "nop",
        )
    ),
    False: frozenset(("mov", "lea", "add", "sub", "and", "push", "pop", "cmp", "nop", "endbr32")),
}
_ARM_ALIASES = {
    "sb": "r9",
    "sl": "r10",
    "fp": "r11",
    "ip": "r12",
    "sp": "r13",
    "lr": "r14",
    "pc": "r15",
}
_X86_ALIASES = {
    part: full
    for full, parts in {
        "eax": ("ax", "al", "ah"),
        "ebx": ("bx", "bl", "bh"),
        "ecx": ("cx", "cl", "ch"),
        "edx": ("dx", "dl", "dh"),
        "esi": ("si",),
        "edi": ("di",),
        "esp": ("sp",),
        "ebp": ("bp",),
    }.items()
    for part in parts
}


def _arm_register(name: str) -> str:
    return _ARM_ALIASES.get(name, name)


def _register(insn, register, arm):
    name = insn.reg_name(register)
    if not isinstance(name, str) or not name:
        raise ValueError("unnamed register")
    return _arm_register(name) if arm else _X86_ALIASES.get(name, name)


def _writes(insn, arm):
    # Decoder metadata is part of the proof, not an optional hint.
    try:
        _reads, writes = insn.regs_access()
        return {_register(insn, register, arm) for register in writes}
    except Exception as exc:
        raise ValueError("register access unavailable") from exc


def _control(insn, arm):
    writes = _writes(insn, arm)
    return bool(_CONTROL.intersection(insn.groups) or (arm and "r15" in writes))


def _version(value):
    if not isinstance(value, int) or not 1_000_000 <= value < 100_000_000:
        return None
    return f"{value // 1000000}.{value // 1000 % 1000}.{value % 1000}"


def classify_version_roles(header_version, min_library_version, min_header_version):
    values = [_version(v) for v in (header_version, min_library_version, min_header_version)]
    if None in values:
        return None
    return dict(
        zip(("header_version", "min_library_version", "min_header_version"), values),
        library_version="unknown",
    )


def recover_arm_version(proof):
    return _recover(proof, ("arm", "arm-thumb"))


def recover_x86_32_version(proof):
    return _recover(proof, ("x86-32",))


def _recover(proof, architectures):
    """Validate the serialized role evidence; machine proof is built below."""
    try:
        constant = proof.comparison_constant
        if (
            proof.architecture not in architectures
            or not proof.failure_edge
            or proof.comparison_role != "min_library_version"
            or tuple(proof.version_string_inputs) != ("min_library_version", constant)
            or not _messages_match(proof.failure_messages)
            or (proof.architecture == "x86-32" and proof.comparison_boundary != constant + 1)
        ):
            return None
        version = _version(constant)
        if version:
            return {
                "version": version,
                "library_version": constant,
                "function_vaddr": hex(
                    proof.function_vaddr & ~1
                    if "arm" in proof.architecture
                    else proof.function_vaddr
                ),
            }
    except (AttributeError, TypeError, ValueError):
        pass
    return None


def _messages_match(messages):
    return any("requires version" in text for text in messages) and any(
        "installed version" in text for text in messages
    )


class _ArmState:
    def __init__(self, image, thumb):
        self.image, self.thumb = image, thumb
        self.regs = {
            "r0": ("parameter", "header_version"),
            "r1": _MINIMUM,
            "r2": ("parameter", "filename"),
        }

    def value(self, insn, op):
        if op.shift.type:
            return None
        if op.type == ARM_OP_IMM:
            return ("constant", int(op.imm) & 0xFFFFFFFF)
        if op.type == ARM_OP_REG:
            register = _register(insn, op.reg, True)
            if register == "r15":
                return ("pointer", insn.address + (4 if self.thumb else 8))
            return self.regs.get(register)
        return None

    def step(self, insn):
        writes = _writes(insn, True)
        ops, assignment = insn.operands, None
        mnemonic = insn.mnemonic.removesuffix(".w")
        if insn.cc == ARM_CC_AL and ops and ops[0].type == ARM_OP_REG:
            destination = _register(insn, ops[0].reg, True)
            if mnemonic in ("mov", "movs", "movw", "movt") and len(ops) == 2:
                source = self.value(insn, ops[1])
                if mnemonic == "movt":
                    previous = self.regs.get(destination)
                    if (
                        previous
                        and previous[0] == "constant"
                        and source
                        and source[0] == "constant"
                    ):
                        assignment = (
                            "constant",
                            (previous[1] & 0xFFFF) | ((source[1] & 0xFFFF) << 16),
                        )
                else:
                    assignment = source
            elif mnemonic == "ldr" and len(ops) == 2 and ops[1].type == ARM_OP_MEM:
                mem = ops[1].mem
                if insn.reg_name(mem.base) == "pc" and not mem.index and not insn.writeback:
                    pc = insn.address + (4 if self.thumb else 8)
                    literal = ((pc & ~3) if self.thumb else pc) + mem.disp
                    raw = self.image.read(literal, 4, readonly=True)
                    if raw is not None and len(raw) == 4:
                        assignment = ("constant", int.from_bytes(raw, "little"))
            elif mnemonic in ("add", "adds") and len(ops) in (2, 3):
                left = self.regs.get(destination) if len(ops) == 2 else self.value(insn, ops[1])
                right = self.value(insn, ops[-1])
                if (
                    left
                    and right
                    and left[0] in ("constant", "pointer")
                    and right[0] in ("constant", "pointer")
                ):
                    kind = "pointer" if "pointer" in (left[0], right[0]) else "constant"
                    assignment = (kind, (left[1] + right[1]) & 0xFFFFFFFF)
        # Always invalidate all reported writes, including pop/ldm, conditional
        # instructions, non-PC loads, writeback bases and register aliases.
        for register in writes:
            self.regs.pop(register, None)
        if insn.group(CS_GRP_CALL):
            for register in ("r0", "r1", "r2", "r3", "r12", "r14"):
                self.regs.pop(register, None)
        if assignment is not None:
            self.regs[destination] = assignment


def _arm_value(image, instructions, boundary, thumb):
    """Compatibility diagnostic for the original prefix controls."""
    state, compares = _ArmState(image, thumb), []
    for insn in instructions[: boundary + 1]:
        if _control(insn, True):
            return {}, []
        if insn.mnemonic == "cmp" and insn.cc == ARM_CC_AL:
            compares.append((insn.address, *(state.value(insn, op) for op in insn.operands), "cmp"))
        state.step(insn)
    return state.regs, compares


def _x86_callee(image, target, registers):
    """Resolve an actual aligned PLT jmp/GOT relocation, never a slot ordinal."""
    plt = image.elf.get_section_by_name(".plt")
    got = image.elf.get_section_by_name(".got.plt")
    rel = image.elf.get_section_by_name(".rel.plt")
    if plt is not None and int(plt["sh_addr"]) <= target < int(plt["sh_addr"]) + int(
        plt["sh_size"]
    ):
        start = int(plt["sh_addr"])
        if (
            got is None
            or rel is None
            or target < start + 16
            or (target - start) % 16
            or target + 16 > start + int(plt["sh_size"])
        ):
            raise ValueError("unaligned or incomplete PLT stub")
        stub = image.instructions(target, 16)
        if len(stub) < 3:
            raise ValueError("incomplete PLT stub")
        jump, push, resolver = stub[:3]
        for insn in stub:
            _writes(insn, False)
        if (
            jump.mnemonic != "jmp"
            or len(jump.operands) != 1
            or jump.operands[0].type != X86_OP_MEM
            or jump.operands[0].size != 4
        ):
            raise ValueError("PLT stub does not start with jmp MEM")
        mem = jump.operands[0].mem
        if mem.index or mem.segment:
            raise ValueError("unsupported PLT addressing")
        got_base = int(got["sh_addr"])
        if jump.reg_name(mem.base) == "ebx":
            base = registers.get("ebx")
            if base not in (("constant", got_base), ("pointer", got_base)):
                raise ValueError("unproven PLT EBX base")
            slot = got_base + int(mem.disp)
        elif not mem.base:
            slot = int(mem.disp) & 0xFFFFFFFF
        else:
            raise ValueError("unsupported PLT base")
        if not got_base <= slot <= got_base + int(got["sh_size"]) - 4 or (slot - got_base) % 4:
            raise ValueError("GOT slot outside .got.plt")
        if image.read(slot, 4) is None:
            raise ValueError("GOT slot is not file-backed")
        matches = [
            (index, relocation)
            for index, relocation in enumerate(rel.iter_relocations())
            if int(relocation["r_offset"]) == slot and int(relocation["r_info_type"]) == 7
        ]
        if len(matches) != 1:
            raise ValueError("missing or ambiguous GOT JUMP_SLOT relocation")
        index, relocation = matches[0]
        if (
            push.mnemonic != "push"
            or len(push.operands) != 1
            or push.operands[0].type != X86_OP_IMM
            or int(push.operands[0].imm) != index * int(rel["sh_entsize"])
            or resolver.mnemonic != "jmp"
            or len(resolver.operands) != 1
            or resolver.operands[0].type != X86_OP_IMM
            or int(resolver.operands[0].imm) != start
        ):
            raise ValueError("inconsistent PLT resolver")
        symbol = image.elf.get_section(rel["sh_link"]).get_symbol(relocation["r_info_sym"])
        name = symbol.name
        if name == VERSION_STRING and (
            symbol["st_shndx"] in (0, "SHN_UNDEF")
            or int(symbol["st_value"]) != image.functions[VERSION_STRING][0]
        ):
            raise ValueError("PLT VersionString is not this library's definition")
        return name, {
            "plt_entry_vaddr": hex(target),
            "got_vaddr": hex(slot),
            "got_base_vaddr": hex(got_base),
        }
    for name, (address, _size) in image.functions.items():
        if address == target:
            return name, {"target_vaddr": hex(target)}
    return None, {}


class _X86State:
    def __init__(self, frame_address):
        self.regs, self.pushed = {}, []
        self.frame_address, self.frame, self.pic_return = frame_address, False, None

    def value(self, insn, op):
        if op.type == X86_OP_IMM:
            return ("constant", int(op.imm) & 0xFFFFFFFF)
        if op.type == X86_OP_REG and op.size == 4:
            return self.regs.get(_register(insn, op.reg, False))
        if op.type == X86_OP_MEM and op.size == 4 and self.frame:
            mem = op.mem
            if insn.reg_name(mem.base) == "ebp" and not mem.index and not mem.segment:
                return {
                    8: ("parameter", "header_version"),
                    12: _MINIMUM,
                    16: ("parameter", "filename"),
                }.get(int(mem.disp))
        return None

    def step(self, insn, pic=False):
        writes, ops, assignment = _writes(insn, False), insn.operands, None
        mnemonic, destination = insn.mnemonic, None
        prologue = (
            insn.address == self.frame_address and mnemonic == "mov" and insn.op_str == "ebp, esp"
        )
        if ops and ops[0].type == X86_OP_REG and ops[0].size == 4:
            destination = _register(insn, ops[0].reg, False)
            if mnemonic == "mov" and len(ops) == 2:
                assignment = self.value(insn, ops[1])
            elif mnemonic == "lea" and len(ops) == 2 and ops[1].type == X86_OP_MEM:
                mem = ops[1].mem
                base = self.regs.get(insn.reg_name(mem.base))
                if (
                    base
                    and base[0] in ("constant", "pointer")
                    and not mem.index
                    and not mem.segment
                ):
                    assignment = ("pointer", (base[1] + int(mem.disp)) & 0xFFFFFFFF)
            elif mnemonic == "add" and len(ops) == 2 and ops[1].type == X86_OP_IMM:
                base = self.regs.get(destination)
                if base and base[0] in ("constant", "pointer"):
                    assignment = (base[0], (base[1] + int(ops[1].imm)) & 0xFFFFFFFF)
            elif mnemonic == "pop":
                assignment = self.pic_return
        if mnemonic == "push" and len(ops) == 1 and ops[0].size == 4:
            self.pushed.append(self.value(insn, ops[0]))
        elif "esp" in writes or any(op.access & CS_AC_WRITE for op in ops if op.type == X86_OP_MEM):
            # No list of arguments may survive an untracked stack/memory write.
            self.pushed.clear()
        elif mnemonic not in ("mov", "lea", "add", "cmp", "nop", "endbr32"):
            self.pushed.clear()
        if any(op.access & CS_AC_WRITE for op in ops if op.type == X86_OP_MEM):
            self.frame = False
        if "ebp" in writes:
            self.frame = prologue
        for register in writes:
            self.regs.pop(register, None)
        if insn.group(CS_GRP_CALL):
            self.pushed.clear()
            for register in ("eax", "ecx", "edx"):
                self.regs.pop(register, None)
        self.pic_return = ("pointer", insn.address + insn.size) if pic else None
        if assignment is not None and destination is not None:
            self.regs[destination] = assignment


def _pic_pair(instructions, index):
    insn = instructions[index]
    return (
        insn.mnemonic == "call"
        and len(insn.operands) == 1
        and insn.operands[0].type == X86_OP_IMM
        and int(insn.operands[0].imm) == insn.address + insn.size
        and index + 1 < len(instructions)
        and instructions[index + 1].mnemonic == "pop"
        and instructions[index + 1].op_str in ("eax", "ebx", "ecx", "edx", "edi", "esi")
    )


def _failure_start(left, right, branch, arm):
    left_is_minimum = left == _MINIMUM
    other = right if left_is_minimum else left
    if (not left_is_minimum and right != _MINIMUM) or not other or other[0] != "constant":
        return None
    ops = branch.operands
    if len(ops) != 1 or ops[0].type != (ARM_OP_IMM if arm else X86_OP_IMM):
        return None
    if arm:
        if branch.id != ARM_INS_B:
            return None
        taken, untaken = (ARM_CC_GT, ARM_CC_LE) if left_is_minimum else (ARM_CC_LT, ARM_CC_GE)
        condition = branch.cc
    else:
        taken, untaken = ("jge", "jl") if left_is_minimum else ("jle", "jg")
        condition = branch.mnemonic
    if condition == taken:
        start = int(ops[0].imm) & (~1 if arm else 0xFFFFFFFF)
    elif condition == untaken:
        start = branch.address + branch.size
    else:
        return None
    return start, other[1]


def _proof(image, function):
    address, size = function
    arm, thumb = image.machine == "EM_ARM", bool(address & 1)
    instructions = image.instructions(address, size)
    if not instructions or len(instructions) > 2048:
        return None
    # ARM literal pools may trail the decoded instructions. Every instruction
    # used below must be contiguous, decoded and backed by the complete symbol.
    if not arm and (
        len(instructions) < 2
        or instructions[0].op_str != "ebp"
        or instructions[0].mnemonic != "push"
        or instructions[1].mnemonic != "mov"
        or instructions[1].op_str != "ebp, esp"
    ):
        return None
    state = _ArmState(image, thumb) if arm else _X86State(instructions[1].address)
    for index, insn in enumerate(instructions):
        if _control(insn, arm):
            if not arm and _pic_pair(instructions, index):
                state.step(insn, pic=True)
                continue
            return None
        if insn.mnemonic.removesuffix(".w") not in _FALLTHROUGH[arm]:
            return None
        if insn.mnemonic == "cmp" and len(insn.operands) == 2:
            left, right = (state.value(insn, op) for op in insn.operands)
            if _MINIMUM in (left, right):
                for branch in instructions[index + 1 : index + 9]:
                    if _control(branch, arm):
                        edge = _failure_start(left, right, branch, arm)
                        if edge:
                            return _failure_proof(
                                image, function, instructions, state, insn, branch, edge
                            )
                        return None
                    if branch.update_flags if arm else "eflags" in _writes(branch, False):
                        return None
                    # Only known non-flag-writing gap forms are accepted.
                    # In particular MSR may report neither update_flags nor a
                    # CPSR write in Capstone, so metadata alone is insufficient.
                    safe = (
                        ("mov", "movw", "movt", "ldr", "str", "add", "sub", "push", "nop")
                        if arm
                        else ("mov", "lea", "push", "nop")
                    )
                    if branch.mnemonic.removesuffix(".w") not in safe or (
                        arm and branch.cc != ARM_CC_AL
                    ):
                        return None
                    state.step(branch)
                return None
        state.step(insn)
    return None


def _failure_proof(image, function, instructions, state, comparison, branch, edge):
    start, boundary = edge
    arm = image.machine == "EM_ARM"
    index = next((i for i, insn in enumerate(instructions) if insn.address == start), None)
    if index is None or _control(instructions[index], arm):
        return None
    inputs, calls, messages, callees = [], [], [], []
    if not arm:
        state.pushed.clear()
    for insn in instructions[index : index + (96 if arm else 240)]:
        is_call = insn.group(CS_GRP_CALL)
        if _control(insn, arm) and not is_call:
            break
        if not is_call and insn.mnemonic.removesuffix(".w") not in _FALLTHROUGH[arm]:
            return None
        if is_call:
            if len(insn.operands) != 1 or insn.operands[0].type != (
                ARM_OP_IMM if arm else X86_OP_IMM
            ):
                return None
            if arm:
                if insn.cc != ARM_CC_AL:
                    return None
                target = int(insn.operands[0].imm) & ~1
                name = next(
                    (name for name, (va, _) in image.functions.items() if va & ~1 == target), None
                )
                callee = {"target_vaddr": hex(target)}
                value = state.regs.get("r1")
            else:
                name, callee = _x86_callee(image, int(insn.operands[0].imm), state.regs)
                value = state.pushed[-2] if len(state.pushed) == 2 else None
            if name == VERSION_STRING:
                inputs.append(
                    "min_library_version"
                    if value == _MINIMUM
                    else value[1]
                    if value and value[0] == "constant"
                    else None
                )
                calls.append(hex(insn.address))
                callees.append(callee)
        state.step(insn)
        for value in state.regs.values():
            if value and value[0] in ("constant", "pointer"):
                text = image.c_string(value[1])
                if text and text not in messages:
                    messages.append(text)
        if len(inputs) == 2:
            constant = inputs[1]
            if (
                inputs[0] != "min_library_version"
                or not _version(constant)
                or boundary != constant + (0 if arm else 1)
            ):
                return None
            if _messages_match(messages):
                return {
                    "comparison_role": "min_library_version",
                    "comparison_constant": constant,
                    "comparison_boundary": boundary,
                    "comparison_instruction": f"{comparison.mnemonic} {comparison.op_str}",
                    "branch_instruction": f"{branch.mnemonic} {branch.op_str}",
                    "failure_condition": "min_library_version > library_version",
                    "version_string_inputs": inputs,
                    "version_string_call_vaddrs": calls,
                    "callees": callees,
                    "failure_messages": messages,
                    "failure_edge": True,
                    "architecture": ("arm-thumb" if function[0] & 1 else "arm")
                    if arm
                    else "x86-32",
                    "function_vaddr": function[0] & ~1 if arm else function[0],
                    "comparison_vaddr": comparison.address,
                    "branch_vaddr": branch.address,
                    "failure_block_vaddr": start,
                }
        if len(inputs) > 2:
            return None
    return None


def inspect_elf(data: bytes):
    """Diagnostic form of the same fail-closed proof used by the public API."""
    if (
        not isinstance(data, bytes)
        or len(data) < 52
        or data[:4] != b"\x7fELF"
        or VERIFY.encode() not in data
        or VERSION_STRING.encode() not in data
    ):
        return {"status": "rejected-unproven"}
    try:
        if data[4:6] != b"\x01\x01" or int.from_bytes(data[18:20], "little") not in (3, 40):
            return {"status": "unsupported-architecture"}
        image = ELFView(data)
        if (
            image.elf.elfclass != 32
            or not image.elf.little_endian
            or image.machine not in ("EM_ARM", "EM_386")
        ):
            return {"status": "unsupported-architecture"}
        for name in (VERIFY, VERSION_STRING):
            fn = image.functions.get(name)
            if fn is None:
                return {"status": "missing-defined-symbol", "machine": image.machine}
            address, size = fn
            if (
                not 0 < size <= 4096
                or image.read(
                    address & ~1 if image.machine == "EM_ARM" else address, size, executable=True
                )
                is None
            ):
                return {"status": "rejected-unproven", "machine": image.machine}
        proof = _proof(image, image.functions[VERIFY])
        if proof:
            return {
                "status": "matched",
                "machine": image.machine,
                "version": _version(proof["comparison_constant"]),
                "library_version": proof["comparison_constant"],
                "function_vaddr": hex(proof["function_vaddr"]),
                "proof": proof,
            }
        return {"status": "rejected-unproven", "machine": image.machine}
    except Exception:  # noqa: BLE001 -- untrusted ELF/decoder boundary must fail closed
        # Untrusted ELF metadata and decoder failure must never produce a guess.
        return {"status": "rejected-unproven"}


def extract_protobuf_versions(data: bytes) -> list[StaticVersionMatch]:
    """Recover only a defined ELF32 library's own statically proven version."""
    result = inspect_elf(data)
    if result["status"] != "matched":
        return []
    return [
        StaticVersionMatch(
            "Protobuf", result["version"], json.dumps(result["proof"], sort_keys=True), 0.94
        )
    ]
