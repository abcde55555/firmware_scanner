"""Conservatively recover an embedded TensorFlow Lite runtime version.

The probe follows the exported Android runtime-version JNI method to its
NewStringUTF call and resolves the returned pointer only for a small set of
audited position-independent return-string thunks. It never loads or executes
the ELF. Unsupported control flow or data flow is rejected.
"""

from __future__ import annotations

import json
import re
from io import BytesIO

from capstone import (
    CS_ARCH_ARM,
    CS_ARCH_ARM64,
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    CS_MODE_THUMB,
    CS_OP_IMM,
    CS_OP_MEM,
    CS_OP_REG,
    Cs,
)
from elftools.elf.constants import P_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from .static_version import StaticVersionMatch

_JNI_VERSION_METHOD = "Java_org_tensorflow_lite_InterpreterFactoryImpl_nativeRuntimeVersion"
_VERSION_RE = re.compile(rb"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:[-+][A-Za-z0-9.-]+)?\Z")


class _ELF:
    def __init__(self, data: bytes):
        self.data = data
        self.elf = ELFFile(BytesIO(data))
        machine, bits = self.elf.header["e_machine"], self.elf.elfclass
        self.arch = {
            ("EM_AARCH64", 64): (CS_ARCH_ARM64, 0),
            ("EM_ARM", 32): (CS_ARCH_ARM, CS_MODE_THUMB),
            ("EM_386", 32): (CS_ARCH_X86, CS_MODE_32),
            ("EM_X86_64", 64): (CS_ARCH_X86, CS_MODE_64),
        }.get((machine, bits))
        if not self.elf.little_endian or self.arch is None:
            raise ValueError("unsupported ELF ABI")
        self.machine = machine
        self.loads = [s for s in self.elf.iter_segments() if s["p_type"] == "PT_LOAD"]
        definitions = set()
        for section in self.elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if (
                        symbol.name == _JNI_VERSION_METHOD
                        and symbol["st_info"]["type"] == "STT_FUNC"
                        and symbol["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK")
                        and symbol["st_shndx"] not in ("SHN_UNDEF", "SHN_ABS", 0)
                        and int(symbol["st_size"]) > 0
                    ):
                        definitions.add((int(symbol["st_value"]), int(symbol["st_size"])))
        self.functions = (
            {_JNI_VERSION_METHOD: next(iter(definitions))} if len(definitions) == 1 else {}
        )
        self.dis = Cs(*self.arch)
        self.dis.detail = True

    def bytes_at(
        self, address: int, size: int, executable: bool = False, readonly: bool = False
    ) -> bytes | None:
        for segment in self.loads:
            flags = int(segment["p_flags"])
            start, end = int(segment["p_vaddr"]), int(segment["p_vaddr"]) + int(segment["p_filesz"])
            if (
                start <= address
                and address + size <= end
                and (not executable or flags & P_FLAGS.PF_X)
                and (not readonly or not flags & P_FLAGS.PF_W)
            ):
                offset = int(segment["p_offset"]) + address - start
                raw = self.data[offset : offset + size]
                return raw if offset >= 0 and len(raw) == size else None
        return None

    def c_string(self, address: int) -> str | None:
        for segment in self.loads:
            start, end = int(segment["p_vaddr"]), int(segment["p_vaddr"]) + int(segment["p_filesz"])
            if start <= address < end and not int(segment["p_flags"]) & P_FLAGS.PF_W:
                raw = self.bytes_at(address, min(256, end - address))
                if raw is None or b"\0" not in raw:
                    return None
                raw = raw.split(b"\0", 1)[0]
                if _VERSION_RE.fullmatch(raw):
                    return raw.decode("ascii")
        return None

    def instructions(self, address: int, size: int):
        thumb = self.machine == "EM_ARM"
        dis = self.dis
        if thumb:
            dis = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
            dis.detail = True
        raw = self.bytes_at(address & ~1 if thumb else address, size, executable=True)
        if raw is None:
            return []
        return list(dis.disasm(raw, address & ~1 if thumb else address))


def _resolve_return_string(image: _ELF, address: int) -> tuple[int, str] | None:
    """Resolve a complete, bounded helper whose sole purpose is returning a literal."""
    if image.machine == "EM_AARCH64":
        ins = image.instructions(address, 12)
        if (
            len(ins) == 3
            and ins[0].mnemonic == "nop"
            and ins[1].mnemonic == "adr"
            and ins[2].mnemonic == "ret"
            and not ins[2].operands
        ):
            op = ins[1].operands
            if (
                len(op) == 2
                and op[0].type == CS_OP_REG
                and ins[1].reg_name(op[0].reg) == "x0"
                and op[1].type == CS_OP_IMM
            ):
                ptr = int(op[1].imm)
                value = image.c_string(ptr)
                return (ptr, value) if value else None
        if (
            len(ins) == 2
            and ins[0].mnemonic == "adr"
            and ins[1].mnemonic == "ret"
            and not ins[1].operands
        ):
            op = ins[0].operands
            if (
                len(op) == 2
                and op[0].type == CS_OP_REG
                and ins[0].reg_name(op[0].reg) == "x0"
                and op[1].type == CS_OP_IMM
            ):
                ptr = int(op[1].imm)
                value = image.c_string(ptr)
                return (ptr, value) if value else None
    elif image.machine == "EM_ARM":
        # Thumb literal-load plus PC-relative add, then return. The literal is
        # a relocation-free delta to the NUL-terminated version bytes.
        ins = image.instructions(address, 12)
        end = next((i for i, item in enumerate(ins) if item.mnemonic == "bx"), None)
        if end is not None and [i.mnemonic for i in ins[: end + 1]] == ["ldr", "add", "bx"]:
            load, add, ret = ins[: end + 1]
            if (
                load.operands[0].type == CS_OP_REG
                and load.reg_name(load.operands[0].reg) == "r0"
                and load.operands[1].type == CS_OP_MEM
                and load.reg_name(load.operands[1].mem.base) == "pc"
                and not load.operands[1].mem.index
                and not load.writeback
                and add.operands[0].type == CS_OP_REG
                and add.reg_name(add.operands[0].reg) == "r0"
                and add.operands[1].type == CS_OP_REG
                and add.reg_name(add.operands[1].reg) == "pc"
                and ret.operands[0].type == CS_OP_REG
                and ret.reg_name(ret.operands[0].reg) == "lr"
            ):
                literal_at = ((load.address + 4) & ~3) + int(load.operands[1].mem.disp)
                literal = image.bytes_at(literal_at, 4, readonly=True)
                if literal:
                    delta = int.from_bytes(literal, "little", signed=True)
                    # ADD Rd, PC uses instruction address + 4; unlike an LDR
                    # literal, this register read is not word-aligned.
                    ptr = add.address + 4 + delta
                    value = image.c_string(ptr)
                    return (ptr, value) if value else None
    elif image.machine == "EM_X86_64":
        ins = image.instructions(address, 8)
        if len(ins) == 2 and ins[0].mnemonic == "lea" and ins[1].mnemonic == "ret":
            dst, src = ins[0].operands
            if (
                dst.type == CS_OP_REG
                and ins[0].reg_name(dst.reg) == "rax"
                and src.type == CS_OP_MEM
                and ins[0].reg_name(src.mem.base) == "rip"
                and not src.mem.index
            ):
                ptr = ins[0].address + ins[0].size + int(src.mem.disp)
                value = image.c_string(ptr)
                return (ptr, value) if value else None
    elif image.machine == "EM_386":
        # PIC thunk emitted by the compiler: call/pop establishes EIP, then
        # arithmetic resolves the address of the literal and returns it.
        ins = image.instructions(address, 40)
        end = next((i for i, item in enumerate(ins) if item.mnemonic.startswith("ret")), None)
        if end is not None:
            ins = ins[: end + 1]
            names = [i.mnemonic for i in ins]
            if names == ["push", "mov", "and", "call", "pop", "add", "lea", "mov", "pop", "ret"]:
                call, pop, add, lea = ins[3:7]
                if (
                    ins[0].op_str == "ebp"
                    and ins[1].op_str == "ebp, esp"
                    and ins[2].op_str == "esp, 0xfffffffc"
                    and call.operands[0].type == CS_OP_IMM
                    and int(call.operands[0].imm) == pop.address
                    and pop.operands[0].type == CS_OP_REG
                    and pop.reg_name(pop.operands[0].reg) == "eax"
                    and add.operands[0].type == CS_OP_REG
                    and add.reg_name(add.operands[0].reg) == "eax"
                    and add.operands[1].type == CS_OP_IMM
                    and lea.operands[0].type == CS_OP_REG
                    and lea.reg_name(lea.operands[0].reg) == "eax"
                    and lea.operands[1].type == CS_OP_MEM
                    and lea.reg_name(lea.operands[1].mem.base) == "eax"
                    and not lea.operands[1].mem.index
                    and ins[7].op_str == "esp, ebp"
                    and ins[8].op_str == "ebp"
                    and not ins[9].operands
                ):
                    ptr = pop.address + int(add.operands[1].imm) + int(lea.operands[1].mem.disp)
                    value = image.c_string(ptr)
                    return (ptr, value) if value else None
    return None


def _strict_jni_flow(image: _ELF, instructions, helper: int) -> tuple[int, int] | None:
    """Match the entire observed JNI method shape, including receiver and target provenance."""
    names = [ins.mnemonic for ins in instructions]
    if image.machine == "EM_AARCH64":
        slot = 0x538
        expected = [
            "stp",
            "mov",
            "bl",
            "tbz",
            "bl",
            "ldr",
            "mov",
            "mov",
            "ldr",
            "ldp",
            "br",
            "mov",
            "ldp",
            "ret",
        ]
        if names != expected:
            return None
        if (
            instructions[0].op_str != "x30, x19, [sp, #-0x10]!"
            or instructions[1].op_str != "x19, x0"
            or int(instructions[4].operands[0].imm) != helper
            or instructions[3].operands[0].type != CS_OP_REG
            or instructions[3].reg_name(instructions[3].operands[0].reg) != "w0"
            or int(instructions[3].operands[1].imm) != 0
            or instructions[5].op_str != "x8, [x19]"
            or instructions[6].op_str != "x1, x0"
            or instructions[7].op_str != "x0, x19"
            or instructions[8].op_str != f"x2, [x8, #{slot:#x}]"
            or instructions[9].op_str != "x30, x19, [sp], #0x10"
            or instructions[10].op_str != "x2"
            or int(instructions[3].operands[2].imm) != instructions[11].address
            or instructions[11].op_str != "x0, xzr"
            or instructions[12].op_str != "x30, x19, [sp], #0x10"
            or instructions[13].operands
        ):
            return None
        return 10, slot

    if image.machine == "EM_ARM":
        slot = 0x29C
        expected = [
            "push",
            "mov",
            "bl",
            "cmp",
            "itt",
            "moveq",
            "popeq",
            "bl",
            "mov",
            "ldr",
            "ldr.w",
            "mov",
            "pop.w",
            "bx",
        ]
        if names != expected:
            return None
        if (
            instructions[0].op_str != "{r4, lr}"
            or int(instructions[7].operands[0].imm) != helper
            or instructions[1].op_str != "r4, r0"
            or instructions[3].op_str != "r0, #0"
            or instructions[4].op_str != "eq"
            or instructions[5].op_str != "r0, #0"
            or instructions[6].op_str != "{r4, pc}"
            or instructions[8].op_str != "r1, r0"
            or instructions[9].op_str != "r0, [r4]"
            or instructions[10].op_str != f"r2, [r0, #{slot:#x}]"
            or instructions[11].op_str != "r0, r4"
            or instructions[12].op_str != "{r4, lr}"
            or instructions[13].op_str != "r2"
        ):
            return None
        return 13, slot

    if image.machine == "EM_X86_64":
        slot = 0x538
        expected = [
            "push",
            "mov",
            "call",
            "test",
            "je",
            "call",
            "mov",
            "mov",
            "mov",
            "mov",
            "pop",
            "jmp",
            "xor",
            "pop",
            "ret",
        ]
        if names != expected:
            return None
        if (
            instructions[0].op_str != "rbx"
            or instructions[1].op_str != "rbx, rdi"
            or instructions[3].op_str != "al, al"
            or int(instructions[5].operands[0].imm) != helper
            or instructions[6].op_str != "rcx, qword ptr [rbx]"
            or instructions[7].op_str != f"rcx, qword ptr [rcx + {slot:#x}]"
            or instructions[8].op_str != "rdi, rbx"
            or instructions[9].op_str != "rsi, rax"
            or instructions[10].op_str != "rbx"
            or instructions[11].op_str != "rcx"
            or int(instructions[4].operands[0].imm) != instructions[12].address
            or instructions[12].op_str != "eax, eax"
            or instructions[13].op_str != "rbx"
            or instructions[14].operands
        ):
            return None
        return 11, slot

    if image.machine == "EM_386":
        slot = 0x29C
        expected = [
            "push",
            "mov",
            "push",
            "push",
            "and",
            "sub",
            "call",
            "pop",
            "add",
            "mov",
            "mov",
            "call",
            "test",
            "je",
            "call",
            "mov",
            "mov",
            "mov",
            "call",
            "jmp",
            "xor",
            "lea",
            "pop",
            "pop",
            "pop",
            "ret",
        ]
        if names != expected:
            return None
        if (
            instructions[0].op_str != "ebp"
            or instructions[1].op_str != "ebp, esp"
            or instructions[2].op_str != "ebx"
            or instructions[3].op_str != "esi"
            or instructions[4].op_str != "esp, 0xfffffff0"
            or instructions[5].op_str != "esp, 0x10"
            or int(instructions[6].operands[0].imm) != instructions[7].address
            or instructions[7].op_str != "ebx"
            or instructions[8].operands[0].type != CS_OP_REG
            or instructions[8].reg_name(instructions[8].operands[0].reg) != "ebx"
            or instructions[8].operands[1].type != CS_OP_IMM
            or int(instructions[14].operands[0].imm) != helper
            or instructions[9].op_str != "esi, dword ptr [ebp + 8]"
            or instructions[10].op_str != "dword ptr [esp], esi"
            or instructions[11].mnemonic != "call"
            or instructions[12].op_str != "al, al"
            or int(instructions[13].operands[0].imm) != instructions[20].address
            or instructions[15].op_str != "ecx, dword ptr [esi]"
            or instructions[16].op_str != "dword ptr [esp + 4], eax"
            or instructions[17].op_str != "dword ptr [esp], esi"
            or instructions[18].op_str != f"dword ptr [ecx + {slot:#x}]"
            or int(instructions[19].operands[0].imm) != instructions[21].address
            or instructions[20].op_str != "eax, eax"
            or instructions[21].op_str != "esp, [ebp - 8]"
            or [ins.op_str for ins in instructions[22:25]] != ["esi", "ebx", "ebp"]
        ):
            return None
        return 18, slot
    return None


def inspect_elf(data: bytes) -> dict:
    """Return a proof only when nativeRuntimeVersion passes its own literal to JNI."""
    if (
        not isinstance(data, bytes)
        or len(data) < 52
        or data[:4] != b"\x7fELF"
        or _JNI_VERSION_METHOD.encode() not in data
    ):
        return {"status": "rejected-unproven", "reason": "missing defined runtime API candidate"}
    try:
        image = _ELF(data)
        function = image.functions.get(_JNI_VERSION_METHOD)
        if function is None:
            return {"status": "rejected-unproven", "reason": "runtime-version JNI symbol missing"}
        address, size = function
        if not 0 < size <= 4096:
            return {"status": "rejected-unproven", "reason": "JNI function exceeds proof bound"}
        if image.machine == "EM_ARM" and not address & 1:
            return {
                "status": "rejected-unproven",
                "reason": "ARM method requires verified Thumb entry",
            }
        instructions = image.instructions(address, size)
        if not instructions or sum(i.size for i in instructions) != size:
            return {"status": "rejected-unproven", "reason": "JNI function decode incomplete"}
        helper_call_index = {"EM_AARCH64": 4, "EM_ARM": 7, "EM_X86_64": 5, "EM_386": 14}[
            image.machine
        ]
        helper_call = instructions[helper_call_index]
        if (
            helper_call.mnemonic not in ("bl", "call")
            or not helper_call.operands
            or helper_call.operands[0].type != CS_OP_IMM
        ):
            return {
                "status": "rejected-unproven",
                "reason": "runtime-version helper call shape unsupported",
            }
        helper = int(helper_call.operands[0].imm)
        flow = _strict_jni_flow(image, instructions, helper)
        if flow is None:
            return {
                "status": "rejected-unproven",
                "reason": "JNI receiver, bytes argument, table slot, or callee provenance unsupported",
            }
        _jni_index, slot = flow
        for ins in instructions:
            if (
                ins.mnemonic in ("call", "bl", "blx")
                and ins.operands
                and ins.operands[0].type == CS_OP_IMM
            ):
                target = int(ins.operands[0].imm)
                if not image.bytes_at(
                    target & ~1 if image.machine == "EM_ARM" else target, 1, executable=True
                ):
                    return {
                        "status": "rejected-unproven",
                        "reason": "JNI wrapper calls an imported or non-executable target",
                    }
        if not image.bytes_at(
            helper & ~1 if image.machine == "EM_ARM" else helper, 1, executable=True
        ):
            return {
                "status": "rejected-unproven",
                "reason": "version helper target is not local executable code",
            }
        resolved = _resolve_return_string(image, helper)
        if resolved is None:
            return {
                "status": "rejected-unproven",
                "reason": "version helper return dataflow unsupported",
            }
        string_address, version = resolved
        abi_flow = {
            "EM_AARCH64": {
                "jni_env": "entry x0 saved in x19",
                "jni_table": "x8 <- [x19]",
                "bytes_argument": "x1 <- x0 helper return",
                "call_target": f"x2 <- [x8 + {slot:#x}]; br x2",
            },
            "EM_ARM": {
                "jni_env": "entry r0 saved in r4",
                "jni_table": "r0 <- [r4]",
                "bytes_argument": "r1 <- r0 helper return",
                "call_target": f"r2 <- [r0 + {slot:#x}]; bx r2",
            },
            "EM_X86_64": {
                "jni_env": "entry rdi saved in rbx",
                "jni_table": "rcx <- [rbx]",
                "bytes_argument": "rsi <- rax helper return",
                "call_target": f"rcx <- [rcx + {slot:#x}]; jmp rcx",
            },
            "EM_386": {
                "jni_env": "entry [ebp+8] saved in esi",
                "jni_table": "ecx <- [esi]",
                "bytes_argument": "[esp+4] <- eax helper return",
                "call_target": f"call [ecx + {slot:#x}] with [esp] <- esi",
            },
        }[image.machine]
        proof = {
            "method": _JNI_VERSION_METHOD,
            "jni_vtable_slot": hex(slot),
            "jni_dataflow": abi_flow,
            "version_helper_vaddr": hex(helper),
            "version_string_vaddr": hex(string_address),
            "explanation": "the exported runtimeVersion JNI method passes the local return-string helper result to the JNI NewStringUTF slot",
            "field": "tflite_runtime_version",
            "artifact_version": None,
            "version_kind": "runtime",
            "source": "https://www.tensorflow.org/guide/versions",
        }
        return {"status": "matched", "version": version, "proof": proof}
    except Exception as exc:  # noqa: BLE001 -- untrusted ELF/decoder boundary fails closed
        return {
            "status": "rejected-unproven",
            "reason": f"static analysis failed: {type(exc).__name__}",
        }


def extract_tflite_runtime(data: bytes) -> list[StaticVersionMatch]:
    """Attribute the core runtime identifier separately from JNI/Maven artifacts."""
    result = inspect_elf(data)
    if result["status"] != "matched":
        return []
    return [
        StaticVersionMatch(
            "TensorFlowLite-runtime",
            result["version"],
            json.dumps(result["proof"], sort_keys=True),
            0.94,
        )
    ]
