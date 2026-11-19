"""Static extraction from defined version functions; never execute ELF.

The product combines these bounded semantic proofs with other evidence. This
module requires retained symbols and rejects unsupported code instead of guessing.
"""
from __future__ import annotations

import json
import re
import struct
from io import BytesIO

from capstone import (
    CS_ARCH_ARM,
    CS_ARCH_ARM64,
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    CS_MODE_ARM,
    CS_MODE_THUMB,
    Cs,
    CsError,
)
from capstone.arm import ARM_CC_AL, ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from firmware_scanner.extraction.static_version import StaticVersionMatch

VERIFY = '_ZN6google8protobuf8internal13VerifyVersionEiiPKc'
VERSION_STRING = '_ZN6google8protobuf8internal13VersionStringEi'
INTEGER_GETTERS = {
    'LZ4_versionNumber': ('LZ4', 'decimal100'),
    'ZSTD_versionNumber': ('zstd', 'decimal100'),
    'XXH_versionNumber': ('xxHash', 'decimal100'),
    'sqlite3_libversion_number': ('SQLite', 'decimal1000'),
    'png_access_version_number': ('libpng', 'decimal100'),
    'WebPGetDecoderVersion': ('libwebp', 'packed8'),
    'WebPGetEncoderVersion': ('libwebp', 'packed8'),
    'WebPGetMuxVersion': ('libwebp', 'packed8'),
    'WebPGetDemuxVersion': ('libwebp', 'packed8'),
    'BrotliDecoderVersion': ('Brotli', 'brotli'),
    'BrotliEncoderVersion': ('Brotli', 'brotli'),
    'uv_version': ('libuv', 'packed8'),
    'vpx_codec_version': ('libvpx', 'packed8'),
    'JxlDecoderVersion': ('libjxl', 'decimal1000'),
}
STRING_GETTERS = {
    'hb_version_string': ('HarfBuzz', ''),
    'LZ4_versionString': ('LZ4', ''),
    'ZSTD_versionString': ('zstd', ''),
    'sqlite3_libversion': ('SQLite', ''),
    'zlibVersion': ('zlib', ''),
    'XML_ExpatVersion': ('Expat', 'expat_'),
    'png_get_libpng_ver': ('libpng', ''),
    'opus_get_version_string': ('Opus', 'libopus '),
    'uv_version_string': ('libuv', ''),
    'lzma_version_string': ('XZ Utils', ''),
    'vpx_codec_version_str': ('libvpx', 'v'),
    'event_get_version': ('libevent', ''),
}
X86_32_STRING_GETTERS = {
    'Cronet_Engine_GetVersionString': ('Cronet', ''),
    'event_get_version': ('libevent', ''),
    'vpx_codec_version_str': ('libvpx', 'v'),
}


def decode_integer(value: int, encoding: str) -> str | None:
    if not 0 < value < 2**32:
        return None
    if encoding == 'decimal100':
        parts = value // 10000, value // 100 % 100, value % 100
    elif encoding == 'decimal1000':
        parts = value // 1000000, value // 1000 % 1000, value % 1000
    elif encoding == 'packed8':
        if value >= 2**24:
            return None
        parts = value >> 16, value >> 8 & 255, value & 255
    elif encoding == 'brotli':
        parts = value >> 24, value >> 12 & 4095, value & 4095
    else:
        return None
    if parts[0] > 99:
        return None
    return '.'.join(map(str, parts))


class SemanticVersionExtractor:
    def extract(self, data: bytes) -> list[StaticVersionMatch]:
        if not data.startswith(b'\x7fELF') or not any(
            name.encode() in data for name in [VERIFY, *INTEGER_GETTERS, *STRING_GETTERS,
                                                *X86_32_STRING_GETTERS]
        ):
            return []
        try:
            image = ELFView(data)
            if not image.elf.little_endian:
                return []
            result = []
            for name, (component, encoding) in INTEGER_GETTERS.items():
                function = image.functions.get(name)
                if function is None or not 0 < function[1] <= 128:
                    continue
                instructions = image.instructions(*function)
                if image.machine == 'EM_ARM':
                    constant = self._arm_return(image, instructions, bool(function[0] & 1))
                elif image.machine == 'EM_AARCH64':
                    constant = self._aarch64_constant(instructions)
                elif image.machine == 'EM_386':
                    constant = self._x86_32_return(image, instructions)
                else:
                    constant = self._constant_return(instructions)
                version = decode_integer(constant, encoding) if constant is not None else None
                if version:
                    evidence = {
                        'prototype': 'function-version-semantics-v1',
                        'function': name, 'vaddr': hex(function[0]),
                        'value': constant, 'encoding': encoding,
                        'instructions': image.format_instructions(instructions),
                    }
                    result.append(StaticVersionMatch(component, version, json.dumps(evidence), .94))
            if image.machine == 'EM_ARM':
                for name, (component, prefix) in STRING_GETTERS.items():
                    function = image.functions.get(name)
                    if function is None or not 0 < function[1] <= 128:
                        continue
                    instructions = image.instructions(*function)
                    pointer = self._arm_return(image, instructions, bool(function[0] & 1))
                    text = image.c_string(pointer, readonly=True) if pointer is not None else None
                    if text is None or not text.startswith(prefix):
                        continue
                    version = text[len(prefix):]
                    if not re.fullmatch(r'v?\d+\.\d+(?:\.\d+)*[A-Za-z0-9.+_-]*', version):
                        continue
                    evidence = {'prototype': 'function-version-semantics-v1',
                                'function': name, 'vaddr': hex(function[0] & ~1),
                                'mode': 'Thumb' if function[0] & 1 else 'ARM',
                                'string_vaddr': hex(pointer), 'string': text,
                                'instructions': image.format_instructions(instructions[:8])}
                    result.append(StaticVersionMatch(component, version, json.dumps(evidence), .94))
            if image.machine == 'EM_386' and image.elf.elfclass == 32:
                for name, (component, prefix) in X86_32_STRING_GETTERS.items():
                    function = image.functions.get(name)
                    if function is None or not 0 < function[1] <= 128:
                        continue
                    instructions = image.instructions(*function)
                    pointer = self._x86_32_return(image, instructions)
                    text = image.c_string(pointer, readonly=True) if pointer is not None else None
                    if text is None or not text.startswith(prefix):
                        continue
                    version = text[len(prefix):]
                    if not re.fullmatch(r'v?\d+\.\d+(?:\.\d+)*[A-Za-z0-9.+_-]*', version):
                        continue
                    evidence = {'prototype': 'function-version-semantics-v1',
                                'function': name, 'vaddr': hex(function[0]),
                                'mode': 'x86-32-pic', 'string_vaddr': hex(pointer),
                                'string': text,
                                'instructions': image.format_instructions(instructions)}
                    result.append(StaticVersionMatch(component, version, json.dumps(evidence), .94))
            if image.machine == 'EM_X86_64':
                protobuf = self._protobuf(image)
                if protobuf:
                    result.append(protobuf)
            return result
        except (ValueError, TypeError, KeyError, IndexError, OSError, ELFError, CsError, struct.error):
            return []

    @staticmethod
    def _constant_return(instructions) -> int | None:
        """Only a constant write to EAX followed by an unconditional return."""
        value = None
        for insn in instructions:
            ops = insn.operands
            if insn.mnemonic in ('endbr64', 'endbr32', 'nop'):
                continue
            if insn.mnemonic == 'mov' and len(ops) == 2 and value is None:  # noqa: SIM102
                if (ops[0].type == X86_OP_REG and insn.reg_name(ops[0].reg) == 'eax'
                        and ops[1].type == X86_OP_IMM):
                    value = int(ops[1].imm) & 0xffffffff
                    continue
            if insn.mnemonic == 'ret' and not ops and value is not None:
                return value
            return None
        return None

    @staticmethod
    def _x86_32_return(image: ELFView, instructions) -> int | None:
        """Evaluate a single straight-line 32-bit return, including a verified PIC thunk."""
        registers = {}
        for insn in instructions:
            ops = insn.operands
            if insn.mnemonic in ('endbr32', 'nop'):
                continue
            if insn.mnemonic == 'call' and len(ops) == 1 and ops[0].type == X86_OP_IMM:
                thunk_register = image.pc_thunk(int(ops[0].imm))
                if thunk_register is None:
                    return None
                registers[thunk_register] = (insn.address + insn.size) & 0xffffffff
                continue
            if (insn.mnemonic == 'mov' and len(ops) == 2
                    and ops[0].type == X86_OP_REG and ops[0].size == 4):
                destination = insn.reg_name(ops[0].reg)
                if ops[1].type == X86_OP_IMM:
                    registers[destination] = int(ops[1].imm) & 0xffffffff
                    continue
                if ops[1].type == X86_OP_REG and ops[1].size == 4:
                    source = insn.reg_name(ops[1].reg)
                    if source in registers:
                        registers[destination] = registers[source]
                        continue
                return None
            if (insn.mnemonic == 'add' and len(ops) == 2
                    and ops[0].type == X86_OP_REG and ops[0].size == 4):
                name = insn.reg_name(ops[0].reg)
                if name not in registers or ops[1].type != X86_OP_IMM:
                    return None
                registers[name] = (registers[name] + int(ops[1].imm)) & 0xffffffff
                continue
            if (insn.mnemonic == 'lea' and len(ops) == 2 and ops[0].type == X86_OP_REG
                    and ops[0].size == 4 and ops[1].type == X86_OP_MEM):
                memory = ops[1].mem
                base = insn.reg_name(memory.base) if memory.base else None
                if memory.index or base not in registers:
                    return None
                registers[insn.reg_name(ops[0].reg)] = (registers[base] + int(memory.disp)) & 0xffffffff
                continue
            if insn.mnemonic == 'ret' and not ops:
                return registers.get('eax')
            return None
        return None

    @staticmethod
    def _aarch64_constant(instructions) -> int | None:
        value = None
        for insn in instructions:
            ops = insn.operands
            if insn.mnemonic == 'nop':
                continue
            if insn.mnemonic in ('mov', 'movz', 'movk') and len(ops) == 2:
                if (ops[0].type != ARM64_OP_REG or insn.reg_name(ops[0].reg) not in ('w0', 'x0')
                        or ops[1].type != ARM64_OP_IMM):
                    return None
                shift = int(ops[1].shift.value)
                part = int(ops[1].imm) << shift
                if insn.mnemonic == 'movk':
                    if value is None:
                        return None
                    value = (value & ~(0xffff << shift)) | part
                elif value is None:
                    value = part
                else:
                    return None
                continue
            if insn.mnemonic == 'ret' and not ops and value is not None:
                return value
            return None
        return None

    @staticmethod
    def _arm_return(image: ELFView, instructions, thumb: bool) -> int | None:
        """Evaluate a tiny unconditional MOV/LDR/ADD/BX path, no target execution."""
        registers = {}
        for insn in instructions:
            if insn.cc not in (0, ARM_CC_AL):
                return None
            ops = insn.operands
            pc = insn.address + (4 if thumb else 8)
            def operand_value(op):
                if op.type == ARM_OP_IMM:
                    return int(op.imm)
                if op.type == ARM_OP_REG:
                    # This helper is called synchronously within this iteration.
                    name = insn.reg_name(op.reg)  # noqa: B023
                    return pc if name == 'pc' else registers.get(name)  # noqa: B023
                return None
            if insn.mnemonic == 'nop':
                continue
            if insn.mnemonic in ('mov', 'movs', 'movw', 'movt') and len(ops) == 2:
                if ops[0].type != ARM_OP_REG or any(op.shift.type for op in ops):
                    return None
                name = insn.reg_name(ops[0].reg)
                value = operand_value(ops[1])
                if name not in ('r0', 'r1', 'r2', 'r3', 'ip') or value is None:
                    return None
                if insn.mnemonic == 'movt':
                    if name not in registers:
                        return None
                    value = (registers[name] & 0xffff) | (value << 16)
                registers[name] = value & 0xffffffff
                continue
            if insn.mnemonic == 'ldr' and len(ops) == 2:
                if (ops[0].type != ARM_OP_REG or ops[1].type != ARM_OP_MEM
                        or any(op.shift.type for op in ops)):
                    return None
                memory = ops[1].mem
                base = insn.reg_name(memory.base)
                if memory.index or insn.writeback:
                    return None
                pointer = ((pc & ~3) if thumb else pc) if base == 'pc' else registers.get(base)
                if pointer is None:
                    return None
                raw = image.read((pointer + int(memory.disp)) & 0xffffffff, 4, readonly=True)
                if raw is None:
                    return None
                name = insn.reg_name(ops[0].reg)
                if name not in ('r0', 'r1', 'r2', 'r3', 'ip'):
                    return None
                registers[name] = int.from_bytes(raw, 'little')
                continue
            if insn.mnemonic in ('add', 'adds') and len(ops) in (2, 3):
                if ops[0].type != ARM_OP_REG or any(op.shift.type for op in ops):
                    return None
                name = insn.reg_name(ops[0].reg)
                values = ([registers.get(name), operand_value(ops[1])] if len(ops) == 2
                          else [operand_value(ops[1]), operand_value(ops[2])])
                if name not in ('r0', 'r1', 'r2', 'r3', 'ip') or None in values:
                    return None
                registers[name] = sum(values) & 0xffffffff
                continue
            if insn.mnemonic == 'bx' and len(ops) == 1 and ops[0].type == ARM_OP_REG:
                return registers.get('r0') if insn.reg_name(ops[0].reg) == 'lr' else None
            return None
        return None

    @staticmethod
    def _protobuf(image: ELFView) -> StaticVersionMatch | None:
        function = image.functions.get(VERIFY)
        if function is None or VERSION_STRING not in image.functions or not 0 < function[1] <= 4096:
            return None
        instructions = image.instructions(*function)
        if not instructions:
            return None
        # Inspect the library definition, never a call site's header-version argument.
        boundary = None
        for index, insn in enumerate(instructions[:40]):
            ops = insn.operands
            if insn.mnemonic == 'call' or insn.mnemonic.startswith(('j', 'ret')):
                break
            if insn.mnemonic == 'cmp' and len(ops) == 2:  # noqa: SIM102
                if (ops[0].type == X86_OP_REG and insn.reg_name(ops[0].reg) == 'esi'
                        and ops[1].type == X86_OP_IMM and index + 1 < len(instructions)):
                    branch = instructions[index + 1]
                    if (branch.mnemonic in ('jl', 'jge', 'jle', 'jg')
                            and len(branch.operands) == 1 and branch.operands[0].type == X86_OP_IMM
                            and function[0] <= branch.operands[0].imm < function[0] + function[1]):
                        boundary = index, insn, branch, int(ops[1].imm)
                    break
            _, writes = insn.regs_access()
            if any(insn.reg_name(reg) in ('rsi', 'esi', 'si', 'sil') for reg in writes):
                break
        if boundary is None:
            return None
        boundary_index, cmp, branch, limit = boundary
        # v21.12 fails when minLibraryVersion > libraryVersion. Identify the
        # failing edge, not just an arbitrary block containing constants.
        failure_address = (branch.address + branch.size if branch.mnemonic in ('jl', 'jle')
                           else int(branch.operands[0].imm))
        addresses = {insn.address: index for index, insn in enumerate(instructions)}
        if failure_address not in addresses:
            return None
        state = {'rdi': ('parameter', 'headerVersion'),
                 'rsi': ('parameter', 'minLibraryVersion'),
                 'rdx': ('parameter', 'filename')}
        for insn in instructions[:boundary_index]:
            SemanticVersionExtractor._x86_step(insn, state)
        calls, references = [], []
        for insn in instructions[addresses[failure_address]:]:
            if insn.mnemonic.startswith(('j', 'ret')):
                break
            ops = insn.operands
            if insn.mnemonic == 'call':
                if (len(ops) == 1 and ops[0].type == X86_OP_IMM
                        and image.callee(int(ops[0].imm)) == VERSION_STRING):
                    calls.append((state.get('rsi'), insn.address))
                # SysV AMD64 caller-saved registers become unknown at every call.
                for reg in ('rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11'):
                    state.pop(reg, None)
                if len(calls) == 2:
                    break
                continue
            SemanticVersionExtractor._x86_step(insn, state)
            if insn.mnemonic == 'lea' and ops and ops[0].type == X86_OP_REG:
                value = state.get(SemanticVersionExtractor._x86_register(insn.reg_name(ops[0].reg)))
                if value and value[0] == 'pointer':
                    text = image.c_string(value[1])
                    if text:
                        references.append((insn.address, value[1], text))
        if (len(calls) != 2 or calls[0][0] != ('parameter', 'minLibraryVersion')
                or calls[1][0] is None or calls[1][0][0] != 'constant'):
            return None
        messages = ' '.join(text for _, _, text in references)
        if ('This program requires version ' not in messages
                or 'but the installed version is ' not in messages):
            return None
        value = calls[1][0][1]
        expected = limit - 1 if branch.mnemonic in ('jl', 'jge') else limit
        version = decode_integer(value, 'decimal1000')
        if value != expected or not version or not 1 <= value // 1000000 <= 99:
            return None
        evidence = {
            'prototype': 'function-version-semantics-v1', 'function': VERIFY,
            'vaddr': hex(function[0]), 'parameter': 'minLibraryVersion/esi',
            'comparison': image.format_instructions([cmp, branch]),
            'failure_block': hex(failure_address),
            'boundary': limit, 'advertised_integer': value,
            'version_string_call_vaddrs': [hex(address) for _, address in calls],
            'message_references': [{'instruction': hex(address), 'string_vaddr': hex(pointer), 'text': text}
                                   for address, pointer, text in references],
            'explanation': 'one proven failure edge formats minLibraryVersion then the library constant, with required/installed messages and a consistent boundary',
            'source': 'https://raw.githubusercontent.com/protocolbuffers/protobuf/v21.12/src/google/protobuf/stubs/common.cc',
        }
        return StaticVersionMatch('Protobuf', version, json.dumps(evidence), .94)

    @staticmethod
    def _x86_register(name):
        aliases = {'eax': 'rax', 'ax': 'rax', 'al': 'rax', 'ah': 'rax',
                   'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx', 'bh': 'rbx',
                   'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx', 'ch': 'rcx',
                   'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx', 'dh': 'rdx',
                   'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
                   'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
                   'ebp': 'rbp', 'bp': 'rbp', 'bpl': 'rbp',
                   'esp': 'rsp', 'sp': 'rsp', 'spl': 'rsp'}
        return aliases.get(name, re.sub(r'^(r\d+)[dwb]$', r'\1', name))

    @staticmethod
    def _x86_step(insn, state):
        """Track only register copies, integer immediates and RIP-relative LEA."""
        ops = insn.operands
        assignment = None
        destination = None
        if ops and ops[0].type == X86_OP_REG:
            destination = SemanticVersionExtractor._x86_register(insn.reg_name(ops[0].reg))
            if insn.mnemonic == 'mov' and len(ops) == 2 and ops[0].size in (4, 8):
                if ops[1].type == X86_OP_IMM:
                    assignment = ('constant', int(ops[1].imm) & (2**(8 * ops[0].size) - 1))
                elif ops[1].type == X86_OP_REG and ops[1].size in (4, 8):
                    assignment = state.get(SemanticVersionExtractor._x86_register(insn.reg_name(ops[1].reg)))
            if insn.mnemonic == 'lea' and len(ops) == 2 and ops[1].type == X86_OP_MEM:
                memory = ops[1].mem
                if insn.reg_name(memory.base) == 'rip' and not memory.index:
                    assignment = ('pointer', insn.address + insn.size + int(memory.disp))
        _, writes = insn.regs_access()
        for reg in writes:
            state.pop(SemanticVersionExtractor._x86_register(insn.reg_name(reg)), None)
        if destination is not None and assignment is not None:
            state[destination] = assignment


class ELFView:
    def __init__(self, data: bytes):
        self.data = data
        self.elf = ELFFile(BytesIO(data))
        self.machine = self.elf.header['e_machine']
        self.loads = [s for s in self.elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        self.functions = {}
        self.relocations = {}
        for section in self.elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if (symbol['st_info']['type'] == 'STT_FUNC'
                            and symbol['st_info']['bind'] in ('STB_GLOBAL', 'STB_WEAK')
                            and symbol['st_shndx'] != 'SHN_UNDEF'
                            and symbol['st_shndx'] != 0 and int(symbol['st_size']) > 0):
                        self.functions[symbol.name] = int(symbol['st_value']), int(symbol['st_size'])
            if isinstance(section, RelocationSection):
                symbols = self.elf.get_section(section['sh_link'])
                for relocation in section.iter_relocations():
                    if relocation['r_info_sym']:
                        self.relocations[int(relocation['r_offset'])] = symbols.get_symbol(relocation['r_info_sym']).name
        self.by_address = {address: name for name, (address, _) in self.functions.items()}
        if self.machine in ('EM_X86_64', 'EM_386'):
            self.disassembler = Cs(CS_ARCH_X86, CS_MODE_64 if self.elf.elfclass == 64 else CS_MODE_32)
        elif self.machine == 'EM_ARM':
            self.disassembler = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        elif self.machine == 'EM_AARCH64':
            self.disassembler = Cs(CS_ARCH_ARM64, 0)
        else:
            raise ValueError('unsupported architecture')
        self.disassembler.detail = True

    def read(self, address: int, size: int, executable: bool = False,
             readonly: bool = False) -> bytes | None:
        for segment in self.loads:
            if executable and not int(segment['p_flags']) & 1:
                continue
            if readonly and int(segment['p_flags']) & 2:
                continue
            if segment['p_vaddr'] <= address and address + size <= segment['p_vaddr'] + segment['p_filesz']:
                offset = int(segment['p_offset']) + address - int(segment['p_vaddr'])
                if 0 <= offset and offset + size <= len(self.data):
                    return self.data[offset:offset + size]
        return None

    def instructions(self, address: int, size: int):
        if self.machine == 'EM_ARM':
            self.disassembler = Cs(CS_ARCH_ARM, CS_MODE_THUMB if address & 1 else CS_MODE_ARM)
            self.disassembler.detail = True
            address &= ~1
        code = self.read(address, size, executable=True)
        if code is None:
            return []
        instructions = list(self.disassembler.disasm(code, address))
        return instructions if self.machine == 'EM_ARM' or sum(i.size for i in instructions) == size else []

    def c_string(self, address: int, readonly: bool = False) -> str | None:
        for segment in self.loads:
            if segment['p_vaddr'] <= address < segment['p_vaddr'] + segment['p_filesz']:
                size = min(512, int(segment['p_vaddr'] + segment['p_filesz']) - address)
                raw = self.read(address, size, readonly=readonly)
                if raw is None or b'\0' not in raw:
                    return None
                raw = raw.split(b'\0', 1)[0]
                if raw and all(32 <= byte <= 126 for byte in raw):
                    return raw.decode('ascii')
        return None

    def callee(self, address: int) -> str | None:
        if address in self.by_address:
            return self.by_address[address]
        # x86-64 PLT: prove the RIP-relative GOT jump and resolve its relocation.
        code = self.read(address, 16, executable=True)
        if code is None:
            return None
        for insn in self.disassembler.disasm(code, address):
            if insn.mnemonic in ('endbr64', 'nop'):
                continue
            ops = insn.operands
            if insn.mnemonic == 'jmp' and len(ops) == 1 and ops[0].type == X86_OP_MEM:
                memory = ops[0].mem
                if insn.reg_name(memory.base) == 'rip' and not memory.index:
                    return self.relocations.get(insn.address + insn.size + memory.disp)
            return None
        return None

    def pc_thunk(self, address: int) -> str | None:
        """Return the register loaded by an exact local `mov reg,[esp]; ret` thunk."""
        if self.machine != 'EM_386' or self.elf.elfclass != 32:
            return None
        # The canonical 32-bit thunk is four bytes: mov reg,[esp]; ret.
        code = self.read(address, 4, executable=True)
        if code is None:
            return None
        instructions = list(self.disassembler.disasm(code, address))
        if len(instructions) < 2:
            return None
        load, ret = instructions[:2]
        if (load.mnemonic != 'mov' or len(load.operands) != 2
                or load.operands[0].type != X86_OP_REG or load.operands[1].type != X86_OP_MEM
                or ret.mnemonic != 'ret' or ret.operands):
            return None
        memory = load.operands[1].mem
        if (load.reg_name(memory.base) != 'esp' or memory.index or memory.disp != 0
                or load.operands[0].size != 4):
            return None
        return load.reg_name(load.operands[0].reg)

    @staticmethod
    def format_instructions(instructions):
        return [{'address': hex(i.address), 'instruction': f'{i.mnemonic} {i.op_str}'.strip()}
                for i in instructions]
