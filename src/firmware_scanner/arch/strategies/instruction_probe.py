"""Capstone-based instruction probing for architecture detection."""

from ...arch.models import ArchInfo, CPUFamily, Endianness, FileType

try:
    import capstone

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


PROBE_CONFIGS = [
    # (capstone_arch, capstone_mode, cpu_family, endianness, label)
    (3, 0, CPUFamily.ARM, Endianness.LITTLE, "ARM LE"),  # CS_ARCH_ARM, CS_MODE_ARM
    (3, 0x10, CPUFamily.ARM_CORTEX_M, Endianness.LITTLE, "Thumb LE"),  # CS_MODE_THUMB
    (3, 0x80000000, CPUFamily.ARM, Endianness.BIG, "ARM BE"),  # CS_MODE_BIG_ENDIAN
    (2, 0x04, CPUFamily.MIPS, Endianness.BIG, "MIPS32 BE"),  # CS_ARCH_MIPS, CS_MODE_MIPS32 | BIG
    (2, 0x04 | 0x80000000, CPUFamily.MIPS, Endianness.LITTLE, "MIPS32 LE"),
]

# When Capstone bindings expose RISC-V, use this
RISCV_PROBE = None

MIN_VALID_INSTRUCTIONS = 10
PROBE_SIZE = 256


def detect_from_instruction_probe(data: bytes, offset: int = 0) -> ArchInfo | None:
    """Try decoding bytes as different architectures; best fit wins."""
    if not CAPSTONE_AVAILABLE:
        return None

    if len(data) < offset + PROBE_SIZE:
        return None

    probe_data = data[offset : offset + PROBE_SIZE]
    best_score = 0
    best_result: ArchInfo | None = None

    for arch, mode, cpu_family, endianness, label in PROBE_CONFIGS:
        try:
            md = capstone.Cs(arch, mode)
            md.skipdata = True
            instructions = list(md.disasm(probe_data, 0))
            valid_count = len(instructions)

            if valid_count >= MIN_VALID_INSTRUCTIONS:
                score = valid_count / (PROBE_SIZE / 4)
                if score > best_score:
                    best_score = score
                    best_result = ArchInfo(
                        cpu_family=cpu_family,
                        endianness=endianness,
                        file_type=FileType.RAW_BINARY,
                        word_size=32,
                        specific_model=label,
                        confidence=min(score * 0.7, 0.85),
                    )
        except Exception:
            continue

    # Try RISC-V detection via RV32I pattern matching
    riscv_result = _probe_riscv(probe_data)
    if riscv_result and (best_result is None or riscv_result.confidence > best_result.confidence):
        best_result = riscv_result

    return best_result


def _probe_riscv(data: bytes) -> ArchInfo | None:
    """Heuristic RISC-V detection via instruction encoding patterns."""
    if len(data) < 16:
        return None

    valid_rv32 = 0
    total_checks = 0

    for i in range(0, min(len(data) - 4, PROBE_SIZE), 4):
        word = int.from_bytes(data[i : i + 4], "little")
        opcode = word & 0x7F
        total_checks += 1

        # Valid RV32I opcodes
        rv32_opcodes = {
            0x03, 0x13, 0x17, 0x23, 0x33, 0x37,  # LOAD, OP-IMM, AUIPC, STORE, OP, LUI
            0x63, 0x67, 0x6F, 0x73,               # BRANCH, JALR, JAL, SYSTEM
        }
        if opcode in rv32_opcodes:
            valid_rv32 += 1

    if total_checks == 0:
        return None

    ratio = valid_rv32 / total_checks
    if ratio >= 0.5:
        return ArchInfo(
            cpu_family=CPUFamily.RISCV,
            endianness=Endianness.LITTLE,
            file_type=FileType.RAW_BINARY,
            word_size=32,
            specific_model="RV32",
            confidence=min(ratio * 0.8, 0.8),
        )

    return None
