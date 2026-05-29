"""ELF header-based architecture detection."""

from pathlib import Path
from ...arch.models import ArchInfo, CPUFamily, Endianness, FileType

# ELF e_machine values
ELF_MACHINES = {
    0x03: (CPUFamily.UNKNOWN, "x86"),
    0x08: (CPUFamily.MIPS, "MIPS"),
    0x28: (CPUFamily.ARM, "ARM"),
    0x2B: (CPUFamily.UNKNOWN, "SPARC"),
    0x3E: (CPUFamily.UNKNOWN, "x86_64"),
    0x5E: (CPUFamily.XTENSA, "Xtensa"),
    0xB7: (CPUFamily.ARM_CORTEX_A, "AArch64"),
    0xF3: (CPUFamily.RISCV, "RISC-V"),
    0xF7: (CPUFamily.UNKNOWN, "BPF"),
}

# ARM ELF flags for Cortex-M detection
ARM_EABI_VER5 = 0x05000000
ARM_ATTR_CORTEX_M = [
    "Cortex-M0", "Cortex-M0+", "Cortex-M1", "Cortex-M3",
    "Cortex-M4", "Cortex-M7", "Cortex-M23", "Cortex-M33",
]


def detect_from_elf_header(data: bytes) -> ArchInfo | None:
    """Detect architecture from ELF header fields."""
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return None

    ei_class = data[4]
    ei_data = data[5]

    word_size = 64 if ei_class == 2 else 32
    endianness = Endianness.LITTLE if ei_data == 1 else Endianness.BIG

    if endianness == Endianness.LITTLE:
        e_machine = int.from_bytes(data[18:20], "little")
        e_flags = int.from_bytes(data[36:40], "little") if word_size == 32 else 0
    else:
        e_machine = int.from_bytes(data[18:20], "big")
        e_flags = int.from_bytes(data[36:40], "big") if word_size == 32 else 0

    cpu_family = CPUFamily.UNKNOWN
    specific_model = ""

    if e_machine in ELF_MACHINES:
        cpu_family, specific_model = ELF_MACHINES[e_machine]

    if cpu_family == CPUFamily.ARM:
        cpu_family = _refine_arm_type(data, e_flags, endianness)

    return ArchInfo(
        cpu_family=cpu_family,
        endianness=endianness,
        file_type=FileType.ELF,
        word_size=word_size,
        specific_model=specific_model,
        confidence=0.95,
    )


def _refine_arm_type(data: bytes, e_flags: int, endianness: Endianness) -> CPUFamily:
    """Try to distinguish Cortex-M vs Cortex-A/R from ELF attributes."""
    # Check for Thumb-only (Cortex-M indicator)
    if e_flags & 0x00000200:  # EF_ARM_MAPSYMSFIRST / often Thumb interwork
        pass

    # Scan .ARM.attributes section for CPU name
    marker = b"aeabi"
    pos = data.find(marker)
    if pos != -1:
        attr_region = data[pos : pos + 256]
        for cortex_m in ARM_ATTR_CORTEX_M:
            if cortex_m.encode() in attr_region:
                return CPUFamily.ARM_CORTEX_M
        if b"Cortex-A" in attr_region:
            return CPUFamily.ARM_CORTEX_A
        if b"Cortex-R" in attr_region:
            return CPUFamily.ARM_CORTEX_R

    return CPUFamily.ARM
