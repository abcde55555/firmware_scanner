"""Magic byte sequence-based architecture detection."""

from ...arch.models import ArchInfo, CPUFamily, Endianness, FileType

MAGIC_SIGNATURES = [
    # (offset, bytes, cpu_family, endianness, specific_model, file_type)
    (0, b"\x7fELF", None, None, "", FileType.ELF),
    (0, b"MZ", None, None, "", FileType.PE),

    # ARM Cortex-M vector table patterns (MSP followed by Reset_Handler)
    # Stack pointer typically in 0x20000000-0x20080000 range (RAM)
    # These detect raw binary ARM firmware by vector table
]

# ARM Cortex-M: vector table starts with SP (0x2000xxxx) then PC (0x0800xxxx or 0x0000xxxx)
ARM_CM_SP_RANGE = (0x20000000, 0x20100000)
ARM_CM_PC_RANGE_FLASH = (0x08000000, 0x08200000)
ARM_CM_PC_RANGE_LOW = (0x00000000, 0x00100000)

# MIPS: common NOP (0x00000000) or branch instructions at entry
MIPS_BE_NOP = b"\x00\x00\x00\x00"
MIPS_BRANCH_PREFIX_BE = b"\x10\x00"  # beq $zero, $zero
MIPS_BRANCH_PREFIX_LE = b"\x00\x10"

# ESP image magic
ESP_MAGIC = 0xE9


def detect_from_magic_bytes(data: bytes) -> ArchInfo | None:
    """Detect architecture from known magic byte patterns."""
    if len(data) < 8:
        return None

    # ESP-IDF image
    if data[0] == ESP_MAGIC:
        return ArchInfo(
            cpu_family=CPUFamily.XTENSA,
            endianness=Endianness.LITTLE,
            file_type=FileType.ESP_IMAGE,
            word_size=32,
            specific_model="ESP32",
            confidence=0.7,
        )

    # ARM Cortex-M vector table detection (raw binary)
    if len(data) >= 8:
        sp_le = int.from_bytes(data[0:4], "little")
        pc_le = int.from_bytes(data[4:8], "little")

        if (ARM_CM_SP_RANGE[0] <= sp_le <= ARM_CM_SP_RANGE[1]) and (
            (ARM_CM_PC_RANGE_FLASH[0] <= pc_le <= ARM_CM_PC_RANGE_FLASH[1])
            or (ARM_CM_PC_RANGE_LOW[0] < pc_le <= ARM_CM_PC_RANGE_LOW[1])
        ):
            # Verify the PC is odd (Thumb mode, mandatory for Cortex-M)
            if pc_le & 1:
                return ArchInfo(
                    cpu_family=CPUFamily.ARM_CORTEX_M,
                    endianness=Endianness.LITTLE,
                    file_type=FileType.RAW_BINARY,
                    word_size=32,
                    specific_model="Cortex-M (vector table detected)",
                    confidence=0.75,
                )

    # MIPS detection via common entry patterns
    if data[:4] == MIPS_BE_NOP or data[:2] == MIPS_BRANCH_PREFIX_BE:
        return ArchInfo(
            cpu_family=CPUFamily.MIPS,
            endianness=Endianness.BIG,
            file_type=FileType.RAW_BINARY,
            word_size=32,
            confidence=0.4,
        )

    return None
