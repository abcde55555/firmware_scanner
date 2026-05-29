"""Architecture detection data models."""

from enum import Enum
from pydantic import BaseModel


class CPUFamily(str, Enum):
    ARM_CORTEX_M = "arm-cortex-m"
    ARM_CORTEX_A = "arm-cortex-a"
    ARM_CORTEX_R = "arm-cortex-r"
    ARM = "arm"
    MIPS = "mips"
    RISCV = "riscv"
    XTENSA = "xtensa"
    UNKNOWN = "unknown"


class Endianness(str, Enum):
    LITTLE = "little"
    BIG = "big"
    UNKNOWN = "unknown"


class FileType(str, Enum):
    ELF = "elf"
    PE = "pe"
    INTEL_HEX = "intel_hex"
    SREC = "srec"
    RAW_BINARY = "raw_binary"
    ESP_IMAGE = "esp_image"
    UNKNOWN = "unknown"


class ArchInfo(BaseModel):
    cpu_family: CPUFamily = CPUFamily.UNKNOWN
    endianness: Endianness = Endianness.UNKNOWN
    file_type: FileType = FileType.UNKNOWN
    word_size: int = 32
    specific_model: str = ""
    confidence: float = 0.0
