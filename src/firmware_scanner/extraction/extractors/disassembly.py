"""Capstone disassembly-based component detection via instruction patterns."""

from ...core.context import AnalysisContext
from ...arch.models import CPUFamily
from ..models import Component, VersionConfidence, ExtractionMethod
from .base import BaseExtractor

try:
    import capstone

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


# Known function prologues for different RTOS
FUNCTION_PROLOGUE_PATTERNS = {
    "FreeRTOS": {
        "arm_thumb": [
            # xTaskCreate prologue pattern (PUSH {r4-r7, lr})
            bytes([0xF0, 0xB5]),
            # vTaskSwitchContext (common pattern)
            bytes([0x2D, 0xE9]),
        ],
    },
    "Zephyr RTOS": {
        "arm_thumb": [
            # z_swap pattern
            bytes([0x2D, 0xE9, 0xF0, 0x4F]),
        ],
    },
}

# Instruction sequence fingerprints (mnemonic sequences)
MNEMONIC_SIGNATURES = {
    "FreeRTOS": [
        # Context switch signature: save PSP, load new task's SP
        ["mrs", "stmdb", "str", "ldr", "ldmia", "msr"],
        # SVC handler pattern
        ["mrs", "ldr", "ldr", "str"],
    ],
    "ThreadX": [
        # tx_thread_schedule pattern
        ["ldr", "cmp", "beq", "ldr", "str", "ldr", "bx"],
    ],
}

MAX_DISASM_SIZE = 64 * 1024  # 64KB per section


class DisassemblyExtractor(BaseExtractor):
    @property
    def name(self) -> str:
        return "disassembly"

    def is_available(self) -> bool:
        return CAPSTONE_AVAILABLE

    @property
    def priority(self) -> int:
        return 40

    async def extract(self, context: AnalysisContext) -> list[Component]:
        if not CAPSTONE_AVAILABLE:
            return []

        arch_info = context.arch_info
        if not arch_info:
            return []

        md = self._get_capstone_engine(arch_info.cpu_family)
        if md is None:
            return []

        components: dict[str, Component] = {}

        # Analyze code sections
        if context.unpack_result:
            for section in context.unpack_result.sections:
                if section.section_type not in ("code", "unknown"):
                    continue
                data = section.data[:MAX_DISASM_SIZE]
                if not data:
                    continue

                found = self._analyze_code(md, data, arch_info.cpu_family)
                for name, evidence in found.items():
                    if name not in components:
                        components[name] = Component(
                            name=name,
                            component_type="operating-system",
                        )
                    components[name].versions.append(
                        VersionConfidence(
                            version="detected",
                            confidence=0.6,
                            method=ExtractionMethod.DISASSEMBLY,
                            evidence=evidence,
                        )
                    )
        else:
            # Analyze raw data
            data = context.raw_data[:MAX_DISASM_SIZE]
            found = self._analyze_code(md, data, arch_info.cpu_family)
            for name, evidence in found.items():
                if name not in components:
                    components[name] = Component(
                        name=name,
                        component_type="operating-system",
                    )
                components[name].versions.append(
                    VersionConfidence(
                        version="detected",
                        confidence=0.5,
                        method=ExtractionMethod.DISASSEMBLY,
                        evidence=evidence,
                    )
                )

        return list(components.values())

    def _get_capstone_engine(self, cpu_family: CPUFamily):
        if not CAPSTONE_AVAILABLE:
            return None

        arch_mode_map = {
            CPUFamily.ARM: (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            CPUFamily.ARM_CORTEX_M: (capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB),
            CPUFamily.ARM_CORTEX_A: (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            CPUFamily.ARM_CORTEX_R: (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            CPUFamily.MIPS: (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN),
        }

        if cpu_family not in arch_mode_map:
            return None

        arch, mode = arch_mode_map[cpu_family]
        md = capstone.Cs(arch, mode)
        md.detail = True
        return md

    def _analyze_code(self, md, data: bytes, cpu_family: CPUFamily) -> dict[str, str]:
        """Analyze disassembled code for known patterns."""
        results: dict[str, str] = {}

        instructions = list(md.disasm(data, 0))
        if not instructions:
            return results

        # Build mnemonic sequence
        mnemonics = [insn.mnemonic for insn in instructions[:500]]

        # Check for known mnemonic sequences
        for rtos_name, patterns in MNEMONIC_SIGNATURES.items():
            for pattern in patterns:
                if self._find_sequence(mnemonics, pattern):
                    results[rtos_name] = f"Instruction pattern: {' '.join(pattern)}"
                    break

        # Check function prologue bytes
        mode_key = "arm_thumb" if cpu_family == CPUFamily.ARM_CORTEX_M else "arm"
        for rtos_name, modes in FUNCTION_PROLOGUE_PATTERNS.items():
            if mode_key in modes:
                for prologue in modes[mode_key]:
                    if prologue in data:
                        if rtos_name not in results:
                            results[rtos_name] = f"Prologue pattern at offset {data.index(prologue):#x}"

        # Detect SVC/SWI calls (common in RTOS context switches)
        svc_count = sum(1 for insn in instructions if insn.mnemonic in ("svc", "swi"))
        if svc_count >= 3:
            # Multiple SVC calls suggest RTOS syscall interface
            if not results:
                results["RTOS (generic)"] = f"Detected {svc_count} SVC/SWI instructions"

        return results

    def _find_sequence(self, mnemonics: list[str], pattern: list[str]) -> bool:
        """Check if pattern exists as a subsequence within a window."""
        pattern_len = len(pattern)
        window = pattern_len + 4  # Allow some gap

        for i in range(len(mnemonics) - window):
            window_slice = mnemonics[i : i + window]
            j = 0
            for mnemonic in window_slice:
                if j < pattern_len and mnemonic == pattern[j]:
                    j += 1
            if j == pattern_len:
                return True
        return False
