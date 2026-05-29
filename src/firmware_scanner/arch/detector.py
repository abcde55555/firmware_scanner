"""Architecture detection orchestrator."""

from ..arch.models import ArchInfo, CPUFamily, Endianness, FileType
from .strategies.elf_headers import detect_from_elf_header
from .strategies.magic_bytes import detect_from_magic_bytes
from .strategies.instruction_probe import detect_from_instruction_probe
from .strategies.entropy import find_code_regions


class ArchDetector:
    """Orchestrates multiple detection strategies and picks the best result."""

    def detect(self, data: bytes) -> ArchInfo:
        candidates: list[ArchInfo] = []

        # Strategy 1: ELF headers (highest confidence)
        result = detect_from_elf_header(data)
        if result:
            candidates.append(result)

        # Strategy 2: Magic bytes / vector tables
        result = detect_from_magic_bytes(data)
        if result:
            candidates.append(result)

        # Strategy 3: Instruction probing (try multiple offsets)
        probe_offsets = [0]
        if not candidates:
            code_regions = find_code_regions(data)
            probe_offsets.extend(start for start, _ in code_regions[:3])

        for offset in probe_offsets:
            result = detect_from_instruction_probe(data, offset)
            if result:
                candidates.append(result)
                break

        if not candidates:
            return ArchInfo(
                cpu_family=CPUFamily.UNKNOWN,
                endianness=self._guess_endianness(data),
                file_type=self._guess_file_type(data),
                confidence=0.0,
            )

        # Pick highest confidence
        candidates.sort(key=lambda x: x.confidence, reverse=True)
        best = candidates[0]

        # Cross-validate: if multiple strategies agree on CPU family, boost confidence
        if len(candidates) >= 2:
            families = [c.cpu_family for c in candidates[:3]]
            if families[0] == families[1]:
                best = best.model_copy(update={"confidence": min(best.confidence + 0.1, 1.0)})

        return best

    def _guess_endianness(self, data: bytes) -> Endianness:
        """Heuristic: count null bytes in even vs odd positions."""
        if len(data) < 256:
            return Endianness.UNKNOWN

        sample = data[:4096]
        even_nulls = sum(1 for i in range(0, len(sample), 2) if sample[i] == 0)
        odd_nulls = sum(1 for i in range(1, len(sample), 2) if sample[i] == 0)

        if even_nulls > odd_nulls * 1.5:
            return Endianness.BIG
        elif odd_nulls > even_nulls * 1.5:
            return Endianness.LITTLE
        return Endianness.UNKNOWN

    def _guess_file_type(self, data: bytes) -> FileType:
        if data[:4] == b"\x7fELF":
            return FileType.ELF
        if data[:2] == b"MZ":
            return FileType.PE
        if data[:1] == b":":
            return FileType.INTEL_HEX
        if data[:2] in (b"S0", b"S1", b"S2", b"S3"):
            return FileType.SREC
        if data[0] == 0xE9:
            return FileType.ESP_IMAGE
        return FileType.RAW_BINARY
