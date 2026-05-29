"""Ghidra-based deep decompilation and function signature analysis."""

import json
import subprocess
import tempfile
from pathlib import Path

from ...core.context import AnalysisContext
from ...arch.models import CPUFamily
from ..models import Component, VersionConfidence, ExtractionMethod
from .base import BaseExtractor

PYHIDRA_AVAILABLE = False
try:
    import pyhidra
    PYHIDRA_AVAILABLE = True
except Exception:
    pass


# Decompiled code patterns that indicate specific components
DECOMPILED_PATTERNS = {
    "FreeRTOS": [
        "pxCurrentTCB",
        "uxTopReadyPriority",
        "xSchedulerRunning",
        "pxReadyTasksLists",
        "xTickCount",
        "pxDelayedTaskList",
    ],
    "ThreadX": [
        "_tx_thread_current_ptr",
        "_tx_timer_system_clock",
        "_tx_thread_execute_ptr",
        "_tx_thread_highest_priority",
    ],
    "Zephyr RTOS": [
        "_kernel",
        "z_idle_threads",
        "_current_cpu",
        "z_main_thread",
    ],
    "VxWorks": [
        "taskIdCurrent",
        "vxTicks",
        "readyQHead",
        "workQIsEmpty",
    ],
    "uC/OS": [
        "OSRunning",
        "OSTCBCurPtr",
        "OSPrioCur",
        "OSIntNestingCtr",
    ],
}


class GhidraExtractor(BaseExtractor):
    def __init__(self, ghidra_path: str = ""):
        self._ghidra_path = ghidra_path

    @property
    def name(self) -> str:
        return "ghidra"

    def is_available(self) -> bool:
        if PYHIDRA_AVAILABLE:
            return True
        if self._ghidra_path:
            analyzeHeadless = Path(self._ghidra_path) / "support" / "analyzeHeadless"
            return analyzeHeadless.exists()
        return False

    @property
    def priority(self) -> int:
        return 20

    async def extract(self, context: AnalysisContext) -> list[Component]:
        if PYHIDRA_AVAILABLE:
            return self._extract_pyhidra(context)
        elif self._ghidra_path:
            return self._extract_headless(context)
        return []

    def _extract_pyhidra(self, context: AnalysisContext) -> list[Component]:
        """Use pyhidra for in-process Ghidra analysis."""
        components: dict[str, Component] = {}

        try:
            with pyhidra.open_program(str(context.firmware_path)) as flat_api:
                program = flat_api.getCurrentProgram()
                listing = program.getListing()
                func_manager = program.getFunctionManager()

                # Collect all function names
                func_names = []
                func_iter = func_manager.getFunctions(True)
                while func_iter.hasNext():
                    func = func_iter.next()
                    func_names.append(func.getName())

                # Collect all defined data labels
                data_labels = []
                sym_table = program.getSymbolTable()
                for sym in sym_table.getAllSymbols(True):
                    data_labels.append(sym.getName())

                # Match against known patterns
                all_symbols = func_names + data_labels

                # Check decompiled patterns (global variable names)
                for rtos_name, patterns in DECOMPILED_PATTERNS.items():
                    matched = [p for p in patterns if p in all_symbols]
                    if len(matched) >= 2:
                        confidence = min(0.5 + len(matched) * 0.1, 0.95)
                        components[rtos_name.lower()] = Component(
                            name=rtos_name,
                            component_type="operating-system",
                            versions=[
                                VersionConfidence(
                                    version="detected",
                                    confidence=confidence,
                                    method=ExtractionMethod.GHIDRA,
                                    evidence=f"Symbols: {', '.join(matched[:5])}",
                                )
                            ],
                        )

                # Decompile key functions for version extraction
                from ghidra.app.decompiler import DecompInterface
                decomp = DecompInterface()
                decomp.openProgram(program)

                for func in func_manager.getFunctions(True):
                    fname = func.getName()
                    if any(
                        keyword in fname
                        for keyword in ["version", "Version", "VERSION", "init", "start"]
                    ):
                        result = decomp.decompileFunction(func, 30, None)
                        if result and result.depiledFunction():
                            decomp_code = result.getDecompiledFunction().getC()
                            self._analyze_decompiled(decomp_code, components)

                decomp.dispose()

        except Exception:
            pass

        return list(components.values())

    def _extract_headless(self, context: AnalysisContext) -> list[Component]:
        """Use Ghidra headless analyzer with a script."""
        components: dict[str, Component] = {}

        script_content = self._generate_analysis_script()

        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = Path(tmpdir) / "analyze_firmware.py"
            script_path.write_text(script_content)
            output_path = Path(tmpdir) / "results.json"
            project_path = Path(tmpdir) / "ghidra_project"
            project_path.mkdir()

            analyze_headless = Path(self._ghidra_path) / "support" / "analyzeHeadless"
            cmd = [
                str(analyze_headless),
                str(project_path),
                "firmware_analysis",
                "-import",
                str(context.firmware_path),
                "-postScript",
                str(script_path),
                str(output_path),
                "-deleteProject",
            ]

            # Set processor based on detected arch
            if context.arch_info:
                processor = self._get_ghidra_processor(context.arch_info.cpu_family)
                if processor:
                    cmd.extend(["-processor", processor])

            try:
                subprocess.run(
                    cmd, capture_output=True, timeout=120, check=False
                )

                if output_path.exists():
                    results = json.loads(output_path.read_text())
                    components = self._parse_headless_results(results)
            except (subprocess.TimeoutExpired, json.JSONDecodeError):
                pass

        return list(components.values())

    def _get_ghidra_processor(self, cpu_family: CPUFamily) -> str:
        mapping = {
            CPUFamily.ARM_CORTEX_M: "ARM:LE:32:Cortex",
            CPUFamily.ARM_CORTEX_A: "ARM:LE:32:v7",
            CPUFamily.ARM: "ARM:LE:32:v7",
            CPUFamily.MIPS: "MIPS:BE:32:default",
            CPUFamily.RISCV: "RISCV:LE:32:default",
            CPUFamily.XTENSA: "Xtensa:LE:32:default",
        }
        return mapping.get(cpu_family, "")

    def _generate_analysis_script(self) -> str:
        return '''
import json
import sys
from ghidra.program.model.listing import *
from ghidra.app.decompiler import DecompInterface

output_path = sys.argv[-1]
results = {"functions": [], "strings": [], "symbols": []}

fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    results["functions"].append(func.getName())

st = currentProgram.getSymbolTable()
for sym in st.getAllSymbols(True):
    results["symbols"].append(sym.getName())

# Get defined strings
for data in currentProgram.getListing().getDefinedData(True):
    if data.hasStringValue():
        results["strings"].append(str(data.getValue()))

with open(output_path, "w") as f:
    json.dump(results, f)
'''

    def _parse_headless_results(self, results: dict) -> dict[str, Component]:
        components: dict[str, Component] = {}

        all_symbols = results.get("functions", []) + results.get("symbols", [])

        for rtos_name, patterns in DECOMPILED_PATTERNS.items():
            matched = [p for p in patterns if p in all_symbols]
            if len(matched) >= 2:
                confidence = min(0.5 + len(matched) * 0.1, 0.95)
                components[rtos_name.lower()] = Component(
                    name=rtos_name,
                    component_type="operating-system",
                    versions=[
                        VersionConfidence(
                            version="detected",
                            confidence=confidence,
                            method=ExtractionMethod.GHIDRA,
                            evidence=f"Symbols: {', '.join(matched[:5])}",
                        )
                    ],
                )

        return components

    def _analyze_decompiled(self, code: str, components: dict[str, Component]) -> None:
        """Analyze decompiled C code for version information."""
        import re

        version_patterns = [
            (r'"FreeRTOS\s+V(\d+\.\d+\.\d+)"', "FreeRTOS"),
            (r'"(\d+\.\d+\.\d+)".*version', None),
        ]

        for pattern, comp_name in version_patterns:
            match = re.search(pattern, code)
            if match and comp_name:
                key = comp_name.lower()
                if key not in components:
                    components[key] = Component(
                        name=comp_name,
                        component_type="operating-system",
                    )
                components[key].versions.append(
                    VersionConfidence(
                        version=match.group(1),
                        confidence=0.9,
                        method=ExtractionMethod.GHIDRA,
                        evidence=f"Decompiled: {match.group(0)[:60]}",
                    )
                )
