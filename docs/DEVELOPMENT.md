# Development Documentation

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                          CLI Layer (Typer)                       │
│  analyze | unpack | detect | plugins                            │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                      Analysis Pipeline                           │
│  Load → Unpack → Arch Detect → RTOS Detect → Extract → SBOM    │
└──┬──────────┬──────────┬──────────┬──────────┬──────────┬───────┘
   │          │          │          │          │          │
   ▼          ▼          ▼          ▼          ▼          ▼
┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────────┐  ┌──────┐
│Loader│  │Unpack│  │ Arch │  │ RTOS │  │Extraction│  │ SBOM │
│      │  │      │  │Detect│  │Plugin│  │Orchestr. │  │ Gen  │
└──────┘  └──────┘  └──────┘  └──────┘  └────┬─────┘  └──────┘
                                              │
                    ┌─────────────────────────┬┴┬─────────────┐
                    ▼             ▼           ▼ ▼             ▼
              ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
              │  String  │ │  Symbol  │ │  Deep    │ │  r2/     │
              │ Patterns │ │  Table   │ │ Scanner  │ │  Ghidra  │
              └──────────┘ └──────────┘ └──────────┘ └──────────┘
                                              │
                                    ┌─────────▼──────────┐
                                    │  Component DB      │
                                    │  (200+ signatures) │
                                    └────────────────────┘
```

## Module Descriptions

### `core/` - Framework Foundation
- **`config.py`** - Analysis configuration (paths, timeouts, feature flags)
- **`context.py`** - Shared state passed through pipeline stages
- **`pipeline.py`** - Stage-based pipeline orchestration
- **`errors.py`** - Exception hierarchy with exit codes
- **`plugin_manager.py`** - Plugin loading, registration, and execution

### `firmware/` - Input Handling
- **`loader.py`** - File validation, reading, hashing
- **`unpacker.py`** - Format detection and unpacking orchestrator
- **`formats/`** - Format handlers (ELF, HEX, SREC, raw, ESP-IDF)

### `arch/` - Architecture Detection
- **`detector.py`** - Multi-strategy detection orchestrator
- **`strategies/`** - ELF headers, magic bytes, Capstone probing, entropy

### `extraction/` - Component Discovery
- **`orchestrator.py`** - Runs all extractors, cross-validates results
- **`deep_scanner.py`** - Exhaustive per-section scanning with 200+ signatures
- **`extractors/`** - Individual extraction strategies:
  - `string_patterns.py` - Regex-based version string extraction
  - `symbol_table.py` - ELF symbol to component mapping
  - `disassembly.py` - Capstone instruction pattern matching
  - `binary_signatures.py` - Known byte sequence matching
  - `radare2_ext.py` - r2pipe integration for deep analysis
  - `ghidra_ext.py` - pyhidra/headless Ghidra integration

### `rtos/` - RTOS-Specific Analysis
- **`registry.py`** - Plugin discovery and detection orchestrator
- **`base.py`** - Abstract plugin interface
- **`plugins/`** - Per-RTOS analyzers (FreeRTOS, Zephyr, RT-Thread, etc.)

### `sbom/` - Output Generation
- **`generator.py`** - High-level SBOM generation
- **`cyclonedx.py`** - CycloneDX 1.5 JSON serialization

---

## How the Deep Scanner Works

The deep scanner (`extraction/deep_scanner.py`) is the primary mechanism for comprehensive component discovery:

1. **Section Iteration** - Analyzes every unpacked section + raw firmware data
2. **Signature Matching** - Scans for 200+ ASCII patterns with word-boundary checks
3. **Version Pattern Matching** - Runs 50+ regex patterns for versioned strings
4. **Proximity Search** - For each signature hit, searches 512 bytes around it for version numbers
5. **Global Version Search** - If proximity fails, searches entire firmware for "ComponentName vX.Y.Z"
6. **Version Define Search** - Looks for C-style `#define COMPONENT_VERSION "X.Y.Z"` patterns
7. **MAJOR.MINOR.PATCH Assembly** - Combines separate version defines if found

### Version Resolution Priority

```
1. Direct version string with component name (highest confidence)
2. Version define constant (COMPONENT_VERSION_STRING)
3. Nearby version in proximity window
4. Global search for component + version pattern
5. Assembled MAJOR.MINOR.PATCH defines
6. "detected (version unknown)" (fallback)
```

---

## Plugin Development Guide

### Creating a Custom Plugin

Create a Python file in your plugin directory:

```python
# my_custom_plugin.py
from rtos_firmware_analyzer.core.plugin_manager import AnalyzerPlugin
from rtos_firmware_analyzer.extraction.deep_scanner import SignatureEntry, VersionPatternEntry

class MyCustomPlugin:
    @property
    def name(self) -> str:
        return "my-custom-scanner"

    @property
    def version(self) -> str:
        return "1.0.0"

    def get_signatures(self) -> list[SignatureEntry]:
        return [
            SignatureEntry("MyLibrary", "MyLibrary", "MyVendor", "library"),
            SignatureEntry("mylib_init", "MyLibrary", "MyVendor", "library"),
        ]

    def get_version_patterns(self) -> list[VersionPatternEntry]:
        return [
            VersionPatternEntry(
                r"MyLibrary\s+v(\d+\.\d+\.\d+)",
                "MyLibrary", "MyVendor", "library"
            ),
        ]

    async def analyze(self, context) -> list:
        return []  # Custom analysis logic
```

### Using Custom Signatures via JSON

Create a JSON file in your plugin directory:

```json
{
  "signatures": [
    {"pattern": "MyComponent", "name": "MyComponent", "vendor": "MyVendor", "type": "library"},
    {"pattern": "my_func_init", "name": "MyComponent", "vendor": "MyVendor", "type": "library"}
  ],
  "version_patterns": [
    {"pattern": "MyComponent\\s+v(\\d+\\.\\d+\\.\\d+)", "name": "MyComponent", "vendor": "MyVendor", "type": "library"}
  ]
}
```

### Running with Plugins

```bash
rtos-firmware-analyzer analyze firmware.bin --plugin-dir ./my_plugins/ -o sbom.json
```

---

## Adding a New RTOS Plugin

1. Create `src/rtos_firmware_analyzer/rtos/plugins/my_rtos.py`
2. Implement the `RTOSPlugin` interface
3. Decorate with `@RTOSRegistry.register`
4. Add known symbols, version patterns, and detection heuristics
5. Import in `rtos/plugins/__init__.py`

---

## Adding a New Firmware Format

1. Create `src/rtos_firmware_analyzer/firmware/formats/my_format.py`
2. Implement the `FirmwareFormat` interface
3. Implement `can_handle()` (return confidence 0-1)
4. Implement `unpack()` (return sections with data)
5. Add to `FORMAT_HANDLERS` in `firmware/unpacker.py`

---

## Build & Test

```bash
# Install in development mode
pip install -e ".[dev]"

# Install with all optional analysis tools
pip install -e ".[full]"

# Run tests
pytest tests/ -v

# Type check
mypy src/

# Lint
ruff check src/
```
