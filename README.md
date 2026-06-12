# Firmware Scanner

Firmware Scanner is a Python CLI tool for firmware security analysis. It loads and unpacks embedded/IoT firmware images, detects CPU architecture and RTOS families, extracts embedded software components and versions, and generates CycloneDX SBOM plus optional HTML/JSON reports.

> Intended use: defensive security research, firmware inventory, supply-chain review, and compliance workflows for firmware you are authorized to analyze.

## Features

- **Firmware input handling**
  - ELF binaries
  - Raw `.bin`, `.img`, `.fw` images
  - Intel HEX
  - Motorola S-Record
  - ESP-IDF images
  - Compressed/container formats through built-in unpackers and recursive unpacking
- **Architecture detection**
  - ARM, MIPS, RISC-V, Xtensa and related metadata
  - Endianness, word size, file type, and confidence scoring
- **RTOS detection**
  - FreeRTOS, Zephyr, RT-Thread, ESP-IDF, VxWorks, ThreadX/Azure RTOS, NuttX, LiteOS, uC/OS
- **Component extraction**
  - String and version pattern matching
  - ELF symbol analysis
  - Binary signatures
  - Capstone-based instruction probing
  - Optional radare2 and Ghidra integrations
  - Deep per-section scanning with a signature database
- **Reports**
  - CycloneDX 1.5 JSON SBOM
  - Standalone HTML report
  - Raw JSON analysis output
- **Vulnerability scanning**
  - CVE vulnerability matching via OSV (Google Open Source Vulnerabilities) database
  - Supports scanning from firmware directly or from existing SBOM files
  - Local caching with 24h TTL for fast repeated scans
  - Detailed JSON and HTML vulnerability reports
- **Extensibility**
  - Custom plugin directory
  - JSON-based signatures
  - Python entry points for RTOS plugins and extractors

## Requirements

- Python 3.10+
- Supported OS: Windows, Linux, macOS

Core Python dependencies are declared in `pyproject.toml` and include Typer, Rich, Pydantic, Capstone, LIEF, IntelHex, and packageurl-python.

Optional tools:

- `radare2` + `r2pipe` for deeper binary analysis
- Ghidra + `pyhidra` for decompiler-assisted analysis

## Installation

### From source

```bash
git clone https://github.com/abcde55555/firmware_scanner.git
cd firmware_scanner
python -m pip install -e .
```

For optional integrations:

```bash
python -m pip install -e ".[radare2]"
python -m pip install -e ".[ghidra]"
python -m pip install -e ".[full]"
```

For development tools:

```bash
python -m pip install -e ".[dev]"
```

## Quick Start

Show CLI help:

```bash
firmware-scanner --help
```

Analyze firmware and write a CycloneDX SBOM:

```bash
firmware-scanner analyze firmware.bin -o sbom.json
```

Generate all report formats into a directory:

```bash
firmware-scanner analyze firmware.bin -f all -o reports/
```

Detect architecture and RTOS only:

```bash
firmware-scanner detect firmware.bin
```

Unpack firmware sections:

```bash
firmware-scanner unpack firmware.bin -o unpacked/
```

List available RTOS plugins and extractors:

```bash
firmware-scanner plugins
```

Check optional dependency availability:

```bash
firmware-scanner check-deps
```

Create the user configuration file:

```bash
firmware-scanner init
```

Scan firmware for known CVE vulnerabilities:

```bash
firmware-scanner vuln-scan firmware.bin -o vuln_report.html
```

Scan an existing SBOM for vulnerabilities:

```bash
firmware-scanner vuln-scan sbom.json -f vuln-json -o vulns.json
```

You can also run the package module directly:

```bash
python -m firmware_scanner --help
```

## CLI Commands

### `analyze`

Runs the full analysis pipeline:

1. Load firmware and compute hashes
2. Unpack the image
3. Detect architecture
4. Detect RTOS
5. Run extractors and deep scanner
6. Recursively unpack nested files
7. Deduplicate components
8. Export reports

Common options:

```bash
firmware-scanner analyze <firmware> \
  -o <output-file-or-directory> \
  -f sbom -f html -f json \
  --rtos freertos \
  --arch arm \
  --plugin-dir ./plugins \
  --timeout 300 \
  --deep \
  -v
```

Output formats:

- `sbom` / `cyclonedx` - CycloneDX JSON SBOM
- `html` / `report` - standalone HTML report
- `json` - raw analysis data
- `all` - all formats

### `detect`

Prints firmware size, hashes, architecture details, and likely RTOS matches.

```bash
firmware-scanner detect firmware.elf -v
```

### `vuln-scan`

Scans for known CVE vulnerabilities using the OSV database. Accepts either a firmware binary or a CycloneDX SBOM JSON file — the input type is auto-detected.

```bash
# Scan firmware directly (extracts components, then queries CVE database)
firmware-scanner vuln-scan firmware.bin -o vuln_report.html

# Scan an existing SBOM for vulnerabilities
firmware-scanner vuln-scan sbom.json -o vulns.json

# Output both JSON and HTML reports
firmware-scanner vuln-scan firmware.bin -f all -o reports/

# Use a proxy for network access
firmware-scanner vuln-scan firmware.bin --proxy http://127.0.0.1:7890 -o vulns.json
```

Output formats:

- `vuln-json` / `json` - detailed JSON vulnerability report
- `vuln-html` / `html` - standalone HTML vulnerability report
- `all` - both formats

The vulnerability cache is stored in `~/.firmware-scanner/vuln-cache/` with a 24-hour TTL. On each scan the cache freshness is checked; stale entries are automatically refreshed from OSV. If the network is unavailable, cached data is used with a warning.

### `vuln-update`

Independently update or manage the local vulnerability cache.

```bash
# Refresh all cached entries from OSV
firmware-scanner vuln-update

# Refresh via proxy
firmware-scanner vuln-update --proxy http://127.0.0.1:7890

# Clear all cached entries
firmware-scanner vuln-update --clear
```

### `unpack`

Extracts detected sections/files from the input image.

```bash
firmware-scanner unpack firmware.hex --output-dir unpacked/
```

### `plugins`

Shows built-in RTOS plugins and extractor availability.

### `check-deps`

Reports whether optional external dependencies are installed and discoverable.

### `init`

Creates a user configuration file for tool paths such as radare2, Ghidra, and binwalk.

## Project Structure

```text
src/firmware_scanner/
├── cli/             # Typer CLI application
├── core/            # Config, context, pipeline, plugin management
├── firmware/        # Loading, format handlers, unpacking, recursive unpacking
├── arch/            # CPU architecture detection strategies
├── rtos/            # RTOS plugin registry and built-in RTOS analyzers
├── extraction/      # Component extractors, deep scanner, smart analyzer
├── sbom/            # CycloneDX and HTML report generation
├── vuln/            # CVE vulnerability scanning (OSV API, caching, reports)
└── utils/           # Binary utility helpers

data/
├── signatures/      # Built-in RTOS/component signatures
└── patterns/        # Version and function signature patterns

docs/                # Product, install, extension, and development docs
tests/               # Fixtures and generated sample outputs
```

## Analysis Pipeline

```text
Load → Unpack → Architecture Detection → RTOS Detection → Component Extraction → SBOM/Reports
                                                                                 ↓
                                                                          vuln-scan → CVE Matching (OSV) → Vulnerability Reports
```

The deep scanner analyzes unpacked sections and raw firmware data with component signatures, version regexes, proximity search, global version search, and C-style version define detection. Recursive unpacking then inspects nested artifacts such as archives, compressed images, and application packages where supported.

## Extending Firmware Scanner

The project is designed around extension points:

- Add firmware format handlers under `src/firmware_scanner/firmware/formats/`.
- Add RTOS analyzers under `src/firmware_scanner/rtos/plugins/`.
- Add component extractors under `src/firmware_scanner/extraction/extractors/`.
- Register third-party plugins through `pyproject.toml` entry points:
  - `firmware_scanner.rtos_plugins`
  - `firmware_scanner.extractors`

See `docs/EXTENSION_GUIDE.md` and `docs/DEVELOPMENT.md` for implementation details.

## Development

Install development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run tests when test modules are present:

```bash
pytest
```

Run static checks:

```bash
ruff check src tests
mypy src
```

## Documentation

Additional documentation is available in `docs/`:

- `docs/INSTALL.md` - detailed installation and dependency setup
- `docs/DEVELOPMENT.md` - architecture and development guide
- `docs/EXTENSION_GUIDE.md` - plugin and format extension guide
- `docs/PRD.md` - product requirements and coverage
- `docs/ROADMAP.md` - completed and planned work
- `docs/TECHNICAL_PRINCIPLES.md` - technical principles and detection strategy
- `docs/TEST_REPORT.md` - testing notes and observed results

## License

MIT License. See `pyproject.toml` for package metadata.
