# Development Roadmap

## Phase 1: Core Engine (COMPLETE)

- [x] Project scaffolding (pyproject.toml, package structure)
- [x] Firmware format handlers (ELF, HEX, SREC, Raw Binary, ESP-IDF)
- [x] Architecture detection (ARM, MIPS, RISC-V, Xtensa)
- [x] RTOS detection plugins (9 RTOS types)
- [x] String pattern extraction
- [x] Symbol table extraction
- [x] Binary signature matching
- [x] Cross-validation orchestrator
- [x] CycloneDX SBOM generation
- [x] CLI interface (analyze, unpack, detect, plugins)

## Phase 2: Deep Analysis (COMPLETE)

- [x] Deep per-section scanner engine
- [x] 200+ component signature database
- [x] Proximity-based version detection
- [x] Version define assembly (MAJOR.MINOR.PATCH)
- [x] Global version search fallback
- [x] Word-boundary checking for short patterns
- [x] Plugin extension architecture
- [x] JSON signature file loading
- [x] Python plugin hot-loading

## Phase 3: Enhanced Analysis (COMPLETE)

- [x] Capstone disassembly for all detected architectures
- [ ] Function prologue fingerprinting (FLIRT-like)
- [ ] Cross-reference analysis (who calls what)
- [x] Compressed section auto-extraction (gzip, lzma, xz, zstd)
- [x] Nested firmware image detection and recursive analysis
- [x] Build metadata extraction (.comment, .note, build-id)
- [x] GCC/Clang/IAR/Keil compiler version detection
- [ ] Linker script analysis for memory map
- [x] Multi-threaded deep scanning (ThreadPoolExecutor)
- [x] Progress bar with ETA calculation
- [x] User config file system (~/.rtos-analyzer/config.json)
- [x] Graceful dependency degradation (no crashes for missing tools)
- [x] First-run dependency check command (check-deps)

## Phase 4: Format Support Expansion (COMPLETE)

- [ ] VxWorks firmware image parsing (bootrom, VxWorks image)
- [ ] Qualcomm MELF/SBL format
- [ ] MediaTek scatter file format
- [x] U-Boot image (uImage, FIT)
- [ ] Android boot image (boot.img)
- [ ] ARM Trusted Firmware (BL1/BL2/BL31)
- [ ] UEFI firmware volume
- [ ] Intel firmware descriptor
- [ ] Broadcom TRX format
- [x] Generic compressed firmware (gzip, xz, lzma, zstd wrapped)

## Phase 5: Filesystem Extraction

- [ ] SquashFS extraction
- [ ] CramFS extraction
- [ ] JFFS2 extraction
- [ ] YAFFS extraction
- [ ] LittleFS image parsing
- [ ] SPIFFS image parsing
- [ ] FAT filesystem parsing
- [ ] ext2/ext4 minimal parsing

## Phase 6: Advanced Identification

- [ ] Function hash database (pre-computed hashes for known library versions)
- [ ] Basic block similarity matching
- [ ] Constant pool analysis (magic numbers, lookup tables)
- [ ] String frequency analysis (language detection, SDK fingerprinting)
- [ ] Version range inference from API usage patterns
- [ ] CVE mapping (component+version → known vulnerabilities)
- [ ] License detection from embedded copyright strings

## Phase 7: Integration & Reporting (PARTIAL)

- [ ] SPDX output format
- [x] HTML report generation (standalone, styled)
- [ ] PDF report generation
- [ ] GitHub Actions integration
- [ ] CI/CD pipeline support (exit codes, machine-readable output)
- [ ] Vulnerability database integration (NVD, OSV)
- [ ] Diff mode (compare two firmware versions)
- [ ] Watch mode (monitor directory for new firmware)

## Phase 8: Remote Analysis

- [ ] Remote signature database updates
- [ ] Cloud-based Ghidra analysis
- [ ] Distributed scanning for large firmware sets
- [ ] API server mode (REST API for integration)
- [ ] Multi-firmware batch analysis

---

## Extension Points for Custom Firmware

When you need to scan a new type of firmware:

### 1. Custom Format Handler
Add to `firmware/formats/` - handles specific container format

### 2. Custom RTOS Plugin  
Add to `rtos/plugins/` - handles RTOS-specific detection and analysis

### 3. Custom Signature File
Drop a JSON file in your `--plugin-dir` with patterns for your specific components

### 4. Custom Python Plugin
Write a Python class implementing `AnalyzerPlugin` protocol for complex analysis logic

### 5. Custom Extractor
Add to `extraction/extractors/` for fundamentally new extraction approaches

---

## Priority Matrix

| Impact | Effort | Item |
|--------|--------|------|
| High | Low | Add more version patterns to signature DB |
| High | Low | Add compressed section auto-extraction |
| High | Medium | Function hash database |
| High | Medium | Filesystem extraction |
| High | High | CVE mapping integration |
| Medium | Low | SPDX output |
| Medium | Medium | Build metadata extraction |
| Medium | High | ML-based identification |
| Low | Low | HTML report |
| Low | Medium | API server mode |
