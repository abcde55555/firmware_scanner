# RTOS Firmware Analyzer - Product Requirements Document (PRD)

## 1. Product Overview

**Product Name:** RTOS Firmware Analyzer  
**Version:** 0.1.0  
**Type:** CLI Security Analysis Tool

### 1.1 Purpose

A command-line tool for security researchers and firmware engineers to:
- Unpack RTOS firmware binaries of various formats
- Identify CPU architecture and RTOS type
- Extract all embedded software components and their versions
- Generate industry-standard CycloneDX SBOM for vulnerability management

### 1.2 Target Users

- Firmware security researchers performing vulnerability assessments
- Supply chain security teams needing SBOM for IoT/embedded products
- Embedded developers auditing third-party firmware dependencies
- Compliance teams verifying component licensing

---

## 2. Functional Requirements

### 2.1 Firmware Input Support

| Priority | Requirement | Status |
|----------|-------------|--------|
| P0 | ELF binary parsing (ARM, MIPS, RISC-V, Xtensa) | Done |
| P0 | Raw binary (.bin, .img, .fw) analysis | Done |
| P0 | Intel HEX (.hex) format parsing | Done |
| P0 | Motorola S-Record (.srec/.s19) parsing | Done |
| P0 | ESP-IDF image format parsing | Done |
| P1 | VxWorks firmware image parsing | Extension point |
| P1 | Qualcomm/MediaTek proprietary formats | Extension point |
| P2 | Compressed firmware auto-extraction (gzip, lzma, lz4) | Planned |
| P2 | Filesystem extraction (JFFS2, SquashFS, CramFS) | Planned |

### 2.2 Architecture Detection

| Priority | Requirement | Status |
|----------|-------------|--------|
| P0 | ARM Cortex-M/A/R detection | Done |
| P0 | MIPS (big/little endian) detection | Done |
| P0 | RISC-V detection | Done |
| P0 | Xtensa (ESP32) detection | Done |
| P0 | Byte order (endianness) detection | Done |
| P0 | Word size (32/64-bit) detection | Done |
| P1 | Specific SoC model identification | Partial |

### 2.3 Component Extraction

| Priority | Requirement | Status |
|----------|-------------|--------|
| P0 | String pattern matching with 200+ signatures | Done |
| P0 | ELF symbol table parsing | Done |
| P0 | Binary signature/fingerprint matching | Done |
| P0 | Deep per-section exhaustive scanning | Done |
| P0 | Proximity-based version detection | Done |
| P0 | Cross-validation across multiple methods | Done |
| P1 | Capstone disassembly-based detection | Done |
| P1 | radare2 deep analysis integration | Done (optional) |
| P1 | Ghidra decompilation integration | Done (optional) |
| P2 | Function similarity hashing (FLIRT-like) | Planned |
| P2 | Machine learning-based component identification | Planned |

### 2.4 SBOM Output

| Priority | Requirement | Status |
|----------|-------------|--------|
| P0 | CycloneDX 1.5 JSON format | Done |
| P0 | Component PURL generation | Done |
| P0 | Firmware hash (SHA-256, MD5) | Done |
| P0 | Analysis confidence scores | Done |
| P0 | Extraction evidence trail | Done |
| P1 | SPDX output format | Planned |
| P2 | VEX (Vulnerability Exploitability eXchange) | Planned |

### 2.5 Extensibility

| Priority | Requirement | Status |
|----------|-------------|--------|
| P0 | Plugin directory for custom analyzers | Done |
| P0 | JSON-based signature file loading | Done |
| P0 | RTOS plugin registration system | Done |
| P1 | Entry-point based plugin discovery (pip) | Done |
| P2 | Remote signature database update | Planned |

---

## 3. Non-Functional Requirements

### 3.1 Performance
- Analyze 1MB firmware in < 5 seconds (without radare2/Ghidra)
- Analyze 100MB firmware in < 60 seconds
- Memory usage: < 2x firmware file size

### 3.2 Accuracy
- False positive rate: < 10% for named components
- Version accuracy: > 80% for components with embedded version strings
- Architecture detection accuracy: > 95% for ELF files

### 3.3 Compatibility
- Python 3.10+
- Windows, Linux, macOS
- Optional dependencies gracefully degraded

---

## 4. RTOS Coverage

| RTOS | Detection | Version Extraction | Deep Analysis |
|------|-----------|-------------------|---------------|
| FreeRTOS | Full | Full | Full |
| Zephyr | Full | Full | Full |
| RT-Thread | Full | Full | Full |
| ESP-IDF | Full | Full | Full |
| VxWorks | Full | Full | Basic |
| ThreadX (Azure RTOS) | Full | Full | Full |
| NuttX | Full | Full | Basic |
| LiteOS | Full | Full | Basic |
| uC/OS-II/III | Full | Full | Basic |

---

## 5. Component Coverage (200+ signatures)

### Categories:
- **RTOS Kernels** (9): FreeRTOS, Zephyr, RT-Thread, ESP-IDF, VxWorks, ThreadX, NuttX, LiteOS, uC/OS
- **TLS/Crypto** (8): mbedTLS, wolfSSL, BearSSL, OpenSSL, TinyCrypt, HACL*, libsodium, micro-ecc
- **Network Stacks** (12): lwIP, uIP, MQTT, CoAP, libcurl, Mongoose, CivetWeb, libwebsockets, HTTP parser, etc.
- **Bluetooth** (3): NimBLE, BTstack, ESP-BT
- **File Systems** (7): FatFs, LittleFS, SPIFFS, JFFS2, YAFFS, SquashFS, NVS
- **USB** (3): TinyUSB, CherryUSB, USBX
- **Serialization** (7): cJSON, Jansson, JSMN, nanopb, protobuf-c, MessagePack, CBOR
- **Compression** (5): zlib, LZ4, Snappy, Heatshrink, miniz
- **Graphics** (4): LVGL, emWin, TouchGFX, u8g2
- **HAL/Drivers** (10+): STM32 HAL/LL, nRF SDK, CMSIS, TI DriverLib, NXP SDK, Cypress, Renesas, etc.
- **Bootloaders** (2): U-Boot, MCUboot
- **IoT SDKs** (3): AWS IoT, Azure IoT, Golioth
- **DSP/ML** (2): CMSIS-DSP, TFLite Micro
- **Protocol** (3): FreeModbus, CANopenNode, OpenThread
- **Misc** (10+): SEGGER RTT, Matter, printf, Newlib, picolibc, Unity, etc.

---

## 6. Success Metrics

| Metric | Target |
|--------|--------|
| Components detected per average IoT firmware | 8-15 |
| Version correctly extracted | > 70% of detected components |
| Analysis time for 1MB firmware | < 5 seconds |
| False positive rate | < 10% |
| CycloneDX schema compliance | 100% |
