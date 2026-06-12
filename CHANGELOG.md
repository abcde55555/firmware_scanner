# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Unified logging framework (core.log module)
- RIOT OS and Mbed OS detection plugins
- Offline CVE database for common embedded components
- Automated test framework with pytest
- CI/CD pipeline (GitHub Actions)
- Pre-commit hooks configuration
- Makefile for common development tasks

### Changed
- Externalized signature databases from Python code to JSON files
- Version number now uses single source from pyproject.toml

### Fixed
- Version number inconsistency across modules
- Dead code in deep_scanner._scan_one_section
- Bare exception-pass patterns replaced with logged exceptions

## [0.2.0] - 2026-06-03

### Added
- CycloneDX 1.5 SBOM generation with PURL and confidence scores
- Recursive unpacker (ZIP/gzip/LZMA/XZ/SquashFS/CPIO/U-Boot)
- Android system image analysis (ext4/EROFS/YAFFS2/sparse)
- EMBA rule engine integration (529 rules)
- Deep scanner with 200+ component signatures
- OSV vulnerability scanning with 24h local cache
- Cross-validation with 6-method weighted voting
- Scan telemetry logging

## [0.1.0] - 2026-05-29

### Added
- Initial firmware scanner implementation
- ELF/HEX/SREC format support
- Basic RTOS detection (FreeRTOS, Zephyr, RT-Thread)
- String pattern extraction
- CLI interface with Typer
