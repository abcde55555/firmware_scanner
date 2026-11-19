# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.0] - 2026-11-20

### Added
- ARM32 and Thumb getter support for defined functions that return a release
  string through a PC-relative literal
- Cross-checked `FLAC__VERSION_STRING` and `FLAC__VENDOR_STRING` release
  evidence for embedded libFLAC
- OpenSSL `MD5_version` banner-array evidence for legacy embedded releases

### Fixed
- Release getters no longer accept a version string mapped into writable
  memory
- Frozen scan bundles now include their own project metadata so generated BOMs
  report the scanned source version instead of an unrelated installed package

## [0.9.0] - 2026-11-20

### Added
- Crate-level release pins inside revision-pinned Android Rust source monorepos
- Cargo PURLs for 43 confirmed Rust crates, enabling package-aware OSV and VEX queries
- Exact source declarations for Perfetto, fsverity-utils and Piex
- Reproducible database-enabled scans with BLintDB and NSRL command-line options
- Unique-component BLint reconciliation metrics and non-comparable parent-version reporting

### Changed
- Modern Android fixed-cohort exact versions increased from 177 to 225 without changing usable coverage
- Rust dylib components with a confirmed Cargo PURL are queryable even though the firmware keeps a `.dylib.so` filename
- External database reference-build versions remain diagnostic and never replace target versions

### Fixed
- Embedded dependency source paths no longer override the host crate version
- Parent-package versions are no longer compared with upstream BLint reference releases
- Duplicate pre-dedup BLint rows no longer inflate component reconciliation statistics

## [0.8.0] - 2026-11-20

### Added
- Conservative string, integer and structured version getters for 20 additional
  native libraries, including libyaml, libjxl, seccomp and the nghttp2 family
- GMP, GdkPixbuf and libunistring release-object probes
- Manifest-bound ELF source-path evidence and source-project provenance for
  Rust, ANGLE, OpenSSH, fsverity and Android platform libraries
- Exact rust-openssl and OpenSSH source version pins tied to image-matched commits
- Independent 20-library Debian validation suite alongside the 54-library
  development suite
- CLI-equivalent reproduction support for source manifests, family provenance
  and component taxonomy in the version-coverage harness

### Fixed
- libbpf major/minor banners are generation estimates instead of false exact releases
- Parent-package, source-revision, conflict and generation estimates can no longer
  be counted as exact by the coverage evaluator
- Deduplicated BOM rows can cover multiple fixed baseline paths

## [0.7.0] - 2026-11-19

### Added
- Production x86-64/AArch64 FreeType paired-API version probe
- PCRE2 release-date and libssh2 SSH-banner version evidence
- Independent Debian stripped-library held-out evaluation harness

### Fixed
- Source checkouts report the pyproject version instead of stale installed metadata

## [0.6.0] - 2026-11-19

### Added
- BLintDB-confirmed identity as explicit third-party OSS taxonomy evidence
- Taxonomy provenance for source paths, BLint identity and external PURLs

## [0.5.0] - 2026-11-19

### Added
- Package-level APK/JAR license evidence
- Maven POM coordinate, version and license extraction with evidence

### Changed
- Archive licenses are scoped to the package or matching Maven dependency

## [0.4.0] - 2026-11-19

### Added
- Conservative SPDX license attribution from Android NOTICE HTML
- Final post-deduplication license coverage and risk statistics in JSON and BOM output
- Provenance statistics in JSON and CycloneDX metadata

### Changed
- License compliance now reports `incomplete` whenever components lack verified licenses
- Deduplication merges license evidence from duplicate component observations

## [0.3.0] - 2026-11-19

### Added
- Unified logging framework (core.log module)
- RIOT OS and Mbed OS detection plugins
- Offline CVE database for common embedded components
- Automated test framework with pytest
- CI/CD pipeline (GitHub Actions)
- Pre-commit hooks configuration
- Makefile for common development tasks
- Evidence-backed BLintDB identity reconciliation and diagnostic version comparison
- Pinned BLintDB/NSRL manifests, content-addressed ELF caching, and fail-closed rule locks
- ARM32 ICU and legacy FreeType paired-API version probes
- Conservative same-source ICU and e2fsprogs version inheritance

### Changed
- Externalized signature databases from Python code to JSON files
- Version number now uses single source from pyproject.toml
- BLintDB reference versions remain diagnostic candidates and never overwrite target versions
- NSRL package versions remain distribution metadata and are not treated as upstream releases

### Fixed
- Version number inconsistency across modules
- Dead code in deep_scanner._scan_one_section
- Bare exception-pass patterns replaced with logged exceptions
- CycloneDX round trips now preserve component properties and component-level CPE
- OSV scans of imported BOMs now retain exact/estimated resolution-state gates

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
