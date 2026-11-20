# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.36.1] - 2026-11-20

### Added
- Add a source-verified calibration map for the 15 new Allwinner AOSP source
  revision and platform-build observations

### Validation
- The calibration evaluation reports 15 independently verified, 15 correct,
  zero errors and zero adjacent-only matches

## [0.36.0] - 2026-11-20

### Added
- Resolve third-party project revisions from a pinned official AOSP
  build-ID/tag manifest when an ELF has matching source-path evidence and an
  explicit component-to-project rule
- Recognize selected AOSP platform runtime, stagefright and native-helper
  component rules as system-partition platform build provenance

### Changed
- Keep AOSP build-ID source fallbacks distinct from image-matched source
  revisions and upstream releases
- Advance the packaged rule lock to `builtin-2026.11.20.14`

## [0.35.0] - 2026-11-20

### Added
- Attach an Android platform build baseline to ELF components only when every
  embedded source project is classified as AOSP first-party
- Separate framework and AOSP-source platform build counts in provenance stats
- Report estimated-version coverage by explicit resolution state

### Changed
- Prefer an image-matched source revision over a platform-build fallback
- Keep embedded third-party components, vendor source paths and mixed project
  evidence ineligible for platform-build attribution

## [0.34.0] - 2026-11-20

### Fixed
- Scope deep-ELF evidence to the component identity that produced it instead of
  attaching contained-component taxonomy and source facts to the host library
- Correctly classify OpenCORE-AMR and PVMP3 as confirmed third-party OSS while
  preserving their structured version abstentions

## [0.33.0] - 2026-11-20

### Added
- Record structured version abstentions for identified components that lack
  target release evidence
- Preserve identity, resolution state, evidence tier and the evidence required
  before an unknown can be promoted

### Changed
- Keep OpenCORE-AMR and PVMP3 versions unresolved because their binary
  observations expose codec/algorithm versions rather than component releases

## [0.32.0] - 2026-11-20

### Added
- Add `firmware-scanner database-audit` for standalone BLintDB/NSRL integrity,
  schema, provenance and production-query validation
- Add a real BLintDB symbol-to-project positive control that excludes mechanical
  symbols from the selected proof row

### Changed
- Record self-check durations and serialize audit success or failure as stable
  machine-readable JSON

## [0.31.0] - 2026-11-20

### Added
- Add an untouched 20-library Independent-8 Debian held-out suite
- Extract documented releases for GeoIP, HIDAPI and Unbound, plus the exported
  S-Lang version-string object

### Changed
- Publish Independent-8 at 2/20 exact before tuning and 6/20 exact with zero
  wrong claims after rule expansion

## [0.30.0] - 2026-11-20

### Added
- Resolve libsepol `3.11` only when its official `LIBSEPOL_3.11` ELF version
  definition and release-specific identity symbols are both present

### Changed
- Complete Independent-7 tuning at 10/20 exact, zero wrong and 10 explicit
  unknowns

## [0.29.0] - 2026-11-20

### Added
- Extract documented runtime release APIs for MPFR, MPC, PortAudio, FFADO and
  YAJL using straight-line ELF return-path analysis
- Add an untouched 20-library Debian held-out suite for future regression and
  tuning separation

### Fixed
- Normalize PortAudio's documented `19.7.0-devel` runtime banner to its
  release base `19.7.0` while retaining the original banner in evidence

## [0.28.0] - 2026-11-20

### Added
- Resolve Android 4.4.4 `mDNSResponder` `320.10.80` from the pinned AOSP
  release project
- Represent TinyALSA and Sonivox AOSP baseline pins as
  `estimated-aosp-source-revision` when the project declares no upstream
  semantic release

### Changed
- Advance the packaged rule lock to `builtin-2026.11.20.13`

## [0.27.0] - 2026-11-20

### Changed
- Defer BLintDB's cross-project low-information symbol filter until after a
  target symbol has matched a reference binary, avoiding a large ambiguity
  query for unrelated Android libraries while preserving candidate semantics

### Added
- Resolve Perfetto `heapprofd_client.so` and `heapprofd_client_api.so` to
  source-pinned release `49.0` only when matching embedded
  `external/perfetto` source-path evidence is present

## [0.26.0] - 2026-11-20

### Added
- Resolve BoringSSL `libcrypto.so` and `libssl.so` only to the exact
  `git:<revision>` when the component also contains matching full source-path
  evidence; names alone, unrelated source projects and incomplete source-path
  properties cannot match this rule

### Changed
- Advance the packaged rule lock to `builtin-2026.11.20.11`

## [0.25.0] - 2026-11-20

### Fixed
- Match Android source-release filename rules against the component's real
  locations and evidence containers, allowing contained canonical identities
  such as Tremolo to receive the same pinned AOSP release as their host file

### Changed
- Advance the packaged rule lock to `builtin-2026.11.20.10`

## [0.24.0] - 2026-11-20

### Added
- Pin the exact Modern Android `external/speex` revision to SpeexDSP `1.2.1`
- Map identified SpeexDSP and libyuv components to their exact source projects
  before applying source-declared release versions

### Changed
- Advance the packaged rule lock to `builtin-2026.11.20.9`

## [0.23.0] - 2026-11-20

### Fixed
- Stop treating OpenSSH compatibility globs such as `OpenSSH_7.4*` as release
  banners; only a bounded, non-wildcard OpenSSH version string can resolve the
  component
- Let contained components inherit matching host source paths and safely
  refine an exact base release with its exact source-pinned full version

### Changed
- Advance the packaged rule lock to `builtin-2026.11.20.8`

## [0.22.0] - 2026-11-20

### Added
- Recognize six versioned WebRTC audio-processing modules from documented
  getters, peer API symbol sets and embedded module release literals
- Attribute mDNSResponder, Sonivox, Tremolo and TinyALSA identities only when
  their specific filename and multi-symbol evidence agree
- Classify components with explicit upstream source evidence as third-party OSS
  without treating the EMBA rule repository as a component source
- Report BLintDB identity/reference-version rates and NSRL exact-file rates for
  operational database effectiveness

### Changed
- Advance the packaged rule lock to `builtin-2026.11.20.7`

## [0.21.0] - 2026-11-20

### Added
- Recognize documented runtime release APIs for libusb, libmodbus,
  libserialport, libiio, Mosquitto, rabbitmq-c, libpq, mbedTLS/libmbedcrypto,
  libqrencode, libgphoto2, libzmq, CZMQ and NNG
- Read output-parameter triplets, returned version structures and pointer
  tables only when the documented API and supporting identity symbols are both
  defined in the target ELF
- Distinguish libgpiod's explicitly named API version from its release and
  retain it only as interface-version evidence
- Add a sixth disjoint 20-library Debian black-box catalog

### Changed
- Separate source-package versions from linked-library releases for libftdi,
  MariaDB Connector/C and libserialport in the held-out truth model
- Advance the packaged rule lock to `builtin-2026.11.20.6`

## [0.20.0] - 2026-11-20

### Added
- Recognize Modern Android LLVM's numeric build banner only with the complete
  LLVM banner and public API marker set
- Recover the e2fsprogs or util-linux blkid release only when the referenced
  version string provably flows into the documented version output pointer
- Recognize documented NSS, NSPR, Z3, Poco and mimalloc release getters across
  pointer, output-parameter and packed-integer encodings
- Recover allowlisted full-release SONAMEs such as `libspdlog.so.1.15.3` as
  explicitly estimated filename evidence while continuing to reject generic
  ABI-only `.so.N` suffixes
- Query BLintDB's architecture-scoped import hash as a conservative identity
  candidate when at most ten reference binaries span at most three projects
- Add a fifth, disjoint 20-library Debian black-box catalog

### Changed
- Keep weak function fingerprints and non-unique import hashes as diagnostics
  rather than promoting them to component or version claims
- Disable import-hash lookup explicitly when an older BLintDB lacks the required
  columns
- Record BLintDB import-hash candidate counts and match methods in scan evidence
- Record the fifth suite as 0/20 on its untouched blind run and 14/20 after
  documented rule expansion, with zero wrong version claims

## [0.19.0] - 2026-11-20

### Added
- Preserve embedded `external/*` source-path evidence even when an image has no
  exact source manifest
- Attribute AOSP Android 4.4.4 projects with source declarations as separate
  contained components for Protobuf, V8, OpenCV, RE2, marisa-trie and Chromium
- Recognize LLVM's own development banner only with LLVM public API markers
- Recognize WebRTC VoiceEngine 4.1.0 only with its banner, source path and API
  markers

### Changed
- Keep wrapper libraries such as AppDataSearch and Google TTS unknown while
  reporting the embedded upstream project separately
- Advance the packaged rule lock to `builtin-2026.11.20.5`

## [0.18.0] - 2026-11-20

### Added
- Recognize GLib exported integer version triplets and FriBidi release-info
  pointer objects
- Combine ATK major/minor/micro getters and recognize libsrtp's prefixed
  release string
- Cross-check Lua's numeric ABI version with its official release banner
- Recover Berkeley DB output-parameter versions, the ABI-tagged modern
  Protobuf version boundary, and Jemalloc's API-corroborated release banner
- Add a fourth, previously disconnected Debian black-box catalog

### Changed
- Report blind and tuned results separately for the fourth catalog

## [0.17.0] - 2026-11-20

### Added
- Prove documented `check_version(NULL)` APIs that return a release string only
  on the zero-argument branch, including c-ares optional output APIs and
  x86-64, AArch64 and ARM paths
- Combine liburing major/minor integer getters without inventing a patch value
- Follow one local forwarding jump for libgpg-error's public version wrapper
- Recognize libevent 1.x release strings only when the documented identity
  banner and its exported base API are observed in the same ELF
- Persist scan-level database provenance with release, SHA-256, schema, source,
  license, architecture and integrity status
- Report NSRL total matches and truncation, with an exact-file self-check and
  component provenance IDs

### Changed
- Preserve BLintDB version mismatches as diagnostic evidence and continue to
  prevent reference builds from overwriting target versions

## [0.16.0] - 2026-11-20

### Added
- Recognize documented release getters for libfuse, libarchive, json-c,
  Jansson, MaxMind DB, liborc and libsodium
- Apply filename-checked AOSP release estimates for Allwinner libmtp,
  Tremolo/Vorbis and Chromium WebView only when both Android release and
  build ID match the pinned source tag

### Changed
- Attach explicit third-party taxonomy to AOSP release-derived estimates
- Advance the packaged rule lock to `builtin-2026.11.20.4`

## [0.15.0] - 2026-11-20

### Added
- Conservative probes for documented GNU, libcap, libdevmapper, file, GDBM,
  Little CMS and Readline version APIs
- A second 20-library Debian cold-start held-out catalog that is disjoint from
  the previous development and independent suites

### Changed
- Held-out usable coverage now includes only exact, correct estimated and
  explicitly accepted adjacent versions; incorrect estimates are not counted
  as usable

## [0.14.0] - 2026-11-20

### Added
- Record the libjpeg ABI-62 compatibility guard and use it with the exact AOSP
  Android 4.4.4 r2 source tag as an explicit release estimate
- Attribute the official 3GPP AMR-WB v6.0.0 decoder inside vendor audio
  containers
- Estimate AOSP 4.4.4 project releases from an exact build ID, confirmed binary
  identity and pinned AOSP source tags
- Add SpeexDSP and STLport binary identity rules
- Add a source-verified Allwinner calibration subset for version precision

### Changed
- Distinguish AOSP release-derived estimates from binary self-version evidence
  and exclude both from exact upstream CVE queries
- Advance the packaged rule lock to `builtin-2026.11.20.3`

### Fixed
- Keep libjpeg ABI 62 compatibility evidence separate from an IJG 6b
  implementation release and reject banner-bearing libjpeg-turbo samples
- Require filename corroboration for generic STLport and Jhead symbol sets
- Prevent AOSP release estimates from overriding existing version conflicts

## [0.13.0] - 2026-11-20

### Added
- Associate unresolved system or partition-root Android framework archives
  with the enclosing platform build baseline
- Preserve platform-build estimates in a dedicated resolution state that is
  excluded from upstream CVE queries

### Fixed
- Fail closed for every declared non-exact version resolution state before an
  upstream vulnerability query

## [0.12.0] - 2026-11-20

### Added
- Resolve contained APEX executables to their parent package version when the
  ancestor is unique
- Mark executable parent versions as `estimated-parent-package` and explicitly
  scope them away from upstream vulnerability queries

## [0.11.0] - 2026-11-20

### Changed
- Cache CBOM/AIBOM results for byte-identical ELF contents
- Use a single broad prefilter before detailed CBOM/AIBOM regex evaluation
- Parse ELF metadata and defined symbols in one pass
- Use a bounded raw ELF symbol reader for BLintDB instead of reparsing with
  pyelftools
- Keep large binary reference matching on raw bytes instead of materializing a
  decoded Python text copy

### Added
- Binary asset cache and regex-pass telemetry in scan analysis statistics

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
