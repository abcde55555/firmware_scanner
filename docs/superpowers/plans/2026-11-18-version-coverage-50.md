# Firmware Version Coverage 50 Percent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Implement and measure a firmware scanner improvement against a 50% correct version coverage target on each of the two supplied firmware images.

**Architecture:** Keep package/build metadata, binary reference matching and finite version semantics as separately attributable evidence. Expand Android container contents and build a provenance-bearing reference pipeline, then compare fixed baseline observations with fresh scans. A target is a release gate, not permission to assign unproven versions.

**Tech Stack:** Existing Python scanner, pyelftools, Capstone, ZIP/ext4/EROFS readers; optional Ghidra reference experiment after environment inspection.

**Spec:** `docs/industry-version-recognition-strategy-2026-11-18.md`, approved by the user with the added 50% target.

**Observed status (2026-11-18):** Implementation and real scans are recorded in
`docs/version-coverage-50-results-2026-11-18.md`. The 50% coverage gate is **NOT_MET**
on both inputs. Implementation steps being checked below do not mean that the
user's coverage objective has passed.

Follow-up evidence and the next production scan are recorded in
`docs/version-coverage-next-results-2026-11-18.md`. The same frozen denominators
remain in force. A partial implementation commit does not complete this goal.

## Global Constraints

- Inputs: the original Allwinner image and `system.img` under `/home/kali/Desktop/work/project/vulnscan/`; preserve original hashes and extraction provenance.
- Use GPT-6 Luna for subagents. No firmware execution, library loading, external firmware upload, paid service or Git push.
- No Android release, ABI, SONAME, HAL/API version, compiler version or APK host version as an automatic library release fallback.
- Freeze the existing experiment record set (Allwinner 582 total / 312 native; system 1129 total / 774 native) and report matched baseline records alongside the expanded fresh output. Missing baseline records remain uncovered.
- For each image, separately report all-record and native coverage, independently verified correct versions, errors, ranges, unknown and unanalysed objects. New objects do not erase baseline unknowns. The 50% target is not met by raw nonempty fields alone.
- Keep raw firmware/reference binaries and large scan reports outside Git. Commit exact source/test/data/document paths after verification.

## Review Focus

- Shared binaries or stable functions across multiple releases must not produce an arbitrary exact version.
- Embedded component versions must not be assigned to the containing APK, ELF or APEX module.
- Truncated, corrupt, oversized or unsupported containers must produce scoped coverage warnings.
- Source tags, full-file hashes and reference features need real provenance; test API-shape fixtures are not an upstream build corpus.
- Compiler/architecture/configuration changes, forks and unseen versions need held-out checks and reproducible evidence.

## Task 1: Freeze and Evaluate the Coverage Contract

**Files:** Create `experiments/version_coverage/evaluate.py`, `tests/unit/test_version_coverage.py`, ignored `reports/version-coverage-50-20261118/baseline.json`.

**Interfaces:** `evaluate(baseline: list[dict], current: list[dict], verified: dict) -> dict`; stable observation matching uses source location and component identity, retaining all baseline observations.

- [x] Write failing tests for removed/reclassified baseline records, duplicate new records, wrong verified versions, unknown/range versions and separate native/all metrics.
- [x] Run the focused tests and inspect the expected assertion failures.
- [x] Implement evaluation and serialize input hashes, baseline commit, evidence types and target status.
- [x] Run focused tests and generate the frozen baseline for both images.

## Task 2: Expand Container and Metadata Coverage

**Files:** Create `src/firmware_scanner/android/apex_payload.py`, `src/firmware_scanner/android/archive_reader.py`, `src/firmware_scanner/extraction/archive_metadata.py`; modify `src/firmware_scanner/android/system_scanner.py` and `src/firmware_scanner/android/ext4_reader.py`; create focused payload/metadata/random-access tests.

**Interfaces:** `scan_apex_payload(apex_data: bytes, apex_path: str, inventory) -> ApexPayloadScan` with components, warnings and analysed-file count. `extract_archive_metadata(archive: zipfile.ZipFile, location: str) -> list[Component]` emits separately located dependency declarations.

- [x] Write failing tests using real small containers/filesystems and metadata positive/negative examples.
- [x] Implement bounded payload traversal and explicit metadata parsers; retain nested locations and skip warnings.
- [x] Implement `Ext4Reader.read_file_range(path, offset, size)` and a seekable read-only filesystem file adapter. Verify real filesystem holes, truncated extents and reading an archive beyond the previous 128 MiB prefix without loading the prefix.
- [x] Integrate in Android scanning, preserving module/host versions and component ownership.
- [x] Verify malformed containers, payload limits, ambiguous metadata and no host-version propagation.

## Task 3: Version Reference and Code Evidence Pipeline

**Files:** Create reference import/matching modules and provenance schema under `src/firmware_scanner/extraction/` and `src/firmware_scanner/data/`; add focused reference tests. Select final module boundaries after inspecting real unknown files and local tools; record the choice before implementation.

**Interfaces:** Reference records carry component, version or commit, upstream source, build configuration, artifact SHA-256 and discriminator evidence. Matches feed `BinaryInventory` as attributed claims with candidate ambiguity preserved.

- [x] Inspect actual unknown native families and attainable reference sources; capture findings and select the first corpus slice.
- [x] Write failing tests for source-backed exact matches, same bytes in multiple releases, corrupted records and unseen whole-file hashes. Common-code behavior is bounded by the measured multi-release BSim experiment, not a generic identity guarantee.
- [x] Implement the smallest reference pipeline supported by the selected corpus; integrate previously validated function paths only with regressions.
- [x] Measure candidate identity recovery and version discrimination independently; extend corpus/format support where real evidence identifies gaps. Result: 108 provenance records / 100 unique hashes; 0/9 real exact-hash matches; BSim narrows one real query to four tied releases without an exact version.

## Task 4: Real Scans, Review and Release Gate

**Files:** Add reproducible scan/verification runner under `experiments/version_coverage/`; create `docs/version-coverage-50-results-2026-11-18.md`; raw artifacts in ignored report directory.

- [x] Run the repository tests and all new semantic/reference controls; report any pre-existing failure explicitly. Final: 242 passed, 4 optional host-path skips; actual four image files separately tested, 0/4 FreeType matches.
- [x] Scan the two Android system partitions with the actual product scanner and CLI dedup, recording warnings, file hashes, code hashes, duration and SBOM linkage. Allwinner original container hash and extracted partition provenance are retained; other container partitions are outside this rerun's scope.
- [x] Compare fixed baseline and expanded output, independently check three new vendor-build claims, directly read back 1070 metadata declarations for 152 components, and test real unknown reference queries. Declaration agreement is not proof of implementation version.
- [ ] Establish independent ground truth for every output and a broad held-out compiler/architecture/vendor matrix. This has not been achieved and no overall accuracy is claimed.
- [x] Iterate on material remaining gaps. Mark 50% PASS only when observed correct-version evidence meets the frozen gate; otherwise report the measured gap and its cause without claiming completion. Observed result: NOT_MET for both inputs.
- [x] Review source/data changes, run `git diff --check`, commit validated work and provide concrete report paths. The commit records measured progress, not acceptance of the 50% objective.

## Task 5: Reconcile Provenance and Remaining Library Version APIs

- [x] Inspect both images for source/build metadata and license attribution. The system image contains a pinned manifest; the user has supplied no extra source or SBOM.
- [x] Download the corresponding public GAPPS ZIP, verify its published whole-archive SHA-256, and compare its `system.img` member to the user's file. Record image identity separately from per-library source provenance.
- [x] Reconcile actual SQLite/libevent declared values with pinned source metadata. Do not assume the version getter always reflects the upstream code release: the libevent Bionic header and configure metadata disagree within the same source commit.
- [x] Census direct library version APIs with original ELF hashes and explicit exclusions. Seven candidate records represent six distinct families; interface and module identifiers remain candidates.
- [x] Add the documented SQLite read-only release-object path with ELF32/ELF64, ownership and malformed-value controls. Independently read back five actual libraries; preserve the CryptoAuth path.
- [x] Audit libbpf's actual `v1.4` value against official implementation. It only reports major/minor; do not manufacture a patch value or count it as an exact release.
- [x] Finish the new real-scan comparison and review results; record the remaining gap in `docs/version-provenance-results-2026-11-19.md`. Fixed coverage remains 124/582 and 154/1129, native 22/312 and 26/774. Commit validated code and documentation; the 50% goal remains unmet.
