# Firmware Scanner 0.12.0 performance revalidation

Date: 2026-11-20

## Result

The optimization stack reduced the final Modern Android scan from **414.96
seconds to 267.58 seconds (35.5%)**. Intervening runs under host memory pressure
ranged up to 371.60 seconds, still 10.5% below the 0.10.0 baseline.

| Metric | 0.10.0 baseline | 0.11.0 |
|---|---:|---:|
| Modern scan time, final audit | 414.959 s | **267.581 s** |
| Modern peak RSS | 2,428,852 KiB | 2,419,652 KiB |
| Components | 1,574 | 1,576 |
| Fixed-cohort usable | 744/1,129 | 746/1,129 |
| Fixed-cohort exact | 225 | 225 |
| BLint identity confirmations | 9 | 9 |
| NSRL exact matches | 0 | 0 |

Allwinner remained behaviorally identical:

- 591 components;
- 674 version-evidence claims;
- 146/582 fixed-cohort usable versions;
- 4 BLint identity confirmations and 3 comparable reference disagreements;
- zero NSRL matches.

The final Allwinner audit took **110.60 seconds**, down from 128.63 seconds
(14.0%). Modern timing still varies with host memory pressure because it
reflects larger APEX/APK reads.

## Changes

- CBOM and AIBOM use a two-stage scanner: one broad literal prefilter followed
  by detailed regex evaluation only for candidates present in the binary.
- CBOM and AIBOM scan the first 2 MiB by default. On 1,296 unique direct ELF
  files from the Modern image, this window produced exactly the same CBOM and
  AIBOM findings as the previous 8 MiB and 4 MiB windows.
- Byte-identical ELF contents reuse CBOM/AIBOM results. Modern scans recorded
  191 asset-cache hits over 1,429 unique contents.
- ELF metadata and defined symbols are parsed in one pyelftools pass.
- Defined symbol sets require global/weak function, object or notype symbols;
  local implementation symbols cannot trigger library identity.
- Binary reference matching operates on raw bytes instead of decoding the
  complete binary into Python text.
- BLintDB uses a bounded raw ELF symbol parser and no longer reparses each
  target with pyelftools.

## Telemetry

Modern 0.11.0 recorded:

- content-cache hits: 345;
- binary asset-cache hits: 191;
- unique binary asset scans: 1,429;
- CBOM prefilter plus detail passes: 2,561;
- AIBOM prefilter plus detail passes: 1,436;
- CBOM-scanned bytes: 350,063,420;
- AIBOM-scanned bytes: 350,063,420.

These metrics are published in `analysis_stats` and therefore accompany the
SBOM metadata.

## Verification

- Full Python suite: **697 passed, 39 skipped** before final artifact build.
- Native-library identity and version sets: **zero delta** against 0.11.0.
- Fixed-cohort result: **746/1,129**, with two additional parent-package
  estimates and no exact-version change.
- BLintDB and NSRL result dictionaries: **identical**.
- CycloneDX 1.5/1.6 BOM and VEX schemas: **8/8 valid**.
- Isolated wheel install: module and metadata versions both `0.11.0`.

The roadmap target of sub-200-second Modern scans is not yet met. Remaining
profile hotspots are CBOM regex evaluation, APEX/APK decompression, Rust source
location resolution and the legacy EMBA string rules.
