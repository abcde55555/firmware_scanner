# Firmware Scanner 0.14.0 performance revalidation

Date: 2026-11-20

## Result

The optimization stack reduced the final Modern Android scan from **414.96
seconds to 267.58 seconds (35.5%)**. Intervening runs under host memory pressure
ranged up to 371.60 seconds, still 10.5% below the 0.10.0 baseline.

| Metric | 0.10.0 baseline | 0.12.0 stable run |
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
- 146/582 fixed-cohort usable versions at 0.12.0;
- 4 BLint identity confirmations and 3 comparable reference disagreements;
- zero NSRL matches.

The final Allwinner audit took **110.60 seconds**, down from 128.63 seconds
(14.0%). Modern timing still varies with host memory pressure because it
reflects larger APEX/APK reads.

The 0.13.0 audit added 39 scoped framework platform-build rows to each image:

- Modern fixed-cohort usable: **785/1,129**, exact unchanged at 225, native
  unchanged at 621/774;
- Allwinner fixed-cohort usable: **185/582**, exact unchanged at 119, native
  unchanged at 48/312;
- Modern measured **452.702 seconds** and 2,419,456 KiB peak RSS;
- Allwinner measured **71.949 seconds** and 872,592 KiB peak RSS.

The Modern 0.13.0 run overlapped elevated host load, so its 452.70 seconds is
not evidence of a code-path regression. Component counts, exact versions,
third-party query count, and database results were unchanged. A clean repeat
is needed before making a new performance claim.

Version 0.14.0 Modern runs ranged from **290.914 to 659.390 seconds** under
different host load; the final audited run measured **659.390 seconds**. The slow
run performed the same 1,789 unique ELF database lookups and produced the same
version buckets, so it is a host-load observation rather than a usable
performance regression sample. Allwinner runs ranged from **60.035 to 196.624
seconds**; the final audit measured **76.227 seconds**. Neither firmware timing
series is yet a controlled benchmark.

The final 0.14.0 content results are:

- Modern: 1,577 components, 785/1,129 usable, 225 exact, 621/774 native;
- Allwinner: 593 components, 190/582 usable, 119 exact, 53/312 native;
- Modern database result: 9 identity confirmations, 0 NSRL matches;
- Allwinner database result: 4 identity confirmations, 3 comparable BLint
  disagreements, 1 non-comparable version and 0 NSRL matches.

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
- IJG ABI, AMR-WB and AOSP release-project probes run only after bounded symbol
  checks and do not expand the general regex workload.

## Telemetry

Modern 0.12.0 recorded:

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

- Full Python suite: **725 passed, 39 skipped**.
- Modern fixed-cohort result is unchanged from 0.13.0 in every version bucket.
- Allwinner fixed-cohort result increased from 185/582 to **190/582**; exact
  remained **119** and estimated increased from 66 to **71**.
- The five-item source-verified Allwinner calibration subset is **5/5 correct**.
- CycloneDX 1.5/1.6 BOM and VEX schemas: **8/8 valid**.
- Isolated wheel install: module and metadata versions both `0.14.0`;
  all 15 locked data files verified with `builtin-2026.11.20.3`.

The roadmap target of sub-200-second Modern scans is not yet met. Remaining
profile hotspots are CBOM regex evaluation, APEX/APK decompression, Rust source
location resolution and the legacy EMBA string rules.
