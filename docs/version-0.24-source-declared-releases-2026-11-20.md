# Version 0.24.0: SpeexDSP and libyuv source-declared releases

Date: 2026-11-20

Scanner: 0.24.0

Rule release: `builtin-2026.11.20.9`

## Result

Version 0.24.0 uses the exact Modern Android image source manifest to resolve
two remaining identity-known third-party components:

- SpeexDSP `1.2.1` from `external/speex` revision
  `6c44585f68f6f7f71c51ff1d56d9a5d0409d2d29`;
- libyuv `1883` from `external/libyuv` revision
  `741c38751c436f60c583110f617340b7f3322d94`.

SpeexDSP's release comes from `AC_INIT([speexdsp],[1.2.1])` in the pinned
`configure.ac`. libyuv's release comes from `LIBYUV_VERSION 1883` in the pinned
`include/libyuv/version.h`. Both mappings require an independently recognized
component identity and an exact image manifest revision; a source path is not
invented when the stripped binary does not retain one.

## Real firmware result

### Modern Android 16

| Metric | 0.23.0 | 0.24.0 |
|---|---:|---:|
| BOM components | 1,572 | **1,571** |
| All usable versions | 787/1,129, 69.71% | **788/1,129, 69.80%** |
| Native usable versions | 623/774, 80.49% | **624/774, 80.62%** |
| Exact / estimated | 227 / 560 | **228 / 560** |
| Fixed third-party OSS usable | 112/113, 99.12% | **113/114, 99.12%** |
| Unknown fixed third-party entries | 1 | **1** |

The one-row component decrease is expected: the exact libyuv source release and
one APEX parent-derived libyuv estimate now consolidate. The fixed cohort still
contains one taxonomy entry without a version, so no correctness is claimed for
that residual item.

### Allwinner Android 4.4.4

Allwinner has no matching source manifest, so 0.24.0 does not apply these new
source pins. Its verified 0.23.0 result remains:

| Metric | Result |
|---|---:|
| BOM components | 607 |
| All usable versions | 194/582, 33.33% |
| Native usable versions | 57/312, 18.27% |
| Third-party OSS taxonomy | 51 |
| Fixed third-party OSS usable | 30/32, 93.75% |

## Database use

| Database | Allwinner | Modern |
|---|---:|---:|
| BLintDB identity confirmation rate | 4/5, 80% | 9/9, 100% |
| BLintDB reference-version agreement rate | 0% | 0% |
| NSRL exact-file match rate | 0% | 0% |

The source-manifest path produces the new versions. Neither external database
supplies a version override.

## Version management

- Scanner: `0.24.0`
- Rule lock: `builtin-2026.11.20.9`
- Held-out suite: 18/20 usable, 15 exact, 3 estimated, zero wrong

## Validation

- Full suite: 833 passed, 39 skipped, 7 known warnings.
- Modern CycloneDX 1.6 SBOM: valid with zero schema errors.
- All 177 files in the Modern frozen source snapshot match their recorded
  hashes.
- Isolated wheel verification reports `0.24.0`, verifies rule lock
  `builtin-2026.11.20.9`, and resolves the real SpeexDSP and libyuv binaries.

## Artifacts

- `reports/version-coverage-getters-20261120/version-0.23.0-allwinner-final/`
- `reports/version-coverage-getters-20261120/version-0.24.0-modern-final/`
- `reports/version-coverage-getters-20261120/version-0.24.0-final-summary.json`
- `reports/heldout-debian-independent6-20261120-v024-final/heldout-report.json`
- `reports/version-coverage-getters-20261120/wheel-0.24.0-final/wheel-verification.json`
