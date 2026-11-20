# Version 0.35.0: source-scoped AOSP platform build provenance

Date: 2026-11-20

Scanner: 0.35.0

Rule release: `builtin-2026.11.20.13`

## Result

Version 0.35.0 extends the existing Android platform-build fallback from
framework archives to native libraries and executables only when their embedded
source-path evidence belongs exclusively to AOSP first-party projects.

Every accepted value remains:

- `estimated-android-platform-build`;
- scoped as `platform-build-not-upstream-release`;
- classified as `platform-first-party`;
- excluded from exact upstream OSV and VEX queries.

An image-matched source revision takes precedence over the platform fallback.
Third-party source paths, vendor-proprietary paths, mixed project evidence and
embedded components remain ineligible.

## Real firmware results

### Allwinner Android 4.4.4

| Metric | v0.34.0 | v0.35.0 | Change |
|---|---:|---:|---:|
| All usable | 197/582, 33.85% | **277/582, 47.59%** | **+80** |
| Native usable | 60/312, 19.23% | **123/312, 39.42%** | **+63** |
| Exact | 120 | **120** | 0 |
| Estimated | 77 | **157** | +80 |
| Unknown | 378 | **298** | -80 |
| Platform-first-party | 39/39 | **119/119** | +80 |
| Third-party OSS | 33/35 | **33/35** | 0 |

The scan completed in 100.498 seconds with 872,592 KiB peak RSS, 444 analysed
ELF files, 608 deduplicated BOM components and zero warnings. The fixed cohort's
matched denominator remains 575/582.

The 50% field-coverage target is not claimed: the measured result is 47.59%.
The remaining difference must come from stronger component evidence rather than
relaxing the third-party/vendor exclusion.

### Modern Android 16

| Metric | v0.34.0 | v0.35.0 | Change |
|---|---:|---:|---:|
| All usable | 791/1,129, 70.06% | **864/1,129, 76.53%** | **+73** |
| Native usable | 627/774, 81.01% | **652/774, 84.24%** | **+25** |
| Exact | 230 | **230** | 0 |
| Estimated | 561 | **634** | +73 |
| Unknown | 330 | **257** | -73 |
| Platform-first-party | 470/470 | **551/551** | +81 |
| Third-party OSS | 116/116 | **116/117** | 0 |

The scan completed in 539.663 seconds with 1,521,656 KiB peak RSS, 2,134
analysed ELF files, 34 APEX modules, 1,564 deduplicated BOM components and zero
warnings. Exact-version output remains unchanged.

## Resolution-state visibility

The evaluator now reports `estimated_by_state`, preventing platform builds,
parent packages and source revisions from being merged into an unexplained
"estimated" total.

Allwinner:

| Resolution state | Fixed all | Fixed native |
|---|---:|---:|
| exact observed | 120 | 24 |
| estimated platform build | 119 | 63 |
| estimated AOSP release | 9 | 9 |
| estimated AOSP source revision | 2 | 2 |
| estimated parent package | 16 | 16 |
| other estimate | 11 | 9 |

Modern:

| Resolution state | Fixed all | Fixed native |
|---|---:|---:|
| exact observed | 230 | 107 |
| estimated source revision | 446 | 446 |
| estimated platform build | 120 | 33 |
| estimated parent package | 46 | 44 |
| other estimate | 22 | 22 |

## Database use

Both pinned databases were exercised on the actual scans.

| Metric | Allwinner | Modern |
|---|---:|---:|
| ELF files queried | 430 | 1,789 |
| BLintDB candidate files | 5 | 21 |
| BLintDB identity confirmations | 4/5 | 9/9 |
| BLintDB reference-version agreements | 0/3 comparable | 0/8 comparable |
| BLintDB non-comparable reference versions | 1 | 1 |
| NSRL exact-file matches | 0/430 | 0/1,789 |
| Query errors | 0 | 0 |

The standalone database audit passed both database SHA-256 manifest checks,
schemas and production-query positive controls. BLintDB remains an identity and
diagnostic reference source. NSRL no-match is recorded as no exact-file evidence,
not as proof that a component is absent.

## Validation

- Full unit suite: 858 passed, 39 skipped, 7 known warnings.
- Real source snapshots: 177/177 files match; zero changed, missing or
  unexpected source files.
- CycloneDX 1.6: both SBOMs valid with zero schema errors.
- Fresh wheel: `firmware_scanner-0.35.0-py3-none-any.whl`, SHA-256
  `cf2386d4ae962f3b4ce043db74736a3afc5ff6967196175e7dc1fadb34792c20`.
- Isolated wheel verification reports module/distribution version `0.35.0`,
  verifies all 15 rule-pack files and recognizes a synthetic AOSP platform
  source component.
- Both real scans have zero warnings and produce machine-readable database
  provenance and per-file observations.

## Artifacts

- `reports/version-coverage-getters-20261120/version-0.35.0-allwinner-aosp-platform/`
- `reports/version-coverage-getters-20261120/version-0.35.0-modern-aosp-platform/`
- `reports/version-coverage-getters-20261120/version-0.35.0-database-audit.json`
- `reports/version-coverage-getters-20261120/version-0.35.0-final-summary.json`
- `reports/version-coverage-getters-20261120/wheel-0.35.0-final/wheel-verification.json`

## Boundaries

- Platform-build values identify the enclosing Android image build; they are not
  upstream library releases and must not drive exact upstream vulnerability
  queries.
- The Allwinner image still has no complete independent component-version
  oracle. Its 47.59% result is version-field coverage, not independently
  verified accuracy.
- NSRL contains no exact files from these two rebuilt images. The database stays
  enabled because exact-file matching remains valuable for other firmware.
- BLintDB reference-build versions frequently differ from target versions and
  remain diagnostic-only.
