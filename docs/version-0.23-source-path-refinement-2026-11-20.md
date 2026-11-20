# Version 0.23.0: OpenSSH boundary repair and source-revision refinement

Date: 2026-11-20

Scanner: 0.23.0

Rule release: `builtin-2026.11.20.8`

## Result

Version 0.23.0 fixes two sources of component/version error:

1. OpenSSH compatibility globs such as `OpenSSH_7.4*` were incorrectly treated
   as historical release banners. They are now rejected; only a bounded,
   non-wildcard version string is accepted.
2. Embedded components now inherit source-path evidence from their containing
   ELF only when they have an explicit `contains-evidence-for` relationship.
   A source revision can complete a proven base release, for example
   `OpenSSH_9.0` plus the exact `external/openssh` revision declaring `9.0p1`.

The source-revision refinement is deliberately asymmetric. A pin may only
extend an existing exact version when the pinned value starts with that version
and adds a release/portable suffix. It cannot replace an unrelated exact
version. Components without a matching source project continue to abstain.

## Real firmware result

### Modern Android 16

| Metric | 0.22.0 | 0.23.0 |
|---|---:|---:|
| BOM components | 1,577 | **1,572** |
| All usable versions | 786/1,129, 69.62% | **787/1,129, 69.71%** |
| Native usable versions | 622/774, 80.36% | **623/774, 80.49%** |
| Exact / estimated | 226 / 560 | **227 / 560** |
| Fixed third-party OSS usable | 110/112, 98.21% | **112/113, 99.12%** |
| Unknown fixed third-party entries | 2 | **1** |

Resolved components:

- OpenSSH: `9.0p1`
- libevent: `2.1.12-stable`

The five-row component decrease is deliberate consolidation. Four `libevent`
records carrying APEX/APK parent package identifiers (`360499999`,
`1.68.391954`, `7.9.20231101.4`, and `14.1.0.644281411 leanback`) were not
libevent releases. Their source-path evidence resolves to the same exact AOSP
libevent revision, so they collapse to one component. One generic zlib filename
component also consolidates with the exact AOSP zlib `1.3.0.1-motley` release.

The fixed cohort gains one exact row because the evaluator retains the original
cohort and does not reward removal of extra erroneous rows beyond the fixed
mapping. No old fixed row disappears.

### Allwinner Android 4.4.4

The final 0.23.0 scan is unchanged from 0.22.0. The changed OpenSSH boundary and
source-revision path do not match this image.

| Metric | Result |
|---|---:|
| BOM components | 607 |
| All usable versions | 194/582, 33.33% |
| Native usable versions | 57/312, 18.27% |
| Third-party OSS taxonomy | 51 |
| Fixed third-party OSS usable | 30/32, 93.75% |

## Database use

Database results are unchanged:

| Database | Allwinner | Modern |
|---|---:|---:|
| BLintDB identity confirmation rate | 4/5, 80% | 9/9, 100% |
| BLintDB reference-version agreement rate | 0% | 0% |
| NSRL exact-file match rate | 0% | 0% |

BLintDB continues to contribute identity evidence only. NSRL remains useful for
byte-identical files but has no hit on these rebuilt images. Neither database
overwrites a target version.

## Version management

- Scanner: `0.23.0`
- Rule lock: `builtin-2026.11.20.8`
- Binary reference catalog: 109 rules
- New source-project rules: canonical `OpenSSH` and `libevent` identities
- The held-out suite remains 18/20 usable, 15 exact, 3 estimated, zero wrong

## Validation

- Full suite: 831 passed, 39 skipped, 7 known warnings.
- Both final SBOMs are valid CycloneDX 1.6 with zero schema errors.
- All 177 files in each frozen source snapshot match their recorded hashes.
- The isolated wheel reports module and distribution version `0.23.0`,
  verifies rule lock `builtin-2026.11.20.8`, and resolves OpenSSH `9.0p1` and
  libevent `2.1.12-stable` from the real Modern binaries.

## Artifacts

- `reports/version-coverage-getters-20261120/version-0.23.0-allwinner-final/`
- `reports/version-coverage-getters-20261120/version-0.23.0-modern-final2/`
- `reports/version-coverage-getters-20261120/version-0.23.0-final-summary.json`
- `reports/heldout-debian-independent6-20261120-v023-final2/heldout-report.json`
- `reports/version-coverage-getters-20261120/wheel-0.23.0-final/wheel-verification.json`
- `work/version-target-census-20261120/report.md`
