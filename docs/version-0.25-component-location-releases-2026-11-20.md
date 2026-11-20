# Version 0.25.0: component-location release matching

Date: 2026-11-20

Scanner: 0.25.0

Rule release: `builtin-2026.11.20.10`

## Result

Version 0.25.0 fixes AOSP release-rule matching for canonical contained
components. Filename-only rules previously used only the displayed component
name. A contained `Tremolo` identity therefore did not match a rule written for
`libvorbisidec.so`, even though the same component evidence pointed to that exact
host filename.

The matcher now considers:

- the component name;
- each real component location;
- the recorded evidence container.

The rule still requires an exact filename match where configured. This is not a
substring fallback.

## Firmware result

Allwinner `/lib/libvorbisidec.so` now exposes both:

- host component `libvorbisidec.so`: `0.07`;
- canonical contained component `Tremolo`: `0.07`.

Both are explicitly `estimated-aosp-release`; the value is derived from the
pinned `android-4.4.4_r2` source tag and can differ from vendor patches.

The frozen file-level denominator was already counting the host estimate, so the
headline remains:

| Metric | Result |
|---|---:|
| BOM components | 607 |
| All usable versions | 194/582, 33.33% |
| Native usable versions | 57/312, 18.27% |
| Fixed third-party OSS usable | 30/32, 93.75% |

The gain is component-level correctness: clients no longer see one versioned
file and one unresolved canonical Tremolo component in the same BOM.

Modern Android is unchanged from 0.24.0:

| Metric | Result |
|---|---:|
| All usable versions | 788/1,129, 69.80% |
| Native usable versions | 624/774, 80.62% |
| Exact / estimated | 228 / 560 |

## Database use

| Database | Allwinner | Modern |
|---|---:|---:|
| BLintDB identity confirmation rate | 4/5, 80% | 9/9, 100% |
| BLintDB reference-version agreement rate | 0% | 0% |
| NSRL exact-file match rate | 0% | 0% |

Neither database is used to overwrite the AOSP source estimate.

## Version management

- Scanner: `0.25.0`
- Rule lock: `builtin-2026.11.20.10`
- Held-out: 18/20 usable, 15 exact, 3 estimated, zero wrong

## Validation

- Full suite: 834 passed, 39 skipped, 7 known warnings.
- Allwinner CycloneDX 1.6 SBOM: valid with zero schema errors.
- All 177 files in the Allwinner frozen source snapshot match their recorded
  hashes.
- Isolated wheel verification reports `0.25.0`, verifies rule lock
  `builtin-2026.11.20.10`, and resolves both the real libvorbis host and its
  canonical Tremolo component to `0.07`.

## Artifacts

- `reports/version-coverage-getters-20261120/version-0.25.0-allwinner-final/`
- `reports/version-coverage-getters-20261120/version-0.24.0-modern-final/`
- `reports/version-coverage-getters-20261120/version-0.25.0-final-summary.json`
- `reports/heldout-debian-independent6-20261120-v025-final/heldout-report.json`
- `reports/version-coverage-getters-20261120/wheel-0.25.0-final/wheel-verification.json`
