# Version 0.22.0: target-derived components, WebRTC modules and database metrics

Date: 2026-11-20

Scanner: 0.22.0

Rule release: `builtin-2026.11.20.7`

## Result

Version 0.22.0 changes the expansion strategy from an unrelated Debian library
catalog to components that actually occur in the supplied firmware. The
Allwinner image gains eight canonical component records and six exact WebRTC
module releases. Existing fixed-cohort version coverage is unchanged, so the
new components do not artificially raise the historical percentage.

The project also narrows `unknown` taxonomy by classifying only components
whose claim carries explicit upstream source evidence. The EMBA rule repository
URL is deliberately not treated as evidence that the target component itself is
open source.

## Component and version gains

The selected WebRTC modules are:

| Component | Version | Evidence |
|---|---:|---|
| WebRTC SPL | 1.2.0 | documented getter, peer symbols and literal |
| WebRTC VAD | 1.2.0 | documented getter, peer symbols and literal |
| WebRTC NS | 3.1.0 | documented getter, peer symbols and literal |
| WebRTC AEC | 2.5.0 | documented getter, peer symbols and literal |
| WebRTC AGC | 1.7.0 | documented getter, peer symbols and literal |
| WebRTC AECM | 1.2.0 | documented getter, peer symbols and literal |

They are contained in
`/lib/libwebrtc_audio_preprocessing.so`. Acceptance requires the module getter,
its peer API symbol set and exact module release literal in the same stripped
ELF. The binary also contains WebRTC source paths.

Four further identities were added without inventing versions:

- mDNSResponder in `/lib/libmdnssd.so`;
- Sonivox in `/lib/libsonivox.so`;
- Tremolo in `/lib/libvorbisidec.so`;
- TinyALSA in `/lib/libtinyalsa.so`.

Each requires an exact filename hint and its multi-symbol API set. The
mDNSResponder banner contains a build date and the placeholder
`mDNSResponderVersion`, not a substituted release, so it remains unknown.

## Firmware results

### Allwinner Android 4.4.4

| Metric | 0.21.0 | 0.22.0 |
|---|---:|---:|
| BOM components | 599 | **607** |
| Third-party OSS taxonomy | 18 | **51** |
| Unknown taxonomy | 542 | **517** |
| New canonical records versus 0.21.0 | — | **8** |

The original 582-item frozen cohort remains unchanged:

| Fixed cohort | Result |
|---|---:|
| All usable versions | 194/582, 33.33% |
| Native usable versions | 57/312, 18.27% |
| Third-party OSS identified in frozen fit | 32 |
| Third-party OSS usable versions | 30/32, 93.75% |
| Independently checked Allwinner subset | 5/5 correct |

The six WebRTC releases are new component-level evidence and are not counted in
the old file-level denominator. This distinction prevents component discovery
from being presented as retroactive version recall.

### Modern Android 16

| Metric | 0.21.0 | 0.22.0 |
|---|---:|---:|
| BOM components | 1,577 | 1,577 |
| Third-party OSS taxonomy | 245 | **272** |
| Unknown taxonomy | 840 | **813** |
| Fixed third-party OSS entries | 99 | **112** |
| Fixed third-party OSS usable | 99/99 | **110/112, 98.21%** |

The original fixed cohort remains:

| Fixed cohort | Result |
|---|---:|
| All usable versions | 786/1,129, 69.62% |
| Native usable versions | 622/774, 80.36% |
| Exact / estimated versions | 226 / 560 |

Modern still lacks a complete independent version oracle. Its percentages are
version-field coverage, not whole-image accuracy.

## Database use

Both databases remain active in the product scan and are checked before use.

| Database | Allwinner | Modern |
|---|---:|---:|
| BLintDB queried files | 430 | 1,789 |
| BLintDB identity confirmations / reviewed | 4/5, 80% | 9/9, 100% |
| BLintDB reference-version agreements | 0 | 0 |
| BLintDB reference-version mismatches | 3 | 8 |
| NSRL queried files | 430 | 1,789 |
| NSRL exact-file matches | 0 | 0 |

The product now reports these effectiveness rates directly. BLintDB is useful
for independent identity confirmation, not for overwriting a target version.
NSRL can confirm byte-identical files but does not resolve these vendor-rebuilt
files. Neither database contributes a direct version claim in this run.

## Version management

- Scanner version: `0.22.0`.
- Rule release: `builtin-2026.11.20.7`.
- JSON reference catalog: 109 rules.
- All rules remain in the product repository because rule changes are tested
  against the same extractor APIs and released with the same source revision.
- The SHA-256 lock covers every packaged JSON rule and provenance file.
- Python-resident extraction semantics are tied to the scanner release and
  recorded in held-out and firmware scan provenance.

If the rule catalog later develops an independent publication cadence, it can
still be split into a versioned pack repository; the current lock format already
provides the required compatibility boundary.

## Validation

- Both final SBOMs are valid CycloneDX 1.6 with zero schema errors.
- All 177 files in each frozen source snapshot match their recorded hashes.
- The sixth Debian suite remains 18/20 usable, 15 exact, 3 estimated, 0 wrong.
- Full test suite: 827 passed, 39 skipped, 7 known warnings.
- The isolated wheel reports scanner and distribution version `0.22.0`,
  verifies rule lock `builtin-2026.11.20.7`, and recovers all six WebRTC module
  versions from the real Allwinner binary.
- The Allwinner scan has zero warnings and zero database lookup errors.
- The Modern scan has zero warnings and zero database lookup errors.

## Next work

The next target-derived candidates are the remaining identity-confirmed,
version-unknown components in Allwinner, followed by a customer-shaped
ARM32/AArch64 blind corpus. Priority remains:

1. package or language metadata;
2. documented getter/version object;
3. exact source path and revision evidence;
4. exact/reference hash;
5. bounded Version-Delta only after the cheaper evidence fails.

## Artifacts

- `reports/version-coverage-getters-20261120/version-0.22.0-allwinner-final2/`
- `reports/version-coverage-getters-20261120/version-0.22.0-modern-final/`
- `reports/version-coverage-getters-20261120/version-0.22.0-final-summary.json`
- `reports/heldout-debian-independent6-20261120-v022-final/heldout-report.json`
- `work/version-target-census-20261120/report.md`
