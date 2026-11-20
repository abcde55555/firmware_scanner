# Version 0.28.0: typed Android source revisions and mDNSResponder

Date: 2026-11-20

Scanner: 0.28.0

Rule release: `builtin-2026.11.20.13`

## Result

Version 0.28.0 adds three usable Allwinner native-library identities without
turning a platform tree revision into an upstream semantic release.

| Component | Result | Evidence state |
|---|---|---|
| mDNSResponder / `libmdnssd.so` | `320.10.80` | `estimated-aosp-release` |
| TinyALSA / `libtinyalsa.so` | `git:252af255884d55166115e09c74280aeeeeeb5553` | `estimated-aosp-source-revision` |
| Sonivox / `libsonivox.so` | `git:ac263c249db97d9a1c19a1d5d5ca51e937411090` | `estimated-aosp-source-revision` |

mDNSResponder's version comes from `MVERS` in the official
`android-4.4.4_r2` project Makefile. TinyALSA and Sonivox do not publish a
semantic release in that AOSP tree, so the scanner records the Git tree objects
and labels them as source revisions. These values remain separate from registry
release versions and do not establish that the vendor binary has no local
patches.

The host `libmdnssd.so` and its canonical mDNSResponder contained component both
receive `320.10.80`. The frozen evaluator counts the host observation once.

## Real firmware result

### Allwinner Android 4.4.4

| Metric | Version 0.25.0 | Version 0.28.0 |
|---|---:|---:|
| BOM components | 607 | **607** |
| All usable version fields | 194/582, 33.33% | **197/582, 33.85%** |
| Native usable version fields | 57/312, 18.27% | **60/312, 19.23%** |
| Exact / estimated fixed rows | 120 / 74 | **120 / 77** |
| Unknown fixed rows | 381 | **378** |
| ELF files analyzed | 444 | 444 |
| Peak RSS | 852 MiB | **852 MiB** |

The all/native gains are three fixed native observations. The BOM component
count remains stable because the canonical contained components already
existed; they now carry typed provenance instead of an empty version state.

### Modern Android 16

The 0.28.0 rules match only Android 4.4.4 build `KTU84Q` and do not change the
authoritative 0.27.0 Modern result:

| Metric | Result |
|---|---:|
| BOM components | 1,569 |
| All usable version fields | 791/1,129, 70.06% |
| Native usable version fields | 627/774, 81.01% |
| Exact / estimated fixed rows | 230 / 561 |

## Database result

The Allwinner scan used both external databases:

| Metric | Result |
|---|---:|
| Unique ELF content records queried | 430 |
| BLintDB candidate files / rows | 5 / 5 |
| BLintDB identity confirmations | 4/5, 80% |
| BLintDB reference-version agreements | 0/3 comparable |
| BLintDB non-comparable target versions | 1 |
| NSRL exact-file matches | 0/430 |
| Query errors | 0 |
| Database-enabled scan time | 111.0 seconds |

Both database manifests passed size/SHA-256 verification. The NSRL exact-query
positive control and BLintDB import-hash schema check passed. The database
reference versions still do not overwrite firmware versions.

## Accuracy boundary

All 197 usable Allwinner fields remain `independently_verified=0` for the fixed
cohort because the supplied image has no independent component-version oracle.
The three additions are AOSP-source estimates, not target-embedded release
strings. They improve version evidence and component attribution while retaining
the vendor-patch limitation.

## Validation

- Full suite: 841 passed, 39 skipped, 7 known warnings.
- Allwinner CycloneDX 1.6 SBOM: valid with zero schema errors.
- All 177 files in the Allwinner frozen source snapshot match their recorded
  hashes.
- The isolated `0.28.0` wheel verifies mDNSResponder `320.10.80` and both source
  revisions on the real target ELFs; the wrong-build negative control resolves
  none of them.

## Artifacts

- `reports/version-coverage-getters-20261120/version-0.28.0-allwinner-db-final/`
- `reports/version-coverage-getters-20261120/version-0.28.0-final-summary.json`
- `reports/version-coverage-getters-20261120/wheel-0.28.0-final/`
