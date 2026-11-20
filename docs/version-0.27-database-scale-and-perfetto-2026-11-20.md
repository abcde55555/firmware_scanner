# Version 0.27.0: database-scale BLintDB and Perfetto releases

Date: 2026-11-20

Scanner: 0.27.0

Rule release: `builtin-2026.11.20.12`

## Result

Version 0.27.0 completes a database-enabled Modern Android scan while keeping
the database versions distinct from target versions.

- BLintDB and NSRL both passed manifest size/SHA-256 verification.
- NSRL's exact-file positive control passed.
- BLintDB's import-hash schema check passed.
- 1,789 unique ELF content records were queried in each database without query
  errors.
- CycloneDX 1.6 output contains the database release, digest, schema,
  license/channel metadata, and self-check records.

The scan also adds exact Perfetto release `49.0` for `heapprofd_client.so` and
`heapprofd_client_api.so`. The rule requires full embedded
`external/perfetto` source-path evidence and an image-hash-matched source
manifest revision. It does not infer the release from the filename alone.

## Database evidence

| Metric | Result |
|---|---:|
| BLintDB queried ELF content records | 1,789 |
| BLintDB candidate files | 21 |
| BLintDB candidate rows | 23 |
| BLintDB reviewed components | 9 |
| BLintDB identity confirmations | 9/9, 100% |
| BLintDB reference-version agreements | 0/8 comparable |
| BLintDB reference-version mismatches | 8 |
| BLintDB non-comparable target versions | 1 |
| NSRL exact-file matches | 0/1,789 |
| Database query errors | 0 |

BLintDB's reference versions are not used to overwrite firmware versions. The
eight mismatches confirm why that rule matters: a reference build version can
differ from the target while still providing useful component identity
evidence. NSRL similarly supplies exact-file provenance only; a no-match is not
negative proof that a component is absent.

The previous BLintDB query path filtered every target symbol for cross-project
ambiguity before knowing whether any reference binary matched. The new path
finds matching reference binaries first and applies the ambiguity filter only
to their matched symbols. Results retain the same candidate rules and semantic
output.

On the same local 13-file BLintDB sample, the observed run time changed from
19.12 seconds to 10.90 seconds with a cold SQLite page cache and a 0.078-second
median across two subsequent warm runs. This is an indicative local benchmark,
not a throughput certification. The decisive evidence is that a complete
database-enabled Modern scan finished in 507.2 seconds without query errors.

## Real firmware result

### Modern Android 16

| Metric | Version 0.26.0 | Version 0.27.0 |
|---|---:|---:|
| BOM components | 1,569 | **1,569** |
| All usable version fields | 789/1,129, 69.88% | **791/1,129, 70.06%** |
| Native usable version fields | 625/774, 80.75% | **627/774, 81.01%** |
| Exact / estimated fixed rows | 228 / 561 | **230 / 561** |
| Unknown fixed rows | 332 | **330** |
| ELF files analyzed | 2,134 | 2,134 |
| Unique ELF content queried by databases | 0 | **1,789** |
| Peak RSS | 1,979 MiB | **1,928 MiB** |

The 0.27.0 taxonomy currently classifies 116 selected third-party OSS rows:
101 exact and 15 estimated. The denominator changed as new source-project
evidence was attached, so this is not a like-for-like component-recall gain.
The fixed all/native rows above retain the frozen denominator.

The two exact additions are Perfetto `heapprofd_client.so` and
`heapprofd_client_api.so`, both `49.0`. BoringSSL `libcrypto.so` and
`libssl.so` retain their source-revision state.

### Allwinner Android 4.4.4

No 0.27.0 source rule applies to Allwinner without an image-matched source
manifest. Its verified 0.25.0 result remains:

| Metric | Result |
|---|---:|
| BOM components | 607 |
| All usable version fields | 194/582, 33.33% |
| Native usable version fields | 57/312, 18.27% |

The next Allwinner candidates are TinyALSA, Sonivox, mDNSResponder,
OpenCORE-AMR and PVMP3 decoder. Their component identities are known, but the
current binaries do not expose a trustworthy release string. They require
project-specific binary deltas against independently selected upstream tags;
an AOSP framework path must not be mistaken for the decoder library version.

## Accuracy boundary

All 791 usable fixed rows remain `independently_verified=0` because these two
images have no independent version oracle. Exact and estimated are evidence
states, not a measured whole-firmware accuracy rate. The database scan improves
evidence quality and component identity confidence; it does not convert BLintDB
or NSRL reference versions into target versions.

## Validation

- Full suite: 838 passed, 39 skipped, 7 known warnings.
- Modern CycloneDX 1.6 SBOM: valid with zero schema errors.
- All 177 files in the Modern frozen source snapshot match their recorded hashes.
- Isolated wheel verification reports version `0.27.0`, verifies rule lock
  `builtin-2026.11.20.12`, resolves BoringSSL and both Perfetto binaries, and
  rejects the Perfetto negative control.

## Artifacts

- `reports/version-coverage-getters-20261120/version-0.27.0-modern-db-final2/`
- `reports/version-coverage-getters-20261120/version-0.27.0-database-benchmark.json`
- `reports/version-coverage-getters-20261120/wheel-0.27.0-final/`
