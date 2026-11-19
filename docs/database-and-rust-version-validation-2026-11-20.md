# BLintDB, NSRL and Rust crate version validation

Date: 2026-11-20
Scanner: 0.12.0

## Database releases

| Database | Release | Raw size | SHA-256 |
|---|---|---:|---|
| BLintDB | v4 | 5,660,250,112 | `93bcb321c5c3bc8933cdad5c63454312838750f88053ed0223fd4c2e0da5112e` |
| NIST NSRL Android minimal | 2026.03.1 | 39,967,412,224 | `2f3203615d96e6079fda9a65d39cad4b2a9100fa8f7e6f54a3c74cc5eee1d315` |

The full scans verify database size, manifest, SHA-256 and schema. A separate
repeat scan may use `--skip-database-integrity` only after the pinned database
has already passed integrity verification.

Reproduce an Android scan with both databases:

```bash
PYTHONPATH=src python3 experiments/version_coverage/run_scan.py \
  /home/kali/Desktop/work/project/vulnscan/system.img \
  reports/version-coverage-getters-20261120/modern-pins-db \
  --blintdb reports/existing-databases-20261119/blint.db \
  --nsrl-db reports/existing-databases-20261119/nsrl/android_minimal.db \
  --skip-database-integrity
```

## Modern Android results

| Metric | Result |
|---|---:|
| Unique ELF contents | 1,789 |
| BLintDB queried | 1,789 |
| BLintDB candidate files | 21 |
| BLintDB candidate rows | 23 |
| BLintDB identity-confirmed components | 9 |
| BLintDB exact target/reference disagreements | 8 |
| BLintDB non-comparable parent versions | 1 |
| NSRL queried files | 1,789 |
| NSRL exact file matches | 0 |
| Database errors | 0 |

Reference-build disagreements are retained as diagnostics. They do not
overwrite a target version. Parent-package versions are marked
`not-comparable` rather than being reported as BLint mismatches.

The DB-enriched BOM classifies 100 fixed-cohort records as third-party OSS:
87 exact and 13 explicitly estimated. This slice is evidence-biased and does
not measure total third-party recall.

## Allwinner results

| Metric | Result |
|---|---:|
| Unique ELF contents | 430 |
| BLintDB candidate files | 5 |
| BLintDB identity-confirmed components | 4 |
| BLintDB exact target/reference disagreements | 3 |
| NSRL queried files | 430 |
| NSRL exact file matches | 0 |
| Database errors | 0 |

BLint confirmed four third-party identities and retained three comparable
target/reference disagreements, but did not create additional upstream version
claims. NSRL exact hashes also produced no match. Both databases remain
installed and enabled because this result is target-specific.

## Rust crate exact versions

The image-matched source manifest pins:

`external/rust/android-crates-io@c991cad10330f37e93d82926bd6dae7f4f6647f6`

That repository contains many crates, so its revision alone is not a crate
release. A separate crate-level pin file maps each crate to:

- its monorepo subdirectory;
- the revision-bound `Cargo.toml`;
- the Cargo package name and package version;
- the scanner component alias used in the firmware.

The scanner requires the manifest project path and filename/alias to agree.
When an embedded source path is available it is retained with its file offset.
Dependency source paths cannot override the component's own crate; tests cover
`nix` linked with `libc`, `rand_chacha` linked with `ppv-lite86`, and
`libbpf-rs` linked with `vsprintf`.

Results:

| Metric | Before crate pins | After crate pins |
|---|---:|---:|
| Fixed-cohort exact versions | 177 | **225** |
| Fixed-cohort estimated versions | 567 | **519** |
| Fixed-cohort usable versions | 744 | **744** |
| Native exact versions | 54 | **102** |
| Native estimated versions | 567 | **519** |
| Native usable versions | 621 | **621** |

43 Rust crates now have `pkg:cargo/...@version` PURLs. One
`libvsprintf_wrapper` component remains on the monorepo source-revision
estimate because assigning it the `vsprintf` crate release would misstate what
the wrapper binary is.

Perfetto `49.0`, fsverity-utils `1.6` and Piex `0.27` are also supported by
revision-bound source declarations.

## Vulnerability validation

| Image | Scannable components | Vulnerability records | Critical | High |
|---|---:|---:|---:|---:|
| Modern Android | 266 | 470 | 69 | 212 |
| Allwinner | 36 | 1,500 | 159 | 515 |

The Rust PURL change makes 43 additional components queryable. OSV returned
four records for three crates:

- `anyhow 1.0.97`: `RUSTSEC-2026-0190`;
- `protobuf 3.2.0`: `CVE-2025-53605`;
- `rand 0.8.5`: `GHSA-cq8v-f236-94qc` and `RUSTSEC-2026-0097`.

These are vulnerability candidates. The product still needs patch-backport,
reachability and vendor-status analysis before classifying exploitability.

## Artifacts

- `reports/version-coverage-getters-20261120/final-modern/system_analysis.json`
- `reports/version-coverage-getters-20261120/final-modern/system_cyclonedx_1.6.json`
- `reports/version-coverage-getters-20261120/final-modern/system_cyclonedx_1.6_vuln.json`
- `reports/version-coverage-getters-20261120/final-modern/system_cyclonedx_1.6_cyclonedx_1.6_vex.json`
- `reports/version-coverage-getters-20261120/final-allwinner/system_analysis.json`
- `reports/version-coverage-getters-20261120/final-allwinner/allwinner-system_cyclonedx_1.6.json`
- `reports/version-coverage-getters-20261120/final-allwinner/allwinner-system_cyclonedx_1.6_vuln.json`
- `reports/version-coverage-getters-20261120/schema-validation.json`
