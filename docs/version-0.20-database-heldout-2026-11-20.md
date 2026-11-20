# Version 0.20.0: database evidence, held-out expansion and firmware results

Date: 2026-11-20  
Scanner: 0.20.0  
Rule release: `builtin-2026.11.20.5`

## Result

Version 0.20.0 adds source-grounded and binary-native version evidence without
allowing external reference versions to overwrite target versions.

The new fifth Debian suite was selected without overlap with the previous four
suites. Its untouched blind result and after-rules result are intentionally kept
separate:

| Metric | Blind run | After documented rules |
|---|---:|---:|
| Library identity | 20/20 | 20/20 |
| Exact versions | 0 | **5** |
| Estimated versions | 0 | **8** |
| Accepted adjacent estimates | 0 | **1** |
| Wrong claims | 0 | **0** |
| Usable version coverage | 0/20, 0% | **14/20, 70%** |
| Precision among version claims | not established | **14/14, 100%** |

The 0% blind result is the generalization baseline for the rules as they stood
before viewing the fifth suite. The 70% result is a tuned result and must not be
reported as a held-out score.

The tuned report records UTC start/finish time, Git HEAD, workspace cleanliness,
the rule release and SHA-256, and hashes for every version-extractor source
file. The earlier blind artifact predates this provenance field; it remains
auditable by its catalog, record hashes and report digest, but not by a recorded
source file manifest.

The exact additions are:

- NSS `3.121` from the defined `NSS_GetVersion` release pointer and a second
  NSS API;
- NSPR `4.38.2` from `PR_GetVersion` and the NSPR version-check API;
- Z3 `4.13.3` from the documented `Z3_get_version` output parameters, with
  `Z3_get_full_version` as corroboration;
- Poco `1.14.2` from the documented packed
  `Poco::Environment::libraryVersion` encoding;
- mimalloc `3.5.0` from the documented packed `mi_version` encoding.

The blkid getter is accepted only when the referenced version string is proven
to flow into its version output parameter. `libext2_blkid` is attributed to
e2fsprogs; a generic `libblkid` soname is attributed to util-linux.

Eight allowlisted full-release SONAMEs, including spdlog `1.15.3`, TinyXML2
`11.0.0` and cJSON `1.7.19`, are retained as estimates. Generic ABI-only
`.so.N` suffixes continue to be rejected.

## Firmware results

### Allwinner Android 4.4.4

Against the unchanged 582-item fixed cohort:

| Metric | Result |
|---|---:|
| All usable | **194/582, 33.33%** |
| Native usable | **57/312, 18.27%** |
| Exact | 120 |
| Estimated | 74 |
| Unknown | 381 |
| Independently verified calibration | 5 correct, 0 error |
| Full BOM components | 599 |
| Analysed ELF files | 444 |

The fixed-cohort improvement over 0.18.0 is one exact host version: LLVM
`3.1svn`. The embedded source-project additions remain outside the old
file-level denominator.

### Modern Android 16

| Metric | Result |
|---|---:|
| All usable | **786/1,129, 69.62%** |
| Native usable | **622/774, 80.36%** |
| Exact / estimated | **226 / 560** |
| Unknown | 335 |
| Components | 1,577 |
| Analysed ELF files | 2,134 |
| APEX modules | 34 |
| CycloneDX 1.6 | valid |

The fixed-cohort gain is one exact native library: `libLLVM_android.so`
`3.8.275480`. The blkid `1.46.6` result independently revalidates a version
already present through exact-build source provenance.

The Modern fixed cohort still has no independent version truth mapping; 69.62%
is usable-version field coverage, not an independently measured accuracy.

## Database use

### BLintDB

The pinned BLintDB v4 database contains 35 projects, 47 builds and 803 binaries
in the installed corpus. Its architecture coverage is AArch64.

The product now retains:

- the exact normalized imported-symbol-set hash;
- architecture-scoped import-hash candidates;
- match methods for each candidate;
- candidate versions only as reference-build evidence.

An import hash is accepted only when it has at least five imported symbols and
the candidate is unique, or the target soname independently matches the
candidate. A non-unique hash may remain diagnostic evidence but is never
resolved by lexical rank. Weak function fingerprints and common import hashes
are rejected; a probe that used broad mnemonic fingerprints produced false
matches from `libutils` to Poco and was not promoted into the product. Older
schemas without the required import-hash columns disable that query path
explicitly instead of generating per-file database errors.

On the 301 unresolved direct native paths from the Modern pre-final scan, the
conservative import-hash query returned zero sufficiently unique candidates.
For the complete Allwinner scan, it also returned zero import-hash candidates.
The existing symbol path still produced five candidate files and four confirmed
component identities.

### NSRL

The NSRL exact-file lookup remains enabled and its startup positive control
passes. It returned no exact hash matches for 430 Allwinner ELFs or the Modern
ELF inventory. A separate probe of 64 Modern APK files also returned zero exact
matches.

NSRL can confirm byte-identical files and package provenance when such files
exist. It cannot assign an upstream library version after a vendor rebuild, and
its distribution package version is never promoted to a component release.

## Version management

- The scanner version is `0.20.0`.
- The packaged JSON rule lock remains an independently verified artifact.
- Python-resident extractor semantics are versioned by the scanner release.
- The fifth blind and tuned reports have separate immutable output directories.
- Every accepted or rejected database change is represented in scan statistics
  and component-level provenance.

## Artifacts

- `reports/heldout-debian-independent5-20261120-blind-v2/heldout-report.json`
- `reports/heldout-debian-independent5-20261120-tuned-final/heldout-report.json`
- `reports/version-coverage-getters-20261120/blint-import-hash-census-20261120.json`
- `reports/version-coverage-getters-20261120/version-0.20.0-final-summary.json`
- `reports/version-coverage-getters-20261120/version-0.20.0-source-tree-match.json`
- `reports/version-coverage-getters-20261120/version-0.20.0-allwinner-final3/evaluation-fixed.json`
- `reports/version-coverage-getters-20261120/version-0.20.0-allwinner-final3/schema-validation.json`
- `reports/version-coverage-getters-20261120/version-0.20.0-modern-final3/evaluation-fixed.json`
- `reports/version-coverage-getters-20261120/version-0.20.0-modern-final3/schema-validation.json`
- `reports/version-coverage-getters-20261120/wheel-0.20.0-final2/wheel-verification.json`
