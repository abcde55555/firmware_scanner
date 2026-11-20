# Existing databases and Android provenance experiment

Date: 2026-11-19

## Result

The frozen modern-system cohort now has a populated version for **655 of 1,129
records (58.02%)**. Native libraries reach **532 of 774 records (68.73%)**.
This satisfies the requested populated-field coverage threshold.

This is not an independently verified 58% accuracy claim:

- 152 fixed records have an exact version field.
- 503 records use an explicitly labelled estimate.
- The frozen cohort has no broad, independent ground truth.
- Estimated source revisions and parent package versions are excluded from
  upstream CPE generation and OSV version queries.

The live scan processed 3,596 raw findings into 1,611 deduplicated components in
350 seconds. Its exact input is the 2,309,611,520-byte `system.img` with SHA-256
`ff9025e0f73e6784f57ef9d3dd5b90ce648d524dd4c20d8cfe5dc2b66ccc4ce4`.

| Cohort | Populated version | Denominator | Coverage |
|---|---:|---:|---:|
| All fixed records | 655 | 1,129 | 58.02% |
| Fixed native libraries | 532 | 774 | 68.73% |

The original Allwinner image has no equivalent source manifest in the supplied
materials. Its measured result remains **120/582 (20.62%)** and **23/312
(7.37%) native**. It was not filled with the modern image's revisions or
APEX versions.

## BOM artifacts

Both generated BOM files contain all 1,611 deduplicated findings:

- `system_cyclonedx_1.6.json` validates against the official CycloneDX 1.6
  schema. It has 1,085 non-empty versions and 526 empty versions.
- `system_sbom.json` validates against the official CycloneDX 1.5 schema.
  Version 1.5 compatibility mode writes `"unknown"` for the 526 missing
  versions so consumers do not silently drop those components.

The 1.5 representation is therefore not a claim of 1,611 discovered versions.
The actual populated count in the strict 1.6 artifact is 1,085 of 1,611.

## Vulnerability candidates

An OSV scan of the CycloneDX BOM selected 268 components with queryable
upstream versions. It returned 555 component-vulnerability records, collapsing
to 312 unique vulnerability IDs and 305 unique CVE IDs. The raw severity split
is 76 critical, 239 high, 164 medium, 19 low and 57 unknown.

These are vulnerability candidates, not 555 confirmed exploitable issues:

- only 24 component/version records contain the findings;
- several OSV records are distribution advisories rather than upstream release
  definitions;
- withdrawn/rejected CVE records were observed in the raw result;
- no reachability or exploitation test was performed.

Two findings are marked CISA KEV for `dnsmasq 2.51`:
`CVE-2020-25681` and `CVE-2020-25682`. They should be investigated first,
starting with `/system/bin/dnsmasq`.

The VEX generator now merges duplicate vulnerability IDs and records every
affected `bom-ref`. Both generated VEX files pass their corresponding official
CycloneDX 1.5 and 1.6 schemas.

## What produced the increase

The production scan now applies four provenance layers:

1. **Image-local NOTICE attribution.** `NOTICE.xml.gz` maps built files to
   AOSP source-project labels. A label is accepted only when the source
   manifest contains one revision for that project.
2. **Hash-pinned source manifests.** The Waydroid source manifest pack is
   selected only when the calculated image SHA-256 matches exactly. An
   explicitly supplied manifest follows the same rule.
3. **Narrow source-project rules.** Standard `android.hardware.*` and
   `android.frameworks.*` HAL namespaces map to their generating AOSP projects.
   Ambiguous namespaces such as `android.system.*` are deliberately not mapped
   by a broad rule.
4. **Parent package versions.** A native library can inherit the version of
   its containing APEX/APK only when every matched parent has a version and all
   of those versions are identical. The scope is recorded as
   `parent-package-not-upstream-library`.

Every ELF also carries its SHA-256. Provenance is copied to another component
only when the ELF bytes have the same digest. Same-name files with different
hashes remain separate.

The component output records its evidence kind as one of:

- `estimated-source-revision`
- `estimated-apex-package-version`
- `estimated-apk-package-version`

## BLintDB

The pinned OCI layer is a 5,660,250,112-byte raw SQLite database. Its verified
SHA-256 is `93bcb321c5c3bc8933cdad5c63454312838750f88053ed0223fd4c2e0da5112e`.
The image digest is checked before use.

The database contains 35 projects, 803 binaries, and about 1.54 million symbol
rows. The first raw symbol query found evidence for 492 of 1,790 unknown ELFs,
but 477 were ambiguous and common linker/runtime symbols inflated the result.
There were zero exact binary-hash matches.

Applying Blint's low-information symbol suppression, defined-symbol filtering,
binary-name rules, target coverage, and Conan deploy-path parsing reduced the
result to 11 files with unique dependency paths, covering FreeType, Protobuf,
and libjpeg-turbo. The database version is only a reference-build candidate;
the artifact still needs its own version proof. These candidates are not
included in the 58.02% total.

## NSRL

The NIST Android minimal RDS database was downloaded, decompressed to
39,967,412,224 bytes, and verified against official SHA-256
`2f3203615d96e6079fda9a65d39cad4b2a9100fa8f7e6f54a3c74cc5eee1d315`.

- 2026.03.1 baseline: zero exact file matches in either firmware.
- 2026.06.1 delta: one exact match,
  `libdatastore_shared_counter.so`, associated with "Homebase: Employee
  Scheduling"; the distribution package version is empty.
- 2026.09.1 delta: zero exact matches.

NSRL package versions identify distributions, not upstream library releases.
No NSRL version gain is counted.

## Rule-pack ownership

The current rule volume is small, so built-in rules stay in this repository and
ship with the package. This keeps code, rules, tests, and scan behavior atomic.

Large or frequently updated packs can live in a separate
`firmware-scanner-rules` repository. A consuming scanner must select an
immutable tag and verify a `rules.lock.json` containing the tag, content hash,
schema version, producer, and enabled conditions. The existing `--plugin-dir`
path can load external packs without making mutable branch updates part of a
scan.

Image-specific source provenance follows the same principle. It is stored under
`src/firmware_scanner/data/provenance/` with the exact image hash. The wheel
build was inspected and includes the source pack, rules, and their README.

## Reproduction

```bash
python3 -m firmware_scanner analyze /home/kali/Desktop/work/project/vulnscan/system.img \
  -o reports/version-estimates-20261119/source-revisions/scan-final \
  -f json -f sbom --timeout 900 --no-log

PYTHONPATH=. python3 experiments/version_coverage/evaluate.py \
  reports/function-version-experiment-20261118/after/system/system_analysis.json \
  reports/version-estimates-20261119/source-revisions/scan-final/system_analysis.json \
  --baseline-commit e890f0c
```

Verification completed with **545 passed, 37 skipped** for the default suite
and **65 passed** for the real-image FreeType and semantic-version controls when
the two system-image environment variables were supplied.
