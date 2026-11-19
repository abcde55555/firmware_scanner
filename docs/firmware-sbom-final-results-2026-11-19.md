# Firmware SBOM validation after database and version-evidence work

Date: 2026-11-19

## Outcome

This round added:

- immutable BLintDB and NSRL manifests with schema and SHA-256 checks;
- content-addressed ELF evidence caching with path-safe rebasing;
- source-project SONAME rules and exact source-revision version pins;
- a larger native binary fingerprint catalog;
- strict separation of exact, estimated and unresolved versions;
- target-package and version-branch filtering for OSV candidates;
- dependency-edge deduplication and SONAME ambiguity suppression.

The measured fixed-cohort version coverage improved on the modern Android image
from **655/1,129 (58.02%) to 690/1,129 (61.12%)**. Native-library coverage
improved from **532/774 (68.73%) to 567/774 (73.26%)**.

These are version-field coverage values, not independently verified accuracy.
The exact count increased from 152 to 176 in the fixed cohort. The remaining 514
usable values are explicitly estimated. No broad held-out ground truth is
available for this image.

## Modern Android system image

Input: `system.img`, 2,309,611,520 bytes, SHA-256
`ff9025e0f73e6784f57ef9d3dd5b90ce648d524dd4c20d8cfe5dc2b66ccc4ce4`.

| Metric | Result |
|---|---:|
| Unique BOM components | 1,595 |
| Non-empty resolved versions | 1,104 |
| Exact resolution state | 67 |
| Estimated resolution states | 775 |
| Unknown | 426 |
| Source-declared exact versions applied | 22 |
| BOM dependency records | 928 |
| Android core scan time | 335.1 s |
| End-to-end process time | 357.0 s |
| Peak RSS | 3,403,188 KiB |

The prior database-enabled scan took 408.2 seconds in the Android core scan.
Reusing SQLite connections, content-cache hits and the revised rule path reduced
that to 335.1 seconds, about 17.9% faster. The image is large enough that the
peak remains around 3.4 GiB; the roadmap's 1.2 GiB target is not met.

The scanner analyzed 1,789 unique ELF contents and reused 345 byte-identical
paths. It queried BLintDB for those unique contents and emitted eight candidate
identity rows for seven files. NSRL produced no exact baseline file hit.

The 22 source declarations include:

| Component | Version | Exact source project |
|---|---:|---|
| FreeType (`libft2.so`) | 2.13.2 | `external/freetype` |
| HarfBuzz subset | 10.2.0 | `external/harfbuzz_ng` |
| JsonCpp | 1.9.5 | `external/jsoncpp` |
| libexif | 0.6.21 | `external/libexif` |
| TinyXML-2 | 10.0.0 | `external/tinyxml2` |
| ICU components | 76.1 | `external/icu` |
| libnl | 3.10.0 | `external/libnl` |
| libcap | 2.69 | `external/libcap` |
| zlib | 1.3.0.1-motley | `external/zlib` |
| libdrm | 2.4.131 | `external/libdrm` |
| NTFS-3G | 2022.10.3 | `external/ntfs-3g` |
| e2fsprogs components | 1.46.6 | `external/e2fsprogs` |
| libfuse | 3.17.0 | `external/libfuse` |
| Ultra HDR | 1.4.0 | `external/libultrahdr` |
| libyuv build version | 1883 | `external/libyuv` |
| Android LZMA SDK | 24.09 | `external/lzma` |

The LZMA mapping is deliberately excluded from XZ Utils vulnerability queries.

## Allwinner Android system image

Input: `sun8iw6p1_android_perf3_v1_0_uart0.img`.

| Metric | Result |
|---|---:|
| Unique BOM components | 591 |
| Non-empty resolved versions | 141 |
| Fixed all-component coverage | 141/589, 23.94% |
| Fixed native coverage | 44/316, 13.92% |
| Android core scan time | 76.2 s |
| End-to-end process time | 78.8 s |
| Peak RSS | 3,124,136 KiB |

The previous frozen result was 120/582 (20.62%) for all components and 23/312
(7.37%) for native libraries. The database scan analyzed 430 unique ELF
contents, reused 14 duplicate paths, emitted two BLintDB candidate rows for two
files, and produced no NSRL baseline file hit.

Allwinner has no matching source manifest in the supplied material. Its version
gains therefore come from binary evidence and parent-package attribution. It
does not receive the modern image's source revisions or version pins.

## BOM and VEX validation

The 1.5 and 1.6 BOMs for both images validate against the official CycloneDX
schemas. The 1.5 and 1.6 VEX artifacts also validate with zero schema errors.
The machine-readable results are in
`reports/version-estimates-20261119/schema-validation-all.json`.

CycloneDX dependency edges are emitted only for a SONAME with one provider in
the scanned firmware. Refs with multiple paths are merged into one dependency
record. The final modern BOM contains 928 dependency records.

## Vulnerability candidates

The OSV integration now rejects affected records for unrelated package names,
guards generic upstream versions from incompatible distro major branches, and
uses the ecosystem as part of the cache key.

Modern image:

| Metric | Result |
|---|---:|
| Components queried | 282 |
| Component-vulnerability records | 464 |
| Unique vulnerability IDs | 251 |
| Unique CVE IDs | 244 |
| Components with candidates | 22 |
| Unique CISA KEV IDs | 2 |

Allwinner image:

| Metric | Result |
|---|---:|
| Components queried | 53 |
| Component-vulnerability records | 1,462 |
| Unique vulnerability IDs | 791 |
| Unique CVE IDs | 744 |
| Components with candidates | 22 |
| Unique CISA KEV IDs | 4 |

These are candidate matches. They do not include reachability, exploitability
or vendor patch verification. The previous generic-name run produced obvious
cross-branch results such as OpenSSL 3.0-only CVEs against OpenSSL 1.0.1f; those
were removed. Further NVD/CPE and vendor-advisory validation is still required.

## Remaining limits

- BLintDB and NSRL do not directly increase target-version coverage in these two
  images. BLintDB supplies reference candidates; NSRL supplies exact-file
  distribution context.
- The exact source-version pins are image-revision-specific and must be extended
  with each new source manifest.
- Source revision and parent APEX/APK versions remain estimates and are not sent
  to upstream CPE or OSV queries.
- No independent full-image version truth set exists. The percentages above are
  coverage against a frozen component cohort, not a 61.12% or 73.26% accuracy
  claim.
- Database-enabled scans need more memory than the roadmap target. The 40 GB
  NSRL deployment should remain optional until memory and I/O budgets are tuned.

The machine-readable aggregate is in
`reports/version-estimates-20261119/final-summary.json`.
