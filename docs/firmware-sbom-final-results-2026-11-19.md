# Firmware SBOM validation after database and version-evidence work

Date: 2026-11-19

> **Superseded for version coverage:** the 0.8.0 evaluation corrects parent and
> source revisions being counted as exact and adds source-path-bound provenance.
> See `docs/firmware-sbom-roadmap-review-2026-11-20.md` for current numbers.
> Database, license and vulnerability sections below remain historical evidence
> for the 0.7.0 run.

## Outcome

This round added:

- immutable BLintDB and NSRL manifests with schema and SHA-256 checks;
- content-addressed ELF evidence caching with path-safe rebasing;
- source-project SONAME rules and exact source-revision version pins;
- a larger native binary fingerprint catalog;
- strict separation of exact, estimated and unresolved versions;
- target-package and version-branch filtering for OSV candidates;
- dependency-edge deduplication and SONAME ambiguity suppression.
- a fail-closed SHA-256 lock for bundled binary, provenance, signature,
  database-manifest and offline advisory data.
- an exact ARM32 ICU getter probe for the inlined `U_ICU_VERSION` literal;
- same-source version inheritance for ICU and e2fsprogs families, retained as
  estimates;
- a high-specificity Speex banner rule for the Allwinner wrapper.
- a paired-API ARM32 FreeType probe that recovered `2.4.12` from
  `FT_New_Library` and `FT_Library_Version`;
- post-analysis BLintDB identity reconciliation and diagnostic reference-version
  comparison;
- CycloneDX round-trip preservation of resolution state, BLint identity and CPE.
- conservative SPDX license attribution from Android NOTICE HTML;
- package-level License and Maven `pom.xml` evidence from APKs/JARs;
- explicit `incomplete` license status when any component lacks a license.

The measured fixed-cohort version coverage improved on the modern Android image
from **655/1,129 (58.02%) to 690/1,129 (61.12%)**. Native-library coverage
improved from **532/774 (68.73%) to 567/774 (73.26%)**.

The Allwinner fixed cohort improved from **136/582 (23.37%) to 146/582
(25.09%)**. Native-library coverage improved from **39/312 (12.50%) to
48/312 (15.38%)**.

These are version-field coverage values, not independently verified accuracy.
The exact count increased from 152 to 176 in the fixed cohort. The remaining 514
usable values are explicitly estimated. No broad held-out ground truth is
available for this image.

An independent Debian held-out seed adds evidence beyond the two firmware
images. Twenty-one stripped system libraries are mapped to Debian package truth:

| Metric | Result |
|---|---:|
| Exact version | 19/21 |
| Wrong exact version | 0 |
| Unknown | 2 |
| Usable coverage | 90.48% |
| Precision among exact claims | 19/19, 100% |

The unknown items are a Debian FreeType build shape not accepted by the
fail-closed probe and Capstone's major/minor-only API. This seed is not yet a
large production accuracy gate. See
`docs/heldout-debian-version-validation-2026-11-19.md`.

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
| Android core scan time | 336.3 s |
| License coverage | 3/1,595, 0.19%, `incomplete` |

The prior database-enabled scan took 408.2 seconds in the Android core scan.
Reusing SQLite connections, content-cache hits and the revised rule path reduced
that to 329.8 seconds in the final scan, about 19.2% faster. Scan time on this
host varied by roughly 20 seconds between validated runs. The image is large enough that the
peak remains around 3.4 GiB; the roadmap's 1.2 GiB target is not met.

The scanner analyzed 1,789 unique ELF contents and reused 345 byte-identical
paths. It queried BLintDB for all 1,789 unique contents and emitted 23 candidate
rows for 21 files. Final reconciliation confirmed 25 component identities and
recorded 25 diagnostic reference-version differences. None of those reference
versions replaced a target version. NSRL queried the same 1,789 files and found
no exact baseline file match.

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
| Non-empty resolved versions | 151 |
| Exact resolution state | 37 |
| Estimated resolution state | 11 |
| Unknown | 384 |
| Fixed all-component coverage | 146/582, 25.09% |
| Fixed native coverage | 48/312, 15.38% |
| License coverage | 187/591, 31.64%, `incomplete` |
| Android core scan time | 79.3 s |

The same-source family pass inherited seven values. The ICU donor itself was
resolved exactly as `51.1.0.1`; its ARM32 `u_getVersion_51` wrapper loads that
literal from a read-only pool before parsing four numeric fields.
`libicui18n.so` inherits `51.1.0.1` as an estimate. Five e2fsprogs sibling
libraries and `e2fsck` inherit `1.41.14` from the independently observed
`libext2fs.so`. The Speex wrapper has a direct `speex-1.2beta3` banner. The
legacy FreeType probe recovers `2.4.12` from matching fields in
`FT_New_Library` and `FT_Library_Version`; Android 4.4.4 upstream headers
independently define those three constants. Together these changes account for
the ten newly populated fixed-cohort rows.

The database scan analyzed 430 unique ELF contents and reused 14 duplicate
paths. BLintDB emitted five candidate rows for five files; final reconciliation
confirmed four identities and recorded four diagnostic reference-version
differences. `libft2.so` is an important example: the target is exactly
`2.4.12`, while the BLint reference build is `2.13.3`; the reference value is
retained only as review evidence. NSRL queried all 430 files and found no exact
baseline file match.

Allwinner has no matching source manifest in the supplied material. Its version
gains therefore come from binary evidence and parent-package attribution. It
does not receive the modern image's source revisions or version pins.

## License attribution

The Allwinner image contains `/etc/NOTICE.html.gz`, which maps filesystem paths
to embedded license text. The scanner now recognizes only strong license
signatures and records the NOTICE path as evidence. It does not infer a license
from product names or general copyright statements.

| License | Unique components |
|---|---:|
| Apache-2.0 | 154 |
| BSD-3-Clause | 25 |
| BSD-2-Clause | 14 |
| MIT | 12 |
| Zlib | 5 |
| ISC | 3 |
| OpenSSL | 2 |
| FTL | 1 |

The raw NOTICE pass produced 191 component observations. Package-level
`LICENSE.txt`/`NOTICE.txt` and Maven POM metadata added additional evidence;
final deduplication produced **187 unique licensed components (31.64%)**. The
remaining 404 components have no verified license evidence. The final status is therefore
`incomplete`, not `compliant`. This distinction is enforced in JSON, CycloneDX
metadata and the HTML report.

The modern Android image's NOTICE XML carries file-to-project attribution but
no license text that can support a file-level SPDX claim. Its license status is
conservatively `incomplete` with 3/1,595 licensed components. Package-level
`LICENSE` evidence identifies `com.google.android.gsf`,
`com.android.statementservice` and `com.android.systemui` as Apache-2.0.
Package-level licenses are attached only to the application component; they are
not copied to unrelated embedded libraries. Maven POM licenses are attached
only when the path, group, artifact and version agree.

## Taxonomy and generic database support

The scanner now records taxonomy only where evidence is explicit: an AOSP
source project or an external ecosystem PURL. Unattributed components remain
unknown rather than being guessed into a denominator.

On the modern image:

| Taxonomy | Components | Non-empty versions |
|---|---:|---:|
| `platform-first-party` | 412 | 412 |
| `third-party-oss` | 239 | 239 |
| unclassified | 944 | 453 |

Taxonomy coverage is therefore 651/1,595 (40.82%), not complete BOM coverage.
Within the old fixed cohort, 92 records are matched to explicit third-party
taxonomy and all 92 have a version: 36 exact and 56 estimated. That 92/92 figure
has selection bias and is not a third-party precision claim.

Allwinner now has four BLint-confirmed `third-party-oss` components: expat,
FreeType, libjpeg-turbo and SQLite. The other 587 components remain
taxonomy-unknown because that image has no matching source manifest and the
exposed purls do not identify an external ecosystem. The four-component fixed
cohort has versions for three components (75%) and includes one exact identity
but unresolved version (`libjpeg-turbo`).

Taxonomy evidence is explicit: `source-project-path`,
`blintdb-confirmed-identity` or `external-ecosystem-purl`.

BLintDB and NSRL are now available to both the Android filesystem scanner and
the generic `SmartSectionAnalyzer` ELF path. A real `/bin/echo` smoke scan
queried one unique ELF and wrote database/cache statistics to both JSON and
CycloneDX metadata. The generic enricher is closed in a `finally` path, including
when analysis raises.

The bundled data lock release is `builtin-2026.11.19.3`, covering 13 JSON packs.
Its release and lock SHA-256 are present in both JSON and CycloneDX metadata.

## BOM and VEX validation

The 1.5 and 1.6 BOMs for both images validate against the official CycloneDX
schemas. The 1.5 and 1.6 VEX artifacts also validate with zero schema errors.
The machine-readable results are in
`reports/version-estimates-20261119/schema-validation-0.7.json`.

CycloneDX round-trip parsing now preserves component `properties` and the
component-level `cpe`. This keeps resolution-state gates, BLint-confirmed
identity and CPE available when a generated BOM is scanned again.

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
| Components queried | 218 |
| Component-vulnerability records | 467 |
| Unique vulnerability IDs | 254 |
| Unique CVE IDs | 247 |
| Components with candidates | 23 |
| Unique CISA KEV IDs | 2 |

Allwinner image:

| Metric | Result |
|---|---:|
| Components queried | 36 |
| Component-vulnerability records | 1,500 |
| Unique vulnerability IDs | 829 |
| Unique CVE IDs | 782 |
| Components with candidates | 22 |
| Unique CISA KEV IDs | 4 |

These are candidate matches. They do not include reachability, exploitability
or vendor patch verification. The previous generic-name run produced obvious
cross-branch results such as OpenSSL 3.0-only CVEs against OpenSSL 1.0.1f; those
were removed. Further NVD/CPE and vendor-advisory validation is still required.

The reduced query count is intentional. Round-tripping the BOM now preserves
estimated and parent-package resolution states, so those values are excluded
from upstream OSV queries. BLint-confirmed identity is used only for components
whose target version is exact. For Allwinner FreeType, this correctly maps
`libft2.so 2.4.12` to FreeType and reports 45 historical vulnerability
candidates; without identity reconciliation the filename produced no upstream
match.

## Remaining limits

- BLintDB and NSRL do not directly increase target-version coverage in these two
  images. BLintDB supplies reference candidates; NSRL supplies exact-file
  distribution context.
- The exact source-version pins are image-revision-specific and must be extended
  with each new source manifest.
- Source revision and parent APEX/APK versions remain estimates and are not sent
  to upstream CPE or OSV queries.
- The same-source family pass currently covers only ICU and e2fsprogs. Each
  inherited value is marked `version_estimate` and is excluded from vulnerability
  queries even when its donor version is exact.
- No independent full-image version truth set exists. The percentages above are
  coverage against a frozen component cohort, not a 61.12% or 73.26% accuracy
  claim.
- License coverage is a notice-evidence metric. Missing license data is reported
  as incomplete and must not be interpreted as proof of compliance.
- Database-enabled scans need more memory than the roadmap target. The 40 GB
  NSRL deployment should remain optional until memory and I/O budgets are tuned.

The machine-readable aggregate is in
`reports/version-estimates-20261119/final-summary.json`.
